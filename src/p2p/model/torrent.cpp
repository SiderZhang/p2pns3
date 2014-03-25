/*

Copyright (c) 2003, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#include "libtorrent/pch.hpp"

#include <ctime>
#include <algorithm>
#include <set>
#include <cctype>
#include <numeric>

#ifdef TORRENT_DEBUG
#include <iostream>
#endif

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/bind.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "libtorrent/config.hpp"
#include "libtorrent/torrent_handle.hpp"
#include "libtorrent/session.hpp"
#include "libtorrent/torrent_info.hpp"
#include "libtorrent/tracker_manager.hpp"
#include "libtorrent/parse_url.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/hasher.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/peer.hpp"
#include "libtorrent/peer_connection.hpp"
#include "libtorrent/bt_peer_connection.hpp"
#include "libtorrent/peer_id.hpp"
#include "libtorrent/alert.hpp"
#include "libtorrent/identify_client.hpp"
#include "libtorrent/alert_types.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/assert.hpp"
#include "libtorrent/enum_net.hpp"
#include "libtorrent/gzip.hpp" // for inflate_gzip
#include "libtorrent/random.hpp"
#include "libtorrent/string_util.hpp" // for allocate_string_copy
#include "libtorrent/escape_string.hpp"
#include "libtorrent/broadcast_socket.hpp"
#include "libtorrent/peer_info.hpp"

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
#include "libtorrent/struct_debug.hpp"
#endif

#include <iostream>
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

using namespace libtorrent;
using namespace ns3;
using namespace std;
using boost::tuples::tuple;
using boost::tuples::get;
using boost::tuples::make_tuple;
using libtorrent::aux::session_impl;

NS_LOG_COMPONENT_DEFINE ("Torrent");

namespace
{
	size_type collect_free_download(
		torrent::peer_iterator start
		, torrent::peer_iterator end)
	{
		size_type accumulator = 0;
		for (torrent::peer_iterator i = start; i != end; ++i)
		{
			// if the peer is interested in us, it means it may
			// want to trade it's surplus uploads for downloads itself
			// (and we should not consider it free). If the share diff is
			// negative, there's no free download to get from this peer.
			size_type diff = (*i)->share_diff();
			TORRENT_ASSERT(diff < (std::numeric_limits<size_type>::max)());
			if ((*i)->is_peer_interested() || diff <= 0)
				continue;

			TORRENT_ASSERT(diff > 0);
			(*i)->add_free_upload(-diff);
			accumulator += diff;
			TORRENT_ASSERT(accumulator > 0);
		}
		TORRENT_ASSERT(accumulator >= 0);
		return accumulator;
	}

	// returns the amount of free upload left after
	// it has been distributed to the peers
	boost::uint32_t distribute_free_upload(
		torrent::peer_iterator start
		, torrent::peer_iterator end
		, size_type free_upload)
	{
		TORRENT_ASSERT(free_upload >= 0);
		if (free_upload <= 0) return 0;
		int num_peers = 0;
		size_type total_diff = 0;
		for (torrent::peer_iterator i = start; i != end; ++i)
		{
			size_type d = (*i)->share_diff();
			TORRENT_ASSERT(d < (std::numeric_limits<size_type>::max)());
			total_diff += d;
			if (!(*i)->is_peer_interested() || (*i)->share_diff() >= 0) continue;
			++num_peers;
		}

		if (num_peers == 0) return boost::uint32_t(free_upload);
		size_type upload_share;
		if (total_diff >= 0)
		{
			upload_share = (std::min)(free_upload, total_diff) / num_peers;
		}
		else
		{
			upload_share = (free_upload + total_diff) / num_peers;
		}
		if (upload_share < 0) return boost::uint32_t(free_upload);

		for (torrent::peer_iterator i = start; i != end; ++i)
		{
			peer_connection* p = *i;
			if (!p->is_peer_interested() || p->share_diff() >= 0) continue;
			p->add_free_upload(upload_share);
			free_upload -= upload_share;
		}
		return (std::min)(free_upload, size_type(UINT_MAX));
	}

	struct find_peer_by_ip
	{
		find_peer_by_ip(ns3::InetSocketAddress const& a, const torrent* t)
			: ip(a)
			, tor(t)
		{ TORRENT_ASSERT(t != 0); }
		
		bool operator()(session_impl::connection_map::value_type const& c) const
		{
            ns3::Ipv4EndPoint const& sender = c->remote();
			if (sender.GetPeerAddress() != ip.GetIpv4()) return false;
			if (tor != c->associated_torrent().get()) return false;
			return true;
		}

		ns3::InetSocketAddress const& ip;
		torrent const* tor;
	};

	struct peer_by_id
	{
		peer_by_id(const peer_id& i): pid(i) {}
		
		bool operator()(session_impl::connection_map::value_type const& p) const
		{
			if (p->pid() != pid) return false;
			// have a special case for all zeros. We can have any number
			// of peers with that pid, since it's used to indicate no pid.
			if (pid.is_all_zeros()) return false;
			return true;
		}

		peer_id const& pid;
	};
}

namespace libtorrent
{

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING

	void torrent::print_size(logger& l)
	{
		char tmp[300];
		int temp = 0;
		int prev_size = 0;
		PRINT_SIZEOF(torrent)

		//PRINT_OFFSETOF(torrent, m_tracker_address)
		PRINT_OFFSETOF(torrent, m_manager)
		PRINT_OFFSETOF(torrent, m_policy)
		PRINT_OFFSETOF(torrent, m_total_uploaded)
		PRINT_OFFSETOF(torrent, m_total_downloaded)
		PRINT_OFFSETOF(torrent, m_started)
		PRINT_OFFSETOF(torrent, m_torrent_file)
		//PRINT_OFFSETOF(torrent, m_owning_storage)
	//	PRINT_OFFSETOF(torrent, m_storage)
		PRINT_OFFSETOF(torrent, m_connections)
		//PRINT_OFFSETOF(torrent, m_web_seeds)
        // TODO: 禁用boost::asio
		//PRINT_OFFSETOF(torrent, m_tracker_timer)
		PRINT_OFFSETOF(torrent, m_stat)
// some compilers don't like using offsetof on references it seems
#ifndef _MSC_VER
		PRINT_OFFSETOF(torrent, m_ses)
#endif
		PRINT_OFFSETOF(torrent, m_file_priority)
		PRINT_OFFSETOF(torrent, m_file_progress)
		PRINT_OFFSETOF(torrent, m_picker)
		PRINT_OFFSETOF(torrent, m_trackers)
		PRINT_OFFSETOF(torrent, m_time_critical_pieces)
		PRINT_OFFSETOF(torrent, m_username)
		PRINT_OFFSETOF(torrent, m_password)
		PRINT_OFFSETOF(torrent, m_net_interfaces)
		PRINT_OFFSETOF(torrent, m_save_path)
		//PRINT_OFFSETOF(torrent, m_url)
		//PRINT_OFFSETOF(torrent, m_uuid)
		//PRINT_OFFSETOF(torrent, m_source_feed_url)
		//PRINT_OFFSETOF(torrent, m_torrent_file_buf)
		PRINT_OFFSETOF(torrent, m_verified)
		PRINT_OFFSETOF(torrent, m_error)
		PRINT_OFFSETOF(torrent, m_error_file)
		PRINT_OFFSETOF(torrent, m_resume_data)
		PRINT_OFFSETOF(torrent, m_resume_entry)
		PRINT_OFFSETOF(torrent, m_name)
		PRINT_OFFSETOF(torrent, m_storage_constructor)
		PRINT_OFFSETOF(torrent, m_added_time)
		PRINT_OFFSETOF(torrent, m_completed_time)
		PRINT_OFFSETOF(torrent, m_last_seen_complete)
		PRINT_OFFSETOF(torrent, m_last_saved_resume)
		PRINT_OFFSETOF(torrent, m_ratio)
		PRINT_OFFSETOF(torrent, m_available_free_upload)
		PRINT_OFFSETOF(torrent, m_average_piece_time)
		PRINT_OFFSETOF(torrent, m_piece_time_deviation)
		PRINT_OFFSETOF(torrent, m_total_failed_bytes)
		PRINT_OFFSETOF(torrent, m_total_redundant_bytes)
//		PRINT_OFFSETOF(torrent, m_upload_mode_time:24)
//		PRINT_OFFSETOF(torrent, m_state:3)
//		PRINT_OFFSETOF(torrent, m_storage_mode:2)
//		PRINT_OFFSETOF(torrent, m_announcing:1)
//		PRINT_OFFSETOF(torrent, m_waiting_tracker:1)
//		PRINT_OFFSETOF(torrent, m_seed_mode:1)
//		PRINT_OFFSETOF(torrent, m_active_time:24)
		PRINT_OFFSETOF(torrent, m_last_working_tracker)
//		PRINT_OFFSETOF(torrent, m_finished_time:24)
//		PRINT_OFFSETOF(torrent, m_sequential_download:1)
//		PRINT_OFFSETOF(torrent, m_got_tracker_response:1)
//		PRINT_OFFSETOF(torrent, m_connections_initialized:1)
//		PRINT_OFFSETOF(torrent, m_super_seeding:1)
//		PRINT_OFFSETOF(torrent, m_override_resume_data:1)
//		PRINT_OFFSETOF(torrent, m_resolving_country:1)
//		PRINT_OFFSETOF(torrent, m_resolve_countries:1)
//		PRINT_OFFSETOF(torrent, m_need_save_resume_data:1)
//		PRINT_OFFSETOF(torrent, m_seeding_time:24)
		PRINT_OFFSETOF(torrent, m_time_scaler)
//		PRINT_OFFSETOF(torrent, m_max_uploads:24)
//		PRINT_OFFSETOF(torrent, m_num_uploads:24)
//		PRINT_OFFSETOF(torrent, m_block_size_shift:5)
//		PRINT_OFFSETOF(torrent, m_has_incoming:1)
//		PRINT_OFFSETOF(torrent, m_files_checked:1)
//		PRINT_OFFSETOF(torrent, m_queued_for_checking:1)
//		PRINT_OFFSETOF(torrent, m_max_connections:24)
//		PRINT_OFFSETOF(torrent, m_padding:24)
		PRINT_OFFSETOF(torrent, m_sequence_number)
//		PRINT_OFFSETOF(torrent, m_complete:24)
		PRINT_OFFSETOF(torrent, m_priority)
//		PRINT_OFFSETOF(torrent, m_incomplete:24)
//		PRINT_OFFSETOF(torrent, m_progress_ppm:20)
//		PRINT_OFFSETOF(torrent, m_abort:1)
//		PRINT_OFFSETOF(torrent, m_announce_to_dht:1)
//		PRINT_OFFSETOF(torrent, m_announce_to_trackers:1)
//		PRINT_OFFSETOF(torrent, m_announce_to_lsd:1)
//		PRINT_OFFSETOF(torrent, m_allow_peers:1)
//		PRINT_OFFSETOF(torrent, m_upload_mode:1)
//		PRINT_OFFSETOF(torrent, m_auto_managed:1)
		PRINT_OFFSETOF(torrent, m_num_verified)
		PRINT_OFFSETOF(torrent, m_last_scrape)
	}
#undef PRINT_SIZEOF
#undef PRINT_OFFSETOF

#endif

	int root2(int x)
	{
		int ret = 0;
		x >>= 1;
		while (x > 0)
		{
			// if this assert triggers, the block size
			// is not an even 2 exponent!
			TORRENT_ASSERT(x == 1 || (x & 1) == 0);
			++ret;
			x >>= 1;
		}
		return ret;
	}

	torrent::torrent(
		session_impl& ses
        , ns3::Ipv4Address addr
		, ns3::Ipv4EndPoint const& net_interface
		, int block_size
		, int seq
		, add_torrent_params const& p
		, sha1_hash const& info_hash
        , ns3::Ptr<ns3::Node> myNode
        , bool i_seed)
		: m_policy(this)
		, m_total_uploaded(0)
		, m_total_downloaded(0)
		, m_started(time_now())
		//, m_storage(0)
		, m_num_connecting(0)
		//, m_tracker_timer(ses.m_io_service)
		, m_ses(ses)
		, m_trackerid(p.trackerid)
		, m_save_path(complete(p.save_path))
		//, m_url(p.url)
		//, m_uuid(p.uuid)
		//, m_source_feed_url(p.source_feed_url)
		, m_storage_constructor(p.storage)
		, m_added_time(time(0))
		, m_completed_time(0)
		, m_last_seen_complete(0)
		, m_last_saved_resume(time(0))
		, m_ratio(0.f)
		, m_available_free_upload(0)
		, m_average_piece_time(0)
		, m_piece_time_deviation(0)
		, m_total_failed_bytes(0)
		, m_total_redundant_bytes(0)
		, m_sequence_number(seq)
		, m_upload_mode_time(0)
		, m_state(torrent_status::downloading)
		//, m_storage_mode(p.storage_mode)
		, m_announcing(false)
		, m_waiting_tracker(false)
		, m_seed_mode(false)
		, m_active_time(0)
		, m_last_working_tracker(-1)
		, m_finished_time(0)
		, m_sequential_download(false)
		, m_got_tracker_response(false)
		, m_connections_initialized(false)
		, m_super_seeding(false)
		, m_override_resume_data(p.flags & add_torrent_params::flag_override_resume_data)
		, m_need_save_resume_data(true)
		, m_seeding_time(0)
		, m_time_scaler(0)
		, m_max_uploads((1<<24)-1)
		, m_save_resume_flags(0)
		, m_num_uploads(0)
		, m_block_size_shift(root2(block_size))
		, m_has_incoming(false)
		, m_files_checked(false)
		, m_queued_for_checking(false)
		, m_max_connections((1<<24)-1)
		, m_padding(0)
		, m_complete(0xffffff)
		, m_priority(0)
		, m_incomplete(0xffffff)
		, m_progress_ppm(0)
		, m_abort(false)
		//, m_announce_to_dht((p.flags & add_torrent_params::flag_paused) == 0)
		, m_announce_to_trackers((p.flags & add_torrent_params::flag_paused) == 0)
		//, m_announce_to_lsd((p.flags & add_torrent_params::flag_paused) == 0)
		, m_allow_peers((p.flags & add_torrent_params::flag_paused) == 0)
		, m_upload_mode(p.flags & add_torrent_params::flag_upload_mode)
		, m_auto_managed(p.flags & add_torrent_params::flag_auto_managed)
		, m_share_mode(p.flags & add_torrent_params::flag_share_mode)
		, m_num_verified(0)
		, m_last_scrape(0)
		, m_last_download(0)
		, m_last_upload(0)
		, m_downloaders(0xffffff)
		, m_interface_index(0)
		, m_graceful_pause_mode(false)
		, m_need_connect_boost(true)
		, m_magnet_link(false)
		, m_apply_ip_filter(p.flags & add_torrent_params::flag_apply_ip_filter)
		, m_merge_resume_trackers(p.flags & add_torrent_params::flag_merge_resume_trackers)
		, m_state_subscription(p.flags & add_torrent_params::flag_update_subscribe)
		, m_in_state_updates(false)
		, m_ssl_torrent(false)
        , m_ticket_count(0)
        , m_download_rate(peer_connection::download_channel)
        , m_upload_rate(peer_connection::upload_channel)
	{
        NS_LOG_IP_FUNCTION(addr, this);

        initSeed = i_seed;
        ip = addr;
		// if there is resume data already, we don't need to trigger the initial save
		// resume data
        m_node = myNode;
		if (p.resume_data && (p.flags & add_torrent_params::flag_override_resume_data) == 0)
			m_need_save_resume_data = false;

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_resume_data_loaded = false;
#endif
#if TORRENT_USE_UNC_PATHS
		m_save_path = canonicalize_path(m_save_path);
#endif

		if (!m_apply_ip_filter) ++m_ses.m_non_filtered_torrents;

		if (!p.ti || !p.ti->is_valid())
		{
			// we don't have metadata for this torrent. We'll download
			// it either through the URL passed in, or through a metadata
			// extension. Make sure that when we save resume data for this
			// torrent, we also save the metadata
			m_magnet_link = true;
	
			// did the user provide resume data?
			// maybe the metadata is in there
			if (p.resume_data)
			{
				int pos;
				error_code ec;
				lazy_entry tmp;
				lazy_entry const* info = 0;
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
				debug_log("adding magnet link with resume data");
#endif
				if (lazy_bdecode(&(*p.resume_data)[0], &(*p.resume_data)[0]
					+ p.resume_data->size(), tmp, ec, &pos) == 0
					&& tmp.type() == lazy_entry::dict_t
					&& (info = tmp.dict_find_dict("info")))
				{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
					debug_log("found metadata in resume data");
#endif
					// verify the info-hash of the metadata stored in the resume file matches
					// the torrent we're loading

					std::pair<char const*, int> buf = info->data_section();
					sha1_hash resume_ih = hasher(buf.first, buf.second).final();

					// if url is set, the info_hash is not actually the info-hash of the
					// torrent, but the hash of the URL, until we have the full torrent
					if (resume_ih == info_hash || !p.url.empty())
					{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
						debug_log("info-hash matched");
#endif
						m_torrent_file = (p.ti ? p.ti : new torrent_info(resume_ih));

						if (!m_torrent_file->parse_info_section(*info, ec, 0))
						{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
							debug_log("failed to load metadata from resume file: %s"
								, ec.message().c_str());
#endif
						}
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
						else
						{
							debug_log("successfully loaded metadata from resume file");
						}
#endif
					}
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
					else
					{
						debug_log("metadata info-hash failed");
					}
#endif
				}
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
				else
				{
					debug_log("no metadata found");
				}
#endif
			}
		}

		if (!m_torrent_file)
			m_torrent_file = (p.ti ? p.ti : new torrent_info(info_hash));

		m_trackers = m_torrent_file->trackers();
        NS_LOG_INFO("tracker count " << m_trackers.size());
		if (m_torrent_file->is_valid())
		{
			m_seed_mode = p.flags & add_torrent_params::flag_seed_mode;
			m_connections_initialized = true;
			m_block_size_shift = root2((std::min)(block_size, m_torrent_file->piece_length()));
		}
		else
		{
			if (!p.name.empty()) m_name.reset(new std::string(p.name));
		}

		//if (!m_url.empty() && m_uuid.empty()) m_uuid = m_url;

		TORRENT_ASSERT(m_ses.is_network_thread());
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
		debug_log("creating torrent: %s", torrent_file().name().c_str());
#endif
		m_net_interfaces.push_back(ns3::InetSocketAddress(net_interface.GetPeerAddress(), 0));

		if (p.file_priorities)
			m_file_priority = *p.file_priorities;

		if (m_seed_mode)
			m_verified.resize(m_torrent_file->num_pieces(), false);

		if (p.resume_data) m_resume_data.swap(*p.resume_data);

#ifdef TORRENT_DEBUG
		m_files_checked = false;
#endif
		INVARIANT_CHECK;

		//if (!m_name && !m_url.empty()) m_name.reset(new std::string(m_url));

#ifndef TORRENT_NO_DEPRECATE
		if (p.tracker_url && std::strlen(p.tracker_url) > 0)
		{
			m_trackers.push_back(announce_entry(p.tracker_url));
			m_trackers.back().fail_limit = 0;
			m_trackers.back().source = announce_entry::source_magnet_link;
			m_torrent_file->add_tracker(p.tracker_url);
		}
#endif
		for (std::vector<std::string>::const_iterator i = p.trackers.begin()
			, end(p.trackers.end()); i != end; ++i)
		{
			m_trackers.push_back(announce_entry(*i));
			m_trackers.back().fail_limit = 0;
			m_trackers.back().source = announce_entry::source_magnet_link;
			m_torrent_file->add_tracker(*i);
		}

		if (settings().prefer_udp_trackers)
			prioritize_udp_trackers();
	}

	void torrent::start()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		TORRENT_ASSERT(m_ses.is_network_thread());
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		debug_log("starting torrent");
#endif
		TORRENT_ASSERT(!m_picker);

		if (!m_seed_mode)
		{
			m_picker.reset(new piece_picker());
			std::fill(m_file_progress.begin(), m_file_progress.end(), 0);

			if (!m_resume_data.empty())
			{
				int pos;
				error_code ec;
				if (lazy_bdecode(&m_resume_data[0], &m_resume_data[0]
					+ m_resume_data.size(), m_resume_entry, ec, &pos) != 0)
				{
					std::vector<char>().swap(m_resume_data);
					lazy_entry().swap(m_resume_entry);
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
					debug_log("resume data rejected: %s pos: %d", ec.message().c_str(), pos);
#endif
				}
			}
		}

        if (initSeed)
        {
            for (int i = 0;i < m_picker->num_pieces();++i)
            {
                m_picker->we_have(i);
            }
            completed();
            if (!is_seed())
            {
                NS_LOG_ERROR("failed to build initial seed");
            }
        }

	/*	if (!m_torrent_file->is_valid() && !m_url.empty())
		{
			// we need to download the .torrent file from m_url
			start_download_url();
		}
		else*/ 
        // 张惊:如果torrent文件正常的话，进行初始化
        // 否则采用别的方式（例如从URL下载，从磁力连接找等等）
        if (m_torrent_file->is_valid())
		{
			init();
            // 我们直接开始announce并连接tracker
			start_announcing();
		}
		else
		{
			// we need to start announcing since we don't have any
			// metadata. To receive peers to ask for it.
			set_state(torrent_status::downloading_metadata);
			start_announcing();
		}
	}

	void torrent::set_apply_ip_filter(bool b)
	{
		if (b == m_apply_ip_filter) return;
		if (b)
		{
			TORRENT_ASSERT(m_ses.m_non_filtered_torrents > 0);
			--m_ses.m_non_filtered_torrents;
		}
		else
		{
			++m_ses.m_non_filtered_torrents;
		}
		m_apply_ip_filter = b;
		m_policy.ip_filter_updated();
		state_updated();
	}

	torrent::~torrent()
	{
		if (!m_apply_ip_filter)
		{
			TORRENT_ASSERT(m_ses.m_non_filtered_torrents > 0);
			--m_ses.m_non_filtered_torrents;
			m_apply_ip_filter = true;
		}

		TORRENT_ASSERT(m_ses.is_network_thread());
		// The invariant can't be maintained here, since the torrent
		// is being destructed, all weak references to it have been
		// reset, which means that all its peers already have an
		// invalidated torrent pointer (so it cannot be verified to be correct)
		
		// i.e. the invariant can only be maintained if all connections have
		// been closed by the time the torrent is destructed. And they are
		// supposed to be closed. So we can still do the invariant check.

		TORRENT_ASSERT(m_connections.empty());
		
		INVARIANT_CHECK;

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING || defined TORRENT_LOGGING
		log_to_all_peers("DESTRUCTING TORRENT");
#endif

		TORRENT_ASSERT(m_abort);
		if (!m_connections.empty())
			disconnect_all(errors::torrent_aborted);
	}

	void torrent::read_piece(int piece)
	{
		if (m_abort)
		{
			return;
		}

		TORRENT_ASSERT(piece >= 0 && piece < m_torrent_file->num_pieces());
		int piece_size = m_torrent_file->piece_size(piece);
		int blocks_in_piece = (piece_size + block_size() - 1) / block_size();

		// if blocks_in_piece is 0, rp will leak
		TORRENT_ASSERT(blocks_in_piece > 0);
		TORRENT_ASSERT(piece_size > 0);

		read_piece_struct* rp = new read_piece_struct;
		rp->piece_data.reset(new (std::nothrow) char[piece_size]);
		rp->blocks_left = 0;
		rp->fail = false;

		peer_request r;
		r.piece = piece;
		r.start = 0;
		for (int i = 0; i < blocks_in_piece; ++i, r.start += block_size())
		{
			r.length = (std::min)(piece_size - r.start, block_size());
			//filesystem().async_read(r, boost::bind(&torrent::on_disk_read_complete
			//	, shared_from_this(), _1, _2, r, rp));
			++rp->blocks_left;
		}
	}

	void torrent::set_share_mode(bool s)
	{
		if (s == m_share_mode) return;

		m_share_mode = s;

		// in share mode, all pieces have their priorities initialized to 0
		std::fill(m_file_priority.begin(), m_file_priority.end(), !m_share_mode);

		update_piece_priorities();

		if (m_share_mode) recalc_share_mode();
	}

	void torrent::set_upload_mode(bool b)
	{
		if (b == m_upload_mode) return;

		m_upload_mode = b;

		state_updated();
		//send_upload_only();

		if (m_upload_mode)
		{
			// clear request queues of all peers
			for (std::set<peer_connection*>::iterator i = m_connections.begin()
				, end(m_connections.end()); i != end; ++i)
			{
				peer_connection* p = (*i);
				p->cancel_all_requests();
			}
			// this is used to try leaving upload only mode periodically
			m_upload_mode_time = 0;
		}
		else
		{
			// reset last_connected, to force fast reconnect after leaving upload mode
			for (policy::iterator i = m_policy.begin_peer()
				, end(m_policy.end_peer()); i != end; ++i)
			{
				(*i)->last_connected = 0;
			}

			// send_block_requests on all peers
			for (std::set<peer_connection*>::iterator i = m_connections.begin()
				, end(m_connections.end()); i != end; ++i)
			{
				peer_connection* p = (*i);
				p->send_block_requests();
			}
		}
	}

	void torrent::handle_disk_error(disk_io_job const& j, peer_connection* c)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		if (!j.error) return;

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
		debug_log("disk error: (%d) %s in file: %s", j.error.value(), j.error.message().c_str()
			, j.error_file.c_str());
#endif

		TORRENT_ASSERT(j.piece >= 0);

		piece_block block_finished(j.piece, j.offset / block_size());

		if (j.action == disk_io_job::write)
		{
			// we failed to write j.piece to disk tell the piece picker
			if (has_picker() && j.piece >= 0) picker().write_failed(block_finished);
		}

		if (j.error ==
#if BOOST_VERSION == 103500
			error_code(boost::system::posix_error::not_enough_memory, get_posix_category())
#elif BOOST_VERSION > 103500
			error_code(boost::system::errc::not_enough_memory, get_posix_category())
#else
			asio::error::no_memory
#endif
			)
		{
			if (c) c->disconnect(errors::no_memory);
			return;
		}

		// notify the user of the error

		// put the torrent in an error-state
		set_error(j.error, j.error_file);

		if (j.action == disk_io_job::write
			&& (j.error == boost::system::errc::read_only_file_system
			|| j.error == boost::system::errc::permission_denied
			|| j.error == boost::system::errc::operation_not_permitted
			|| j.error == boost::system::errc::no_space_on_device
			|| j.error == boost::system::errc::file_too_large))
		{
			// if we failed to write, stop downloading and just
			// keep seeding.
			// TODO: make this depend on the error and on the filesystem the
			// files are being downloaded to. If the error is no_space_left_on_device
			// and the filesystem doesn't support sparse files, only zero the priorities
			// of the pieces that are at the tails of all files, leaving everything
			// up to the highest written piece in each file
			set_upload_mode(true);
			return;
		}
	}

//	void torrent::add_piece(int piece, char const* data, int flags)
//	{
//		TORRENT_ASSERT(m_ses.is_network_thread());
//		TORRENT_ASSERT(piece >= 0 && piece < m_torrent_file->num_pieces());
//		int piece_size = m_torrent_file->piece_size(piece);
//		int blocks_in_piece = (piece_size + block_size() - 1) / block_size();
//
//		// avoid crash trying to access the picker when there is none
//		if (is_seed()) return;
//
//		if (picker().have_piece(piece)
//			&& (flags & torrent::overwrite_existing) == 0)
//			return;
//
//		peer_request p;
//		p.piece = piece;
//		p.start = 0;
//		picker().inc_refcount(piece);
//		for (int i = 0; i < blocks_in_piece; ++i, p.start += block_size())
//		{
//			if (picker().is_finished(piece_block(piece, i))
//				&& (flags & torrent::overwrite_existing) == 0)
//				continue;
//
//			p.length = (std::min)(piece_size - p.start, int(block_size()));
//			char* buffer = m_ses.allocate_disk_buffer("add piece");
//			// out of memory
//			if (buffer == 0)
//			{
//				picker().dec_refcount(piece);
//				return;
//			}
//			disk_buffer_holder holder(m_ses, buffer);
//			std::memcpy(buffer, data + p.start, p.length);
//			//filesystem().async_write(p, holder, boost::bind(&torrent::on_disk_write_complete
//			//	, shared_from_this(), _1, _2, p));
//			piece_block block(piece, i);
//			picker().mark_as_downloading(block, 0, piece_picker::fast);
//			picker().mark_as_writing(block, 0);
//		}
//		async_verify_piece(piece, boost::bind(&torrent::piece_finished
//			, shared_from_this(), piece, _1));
//		picker().dec_refcount(piece);
//	}

	bool torrent::add_merkle_nodes(std::map<int, sha1_hash> const& nodes, int piece)
	{
		return m_torrent_file->add_merkle_nodes(nodes, piece);
	}

	peer_request torrent::to_req(piece_block const& p) const
	{
		int block_offset = p.block_index * block_size();
		int block = (std::min)(torrent_file().piece_size(
			p.piece_index) - block_offset, int(block_size()));
		TORRENT_ASSERT(block > 0);
		TORRENT_ASSERT(block <= block_size());

		peer_request r;
		r.piece = p.piece_index;
		r.start = block_offset;
		r.length = block;
		return r;
	}

	std::string torrent::name() const
	{
		if (valid_metadata()) return m_torrent_file->name();
		if (m_name) return *m_name;
		return "";
	}

	// this may not be called from a constructor because of the call to
	// shared_from_this()
	void torrent::init()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT(m_torrent_file->is_valid());
		TORRENT_ASSERT(m_torrent_file->num_files() > 0);
		TORRENT_ASSERT(m_torrent_file->total_size() >= 0);

		if (m_file_priority.size() > (uint)m_torrent_file->num_files())
			m_file_priority.resize(m_torrent_file->num_files());

		std::string cert = m_torrent_file->ssl_cert();
		if (!cert.empty())
		{
			m_ssl_torrent = true;
		}

		m_file_priority.resize(m_torrent_file->num_files(), 1);
		m_file_progress.resize(m_torrent_file->num_files(), 0);

		m_block_size_shift = root2((std::min)(int(block_size()), m_torrent_file->piece_length()));

		if (m_torrent_file->num_pieces() > piece_picker::max_pieces)
		{
			set_error(errors::too_many_pieces_in_torrent, "");
        NS_LOG_INFO("too many pieces in torrent");
			return;
		}

		if (m_torrent_file->num_pieces() == 0)
		{
			set_error(errors::torrent_invalid_length, "");
        NS_LOG_INFO("invalid length");
			return;
		}

		if (has_picker())
		{
			int blocks_per_piece = (m_torrent_file->piece_length() + block_size() - 1) / block_size();
			int blocks_in_last_piece = ((m_torrent_file->total_size() % m_torrent_file->piece_length())
				+ block_size() - 1) / block_size();
			m_picker->init(blocks_per_piece, blocks_in_last_piece, m_torrent_file->num_pieces());
		}

		if (m_share_mode)
		{
			// in share mode, all pieces have their priorities initialized to 0
			std::fill(m_file_priority.begin(), m_file_priority.end(), 0);
		}

		// in case file priorities were passed in via the add_torrent_params
		// ans also in the case of share mode, we need to update the priorities
		update_piece_priorities();

		if (m_seed_mode)
		{
			std::vector<char>().swap(m_resume_data);
			lazy_entry().swap(m_resume_entry);
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			m_resume_data_loaded = true;
#endif
			return;
		}

		set_state(torrent_status::downloading);

		if (m_resume_entry.type() == lazy_entry::dict_t)
		{
			int ev = 0;
			if (m_resume_entry.dict_find_string_value("file-format") != "libtorrent resume file")
				ev = errors::invalid_file_tag;
	
			std::string info_hash = m_resume_entry.dict_find_string_value("info-hash");
			if (!ev && info_hash.empty())
				ev = errors::missing_info_hash;

			if (!ev && sha1_hash(info_hash) != m_torrent_file->info_hash())
				ev = errors::mismatching_info_hash;


			if (ev)
			{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
				debug_log("fastresume data rejected: %s"
					, error_code(ev, get_libtorrent_category()).message().c_str());
#endif
				std::vector<char>().swap(m_resume_data);
				lazy_entry().swap(m_resume_entry);
			}
			else
			{
				//read_resume_data(m_resume_entry);
			}
		}
	
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_resume_data_loaded = true;
#endif

		TORRENT_ASSERT(block_size() > 0);
		int file = 0;
		for (file_storage::iterator i = m_torrent_file->files().begin()
			, end(m_torrent_file->files().end()); i != end; ++i, ++file)
		{
			if (!i->pad_file || i->size == 0) continue;
			m_padding += i->size;
			
			peer_request pr = m_torrent_file->map_file(file, 0, m_torrent_file->file_at(file).size);
			int off = pr.start & (block_size()-1);
			if (off != 0) { pr.length -= block_size() - off; pr.start += block_size() - off; }
			TORRENT_ASSERT((pr.start & (block_size()-1)) == 0);

			int block = block_size();
			int blocks_per_piece = m_torrent_file->piece_length() / block;
			piece_block pb(pr.piece, pr.start / block);
			for (; pr.length >= block; pr.length -= block, ++pb.block_index)
			{
				if (int(pb.block_index) == blocks_per_piece) { pb.block_index = 0; ++pb.piece_index; }
				m_picker->mark_as_finished(pb, 0);
			}
			// ugly edge case where padfiles are not used they way they're
			// supposed to be. i.e. added back-to back or at the end
			if (int(pb.block_index) == blocks_per_piece) { pb.block_index = 0; ++pb.piece_index; }
			if (pr.length > 0 && ((boost::next(i) != end && boost::next(i)->pad_file)
				|| boost::next(i) == end))
			{
				m_picker->mark_as_finished(pb, 0);
			}
		}

		if (m_padding > 0)
		{
			// if we marked an entire piece as finished, we actually
			// need to consider it finished

			std::vector<piece_picker::downloading_piece> const& dq
				= m_picker->get_download_queue();

			std::vector<int> have_pieces;

			for (std::vector<piece_picker::downloading_piece>::const_iterator i
				= dq.begin(); i != dq.end(); ++i)
			{
				int num_blocks = m_picker->blocks_in_piece(i->index);
				if (i->finished < num_blocks) continue;
				have_pieces.push_back(i->index);
			}

			for (std::vector<int>::iterator i = have_pieces.begin();
				i != have_pieces.end(); ++i)
			{
				we_have(*i);
			}
		}

		//m_storage->async_check_fastresume(&m_resume_entry
		//	, boost::bind(&torrent::on_resume_data_checked
		//	, shared_from_this(), _1, _2));
	}

	bt_peer_connection* torrent::find_peer(ns3::InetSocketAddress const& ep) const
	{
		for (const_peer_iterator i = m_connections.begin(); i != m_connections.end(); ++i)
		{
			peer_connection* p = *i;
			if (p->type() != peer_connection::bittorrent_connection) continue;
            // TODO:这里只比较了IP地址，没有比较端口
			if (p->remote().GetPeerAddress() == ep.GetIpv4()) return (bt_peer_connection*)p;
		}
		return 0;
	}

//	void torrent::queue_torrent_check()
//	{
//		TORRENT_ASSERT(m_ses.is_network_thread());
//		if (m_queued_for_checking) return;
//		m_queued_for_checking = true;
//		m_ses.queue_check_torrent(shared_from_this());
//	}

	//void torrent::dequeue_torrent_check()
	//{
	//	TORRENT_ASSERT(m_ses.is_network_thread());
	//	if (!m_queued_for_checking) return;
	//	m_queued_for_checking = false;
	//	m_ses.dequeue_check_torrent(shared_from_this());
	//}

	void torrent::use_interface(std::string net_interfaces)
	{
		INVARIANT_CHECK;
		m_net_interfaces.clear();

	/*	char* str = allocate_string_copy(net_interfaces.c_str());
		char* ptr = str;

        // TODO: 禁用boost::asio
        
		while (ptr)
		{
			char* space = strchr(ptr, ',');
			if (space) *space++ = 0;
			error_code ec;
			address a(address::from_string(ptr, ec));
			ptr = space;
			if (ec) continue;
			m_net_interfaces.push_back(ns3::InetSocketAddress(a, 0));
		}
		free(str);*/
	}

	ns3::InetSocketAddress torrent::get_interface() const
	{
        // TODO: 禁用boost::asio
		//if (m_net_interfaces.empty()) return ns3::InetSocketAddress(address_v4(), 0);
		if (m_interface_index >= m_net_interfaces.size()) m_interface_index = 0;
		return m_net_interfaces[m_interface_index++];
	}

	void torrent::on_tracker_announce_disp(boost::weak_ptr<torrent> p
		, error_code const& e)
	{
#if defined TORRENT_ASIO_DEBUGGING
		complete_async("tracker::on_tracker_announce_disp");
#endif
		if (e) return;
		boost::shared_ptr<torrent> t = p.lock();
		if (!t) return;
		t->on_tracker_announce();
	}

	void torrent::on_tracker_announce()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		m_waiting_tracker = false;	
		if (m_abort) return;
		announce_with_tracker();
	}

	void torrent::announce_with_tracker(tracker_request::event_t e
		, ns3::Address const& bind_interface)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		TORRENT_ASSERT(m_ses.is_network_thread());
		INVARIANT_CHECK;

		if (m_trackers.empty())
		{
            NS_LOG_ERROR("tracker is empty");
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
			debug_log("*** announce_with_tracker: no trackers");
#endif
			return;
		}

		if (m_abort) e = tracker_request::stopped;

		// if we're not announcing to trackers, only allow
		// stopping
//		if (e != tracker_request::stopped && !m_announce_to_trackers)
//		{
//#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
//			debug_log("*** announce_with_tracker: event != stopped && !m_announce_to_trackers");
//#endif
//			return;
//		}

		TORRENT_ASSERT(m_allow_peers || e == tracker_request::stopped);

		//if (e == tracker_request::none && is_finished() && !is_seed())
		//	e = tracker_request::paused;

		tracker_request req;
		//req.apply_ip_filter = m_apply_ip_filter && m_ses.m_settings.apply_ip_filter_to_trackers;
		req.info_hash = m_torrent_file->info_hash();
		req.pid = m_ses.get_peer_id();
		req.downloaded = m_stat.total_payload_download() - m_total_failed_bytes;
		req.uploaded = m_stat.total_payload_upload();
		req.corrupt = m_total_failed_bytes;
        try
        {
		    req.left = bytes_left();
        }
        catch(exception& ex)
        {
		    req.left = 16*1024;
        }

		// exclude redundant bytes if we should
		if (!settings().report_true_downloaded)
			req.downloaded -= m_total_redundant_bytes;
		if (req.downloaded < 0) req.downloaded = 0;

		req.event = e;
		error_code ec;

        // TODO: 临时禁用asio
		/*if (!m_ses.m_settings.anonymous_mode)
		{
			ns3::InetSocketAddress ep = m_ses.get_ipv4_interface();
			if (ep != ns3::InetSocketAddress()) req.ipv4 = ep.ns3::Ipv4Address.to_string(ec);
		}*/

		// if we are aborting. we don't want any new peers
		req.num_want = (req.event == tracker_request::stopped)
			?0:settings().num_want;

        // 张惊 这个从m_ses换到从torrent自己获得数据
		req.listen_port = listen_port();
        // TODO: 由于磁盘读写被禁用，这里去掉else的内容
	//	if (m_ses.m_key)
			req.key = m_ses.m_key;
	//	else
	//		req.key = tracker_key();

		ptime now = time_now_hires();

		// the tier is kept as INT_MAX until we find the first
		// tracker that works, then it's set to that tracker's
		// tier.
		int tier = INT_MAX;

		// have we sent an announce in this tier yet?
		bool sent_announce = false;

        NS_LOG_INFO("trackers count "<< m_trackers.size());

		for (int i = 0; i < int(m_trackers.size()); ++i)
		{
			announce_entry& ae = m_trackers[i];
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
			char msg[1000];
			snprintf(msg, sizeof(msg), "*** announce with tracker: considering \"%s\" "
				"[ announce_to_all_tiers: %d announce_to_all_trackers: %d"
				" i->tier: %d tier: %d "
				" is_working: %d fails: %d fail_limit: %d updating: %d"
				" can_announce: %d sent_announce: %d ]"
				, ae.url.c_str(), settings().announce_to_all_tiers
				, settings().announce_to_all_trackers
				, ae.tier, tier, ae.is_working(), ae.fails, ae.fail_limit
				, ae.updating, ae.can_announce(now, is_seed()), sent_announce);
			debug_log(msg);
#endif
			// if trackerid is not specified for tracker use default one, probably set explicitly
			//req.trackerid = ae.trackerid.empty() ? m_trackerid : ae.trackerid;
			if (settings().announce_to_all_tiers
				&& !settings().announce_to_all_trackers
				&& sent_announce
				&& ae.tier <= tier
				&& tier != INT_MAX)
				continue;

			if (ae.tier > tier && sent_announce && !settings().announce_to_all_tiers) break;
			if (ae.is_working()) { tier = ae.tier; sent_announce = false; }
			if (!ae.can_announce(now, is_seed()))
			{
				// this counts
				if (ae.is_working()) sent_announce = true;
				continue;
			}
			
			req.url = ae.url;
			req.event = e;
			if (req.event == tracker_request::none)
			{
				if (!ae.start_sent) req.event = tracker_request::started;
				else if (!ae.complete_sent && is_seed()) req.event = tracker_request::completed;
			}

			if (!is_any(bind_interface)) req.bind_ip = bind_interface;
			else 
                req.bind_ip = m_ses.m_listen_interface.GetPeerAddress().ConvertTo();

            // TODO: 将ASIO的连接tracker代码改为udp的
            /*
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
			debug_log("==> TRACKER REQUEST \"%s\" event: %s abort: %d"
				, req.url.c_str()
				, (req.event==tracker_request::stopped?"stopped"
					:req.event==tracker_request::started?"started":"")
				, m_abort);

            
			if (m_abort)
			{
				boost::shared_ptr<aux::tracker_logger> tl(new aux::tracker_logger(m_ses));
				m_ses.m_tracker_manager.queue_request(m_ses.m_io_service, m_ses.m_half_open, req
					, tracker_login(), tl);
			}
			else
#endif*/
			{
                // TODO: 传递tracker的IP地址
				m_ses.m_tracker_manager.queue_request(m_ses.GetNode(), req
					, tracker_login() , shared_from_this());
			}

			ae.updating = true;
			ae.next_announce = now + seconds(20);
			ae.min_announce = now + seconds(10);


			sent_announce = true;
			if (ae.is_working()
				&& !settings().announce_to_all_trackers
				&& !settings().announce_to_all_tiers)
				break;
		}
		update_tracker_timer(now);
	}

	void torrent::scrape_tracker()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		m_last_scrape = 0;

		if (m_trackers.empty()) return;

		int i = m_last_working_tracker;
		if (i == -1) i = 0;
		
		tracker_request req;
		//req.apply_ip_filter = m_apply_ip_filter && m_ses.m_settings.apply_ip_filter_to_trackers;
		req.info_hash = m_torrent_file->info_hash();
		req.kind = tracker_request::scrape_request;
		req.url = m_trackers[i].url;
		req.bind_ip = m_ses.m_listen_interface.GetPeerAddress().ConvertTo();
            // TODO: 禁用boost::asio
		//m_ses.m_tracker_manager.queue_request(m_ses.m_io_service, m_ses.m_half_open, req
		//	, tracker_login(), shared_from_this());
	}

	void torrent::tracker_warning(tracker_request const& req, std::string const& msg)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());

		INVARIANT_CHECK;
	}
	
 	void torrent::tracker_scrape_response(tracker_request const& req
 		, int complete, int incomplete, int downloaded, int downloaders)
 	{
		TORRENT_ASSERT(m_ses.is_network_thread());
 
 		INVARIANT_CHECK;
		TORRENT_ASSERT(req.kind == tracker_request::scrape_request);
 
		if ((complete >= 0 && m_complete != complete)
			|| (incomplete >= 0 && m_incomplete != incomplete)
			|| (downloaders >= 0 && m_downloaders != downloaders))
			state_updated();

		if (complete >= 0) m_complete = complete;
		if (incomplete >= 0) m_incomplete = incomplete;
		if (downloaders >= 0) m_downloaders = downloaders;

	}
 
	void torrent::tracker_response(
		tracker_request const& r
		, ns3::Address const& tracker_ip // this is the IP we connected to
		, std::list<ns3::Address> const& tracker_ips // these are all the IPs it resolved to
		, std::vector<peer_entry>& peer_list
		, int interval
		, int min_interval
		, int complete
		, int incomplete
		, ns3::Address const& external_ip
		, const std::string& trackerid)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		TORRENT_ASSERT(m_ses.is_network_thread());

		INVARIANT_CHECK;
		TORRENT_ASSERT(r.kind == tracker_request::announce_request);

        // 张惊：参数检查
		if (external_ip != ns3::Address() && !tracker_ips.empty())
			m_ses.set_external_address(external_ip, aux::session_impl::source_tracker
				, *tracker_ips.begin());

		ptime now = time_now();

		if (interval < settings().min_announce_interval)
			interval = settings().min_announce_interval;

        // 张惊：查找tracker
		announce_entry* ae = find_tracker(r);
		if (ae)
		{
			if (!ae->start_sent && r.event == tracker_request::started)
				ae->start_sent = true;
			if (!ae->complete_sent && r.event == tracker_request::completed)
				ae->complete_sent = true;
			ae->verified = true;
			ae->updating = false;
			ae->fails = 0;
			ae->next_announce = now + seconds(interval);
			ae->min_announce = now + seconds(min_interval);
			int tracker_index = ae - &m_trackers[0];
			m_last_working_tracker = prioritize_tracker(tracker_index);

			if ((!trackerid.empty()) && (ae->trackerid != trackerid))
			{
				ae->trackerid = trackerid;
			}
		}
		update_tracker_timer(now);

		if (complete >= 0) m_complete = complete;
		if (incomplete >= 0) m_incomplete = incomplete;
		if (complete >= 0 && incomplete >= 0)
			m_last_scrape = 0;

#if (defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING) && TORRENT_USE_IOSTREAM
		std::stringstream s;
		s << "TRACKER RESPONSE:\n"
			"interval: " << interval << "\n"
			"peers:\n";
		for (std::vector<peer_entry>::const_iterator i = peer_list.begin();
			i != peer_list.end(); ++i)
		{
			s << "  " << std::setfill(' ') << std::setw(16) << i->ip
				<< " " << std::setw(5) << std::dec << i->port << "  ";
			if (!i->pid.is_all_zeros()) s << " " << i->pid << " " << identify_client(i->pid);
			s << "\n";
		}
		s << "external ip: " << external_ip << "\n";
		s << "tracker ips: ";
		std::copy(tracker_ips.begin(), tracker_ips.end(), std::ostream_iterator<address>(s, " "));
		s << "\n";
		s << "we connected to: " << tracker_ip << "\n";
		debug_log("%s", s.str().c_str());
#endif
		// for each of the peers we got from the tracker
        // 张惊：向policy添加要链接的peer
		for (std::vector<peer_entry>::iterator i = peer_list.begin();
			i != peer_list.end(); ++i)
		{
			// don't make connections to ourself
			if (i->pid == m_ses.get_peer_id())
				continue;

			error_code ec;
			ns3::InetSocketAddress a(i->ip.c_str(), i->port);

			if (ec)
			{
				// assume this is because we got a hostname instead of
				// an ip address from the tracker

				{
#if defined TORRENT_ASIO_DEBUGGING
					add_outstanding_async("torrent::on_peer_name_lookup");
#endif
				}
			}
			else
			{
				// ignore local addresses from the tracker (unless the tracker is local too)
				// there are 2 reasons to allow this:
				// 1. retrackers are popular in russia, where an ISP runs a tracker within
				//    the AS (but not on the local network) giving out peers only from the
				//    local network
				// 2. it might make sense to have a tracker extension in the future where
				//    trackers records a peer's internal and external IP, and match up
				//    peers on the same local network
				if (is_local(a.GetIpv4().ConvertTo()) && !is_local(tracker_ip)) 
                {
                    continue;
                }

                ns3::Ipv4EndPoint enp(a.GetIpv4(), a.GetPort());
				m_policy.add_peer(enp, i->pid, peer_info::tracker, 0);
			}
		}

		m_got_tracker_response = true;

		// we're listening on an interface type that was not used
		// when talking to the tracker. If there is a matching interface
		// type in the tracker IP list, make another tracker request
		// using that interface
		// in order to avoid triggering this case over and over, don't
		// do it if the bind IP for the tracker request that just completed
		// matches one of the listen interfaces, since that means this
		// announce was the second one
		// don't connect twice just to tell it we're stopping

	//	if (r.bind_ip != m_ses.m_ipv4_interface.GetPeerAddress()
	//		&& r.event != tracker_request::stopped)
	//	{

	//		//std::list<ns3::Address>::const_iterator i = std::find_if(tracker_ips.begin()
	//		//	, tracker_ips.end(), boost::bind(&address::is_v4, _1) != tracker_ip.is_v4());
    //        std::list<ns3::Address>::const_iterator i = tracker_ips.begin();
    //        
    //        //std::list<ns3::Address>::const_iterator i;
    //        for (;i != tracker_ips.end();++i)
    //        {
    //            if ((*i) == tracker_ip )
    //                break;
    //        }

	//		if (i != tracker_ips.end())
	//		{
	//			// the tracker did resolve to a different type of address, so announce
	//			// to that as well

	//			// tell the tracker to bind to the opposite protocol type
    //            ns3::Address bind_interface = m_ses.m_ipv4_interface.GetPeerAddress();
	//			announce_with_tracker(r.event, bind_interface);
    //            ostringstream ostr;
    //            //char* pstr = print_address(bind_interface).c_str();
    //            ostr<<"announce again using "<<" as the bind interface";
    //            NS_LOG_INFO(" " << ostr.str().c_str());
	//		}
	//	}

		if (m_need_connect_boost)
		{
			m_need_connect_boost = false;
			// this is the first tracker response for this torrent
			// instead of waiting one second for session_impl::on_tick()
			// to be called, connect to a few peers immediately
			int conns = (std::min)((std::min)(m_ses.m_settings.torrent_connect_boost
				, m_ses.m_settings.connections_limit - m_ses.num_connections())
				//, m_ses.m_half_open.free_slots())
                    // 张惊：这里源代码可能写错了，初始链接的情况下，这个值肯定是负数
				, m_ses.m_settings.connection_speed -  m_ses.m_boost_connections);

            NS_LOG_DEBUG("peer connect boost number is " << conns);

			while (want_more_peers() && conns > 0)
			{
				if (!m_policy.connect_one_peer(m_ses.session_time())) break;
				// increase m_ses.m_boost_connections for each connection
				// attempt. This will be deducted from the connect speed
				// the next time session_impl::on_tick() is triggered
				--conns;
				++m_ses.m_boost_connections;
			}
		}

		state_updated();
	}

    // TODO: 暂时禁用boost::asio
	ptime torrent::next_announce() const
	{
	    //return m_waiting_tracker?m_tracker_timer.expires_at():min_time();
		return min_time();
	}

	void torrent::force_tracker_request()
	{
		force_tracker_request(time_now_hires());
	}

	void torrent::force_tracker_request(ptime t)
	{
		//if (is_paused()) return;
		for (std::vector<announce_entry>::iterator i = m_trackers.begin()
			, end(m_trackers.end()); i != end; ++i)
			i->next_announce = (std::max)(t, i->min_announce) + seconds(1);
		update_tracker_timer(time_now_hires());
	}

	void torrent::set_tracker_login(
		std::string const& name
		, std::string const& pw)
	{
		m_username = name;
		m_password = pw;
	}

    // TODO: 临时禁用asio
	/*void torrent::on_peer_name_lookup(error_code const& e, tcp::resolver::iterator host
		, peer_id pid)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());

		INVARIANT_CHECK;

#if defined TORRENT_ASIO_DEBUGGING
		complete_async("torrent::on_peer_name_lookup");
#endif

#if defined TORRENT_LOGGING
		if (e)
			debug_log("peer name lookup error: %s", e.message().c_str());
#endif
		if (e || host == tcp::resolver::iterator() ||
			m_ses.is_aborted()) return;

		if (m_apply_ip_filter
			&& m_ses.m_ip_filter.access(host->endpoint().address()) & ip_filter::blocked)
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
			error_code ec;
			debug_log("blocked ip from tracker: %s", host->endpoint().address().to_string(ec).c_str());
#endif
			return;
		}
			
		m_policy.add_peer(*host, pid, peer_info::tracker, 0);
	}*/

	size_type torrent::bytes_left() const
	{
		// if we don't have the metadata yet, we
		// cannot tell how big the torrent is.
		if (!valid_metadata())
            throw exception();

		return m_torrent_file->total_size()
			- quantized_bytes_done();
	}

	size_type torrent::quantized_bytes_done() const
	{
//		INVARIANT_CHECK;

		if (!valid_metadata()) return 0;

		if (m_torrent_file->num_pieces() == 0)
			return 0;

		if (is_seed()) return m_torrent_file->total_size();

		const int last_piece = m_torrent_file->num_pieces() - 1;

		size_type total_done
			= size_type(num_have()) * m_torrent_file->piece_length();

		// if we have the last piece, we have to correct
		// the amount we have, since the first calculation
		// assumed all pieces were of equal size
		if (m_picker->have_piece(last_piece))
		{
			int corr = m_torrent_file->piece_size(last_piece)
				- m_torrent_file->piece_length();
			total_done += corr;
		}
		return total_done;
	}

	// returns the number of bytes we are interested
	// in for the given block. This returns block_size()
	// for all blocks except the last one (if it's smaller
	// than block_size()) and blocks that overlap a padding
	// file
	int torrent::block_bytes_wanted(piece_block const& p) const
	{
		file_storage const& fs = m_torrent_file->files();
		int piece_size = m_torrent_file->piece_size(p.piece_index);
		int offset = p.block_index * block_size();
		if (m_padding == 0) return (std::min)(piece_size - offset, int(block_size()));

		std::vector<file_slice> files = fs.map_block(
			p.piece_index, offset, (std::min)(piece_size - offset, int(block_size())));
		int ret = 0;
		for (std::vector<file_slice>::iterator i = files.begin()
			, end(files.end()); i != end; ++i)
		{
			file_entry const& fe = fs.at(i->file_index);
			if (fe.pad_file) continue;
			ret += i->size;
		}
		TORRENT_ASSERT(ret <= (std::min)(piece_size - offset, int(block_size())));
		return ret;
	}

	// fills in total_wanted, total_wanted_done and total_done
	void torrent::bytes_done(torrent_status& st, bool accurate) const
	{
		INVARIANT_CHECK;

		st.total_done = 0;
		st.total_wanted_done = 0;
		st.total_wanted = m_torrent_file->total_size();

		TORRENT_ASSERT(st.total_wanted >= m_padding);
		TORRENT_ASSERT(st.total_wanted >= 0);

		if (!valid_metadata() || m_torrent_file->num_pieces() == 0)
			return;

		TORRENT_ASSERT(st.total_wanted >= size_type(m_torrent_file->piece_length())
			* (m_torrent_file->num_pieces() - 1));

		const int last_piece = m_torrent_file->num_pieces() - 1;
		const int piece_size = m_torrent_file->piece_length();

		if (is_seed())
		{
			st.total_done = m_torrent_file->total_size() - m_padding;
			st.total_wanted_done = st.total_done;
			st.total_wanted = st.total_done;
			return;
		}

		TORRENT_ASSERT(num_have() >= m_picker->num_have_filtered());
		st.total_wanted_done = size_type(num_have() - m_picker->num_have_filtered())
			* piece_size;
		TORRENT_ASSERT(st.total_wanted_done >= 0);
		
		st.total_done = size_type(num_have()) * piece_size;
		TORRENT_ASSERT(num_have() < m_torrent_file->num_pieces());

		int num_filtered_pieces = m_picker->num_filtered()
			+ m_picker->num_have_filtered();
		int last_piece_index = m_torrent_file->num_pieces() - 1;
		if (m_picker->piece_priority(last_piece_index) == 0)
		{
			st.total_wanted -= m_torrent_file->piece_size(last_piece_index);
			--num_filtered_pieces;
		}
		st.total_wanted -= size_type(num_filtered_pieces) * piece_size;
	
		// if we have the last piece, we have to correct
		// the amount we have, since the first calculation
		// assumed all pieces were of equal size
		if (m_picker->have_piece(last_piece))
		{
			TORRENT_ASSERT(st.total_done >= piece_size);
			int corr = m_torrent_file->piece_size(last_piece)
				- piece_size;
			TORRENT_ASSERT(corr <= 0);
			TORRENT_ASSERT(corr > -piece_size);
			st.total_done += corr;
			if (m_picker->piece_priority(last_piece) != 0)
			{
				TORRENT_ASSERT(st.total_wanted_done >= piece_size);
				st.total_wanted_done += corr;
			}
		}
		TORRENT_ASSERT(st.total_wanted >= st.total_wanted_done);

		// subtract padding files
		if (m_padding > 0)
		{
			file_storage const& files = m_torrent_file->files();
			int fileno = 0;
			for (file_storage::iterator i = files.begin()
					, end(files.end()); i != end; ++i, ++fileno)
			{
				if (!i->pad_file) continue;
				peer_request p = files.map_file(fileno, 0, i->size);
				for (int j = p.piece; p.length > 0; ++j)
				{
					int deduction = (std::min)(p.length, piece_size - p.start);
					bool done = m_picker->have_piece(j);
					bool wanted = m_picker->piece_priority(j) > 0;
					if (done) st.total_done -= deduction;
					if (wanted) st.total_wanted -= deduction;
					if (wanted && done) st.total_wanted_done -= deduction;
					TORRENT_ASSERT(st.total_done >= 0);
					TORRENT_ASSERT(st.total_wanted >= 0);
					TORRENT_ASSERT(st.total_wanted_done >= 0);
					p.length -= piece_size - p.start;
					p.start = 0;
					++p.piece;
				}
			}
		}

		TORRENT_ASSERT(st.total_done <= m_torrent_file->total_size() - m_padding);
		TORRENT_ASSERT(st.total_wanted_done <= m_torrent_file->total_size() - m_padding);
		TORRENT_ASSERT(st.total_wanted_done >= 0);
		TORRENT_ASSERT(st.total_done >= st.total_wanted_done);

		// this is expensive, we might not want to do it all the time
		if (!accurate) return;

		const std::vector<piece_picker::downloading_piece>& dl_queue
			= m_picker->get_download_queue();

		const int blocks_per_piece = (piece_size + block_size() - 1) / block_size();

		// look at all unfinished pieces and add the completed
		// blocks to our 'done' counter
		for (std::vector<piece_picker::downloading_piece>::const_iterator i =
			dl_queue.begin(); i != dl_queue.end(); ++i)
		{
			int corr = 0;
			int index = i->index;
			// completed pieces are already accounted for
			if (m_picker->have_piece(index)) continue;
			TORRENT_ASSERT(i->finished <= m_picker->blocks_in_piece(index));

#ifdef TORRENT_DEBUG
			for (std::vector<piece_picker::downloading_piece>::const_iterator j = boost::next(i);
				j != dl_queue.end(); ++j)
			{
				TORRENT_ASSERT(j->index != index);
			}
#endif

			for (int j = 0; j < blocks_per_piece; ++j)
			{
#ifdef TORRENT_EXPENSIVE_INVARIANT_CHECKS
				TORRENT_ASSERT(m_picker->is_finished(piece_block(index, j))
					== (i->info[j].state == piece_picker::block_info::state_finished));
#endif
				if (i->info[j].state == piece_picker::block_info::state_finished)
				{
					corr += block_bytes_wanted(piece_block(index, j));
				}
				TORRENT_ASSERT(corr >= 0);
				TORRENT_ASSERT(index != last_piece || j < m_picker->blocks_in_last_piece()
					|| i->info[j].state != piece_picker::block_info::state_finished);
			}

			st.total_done += corr;
			if (m_picker->piece_priority(index) > 0)
				st.total_wanted_done += corr;
		}

		TORRENT_ASSERT(st.total_wanted <= m_torrent_file->total_size() - m_padding);
		TORRENT_ASSERT(st.total_done <= m_torrent_file->total_size() - m_padding);
		TORRENT_ASSERT(st.total_wanted_done <= m_torrent_file->total_size() - m_padding);
		TORRENT_ASSERT(st.total_wanted_done >= 0);
		TORRENT_ASSERT(st.total_done >= st.total_wanted_done);

		std::map<piece_block, int> downloading_piece;
		for (const_peer_iterator i = begin(); i != end(); ++i)
		{
			peer_connection* pc = *i;
			boost::optional<piece_block_progress> p
				= pc->downloading_piece_progress();
			if (!p) continue;

			if (m_picker->have_piece(p->piece_index))
				continue;

			piece_block block(p->piece_index, p->block_index);
			if (m_picker->is_finished(block))
				continue;

			std::map<piece_block, int>::iterator dp
				= downloading_piece.find(block);
			if (dp != downloading_piece.end())
			{
				if (dp->second < p->bytes_downloaded)
					dp->second = p->bytes_downloaded;
			}
			else
			{
				downloading_piece[block] = p->bytes_downloaded;
			}
#ifdef TORRENT_DEBUG
			TORRENT_ASSERT(p->bytes_downloaded <= p->full_block_bytes);
			TORRENT_ASSERT(p->full_block_bytes == to_req(piece_block(
				p->piece_index, p->block_index)).length);
#endif
		}
		for (std::map<piece_block, int>::iterator i = downloading_piece.begin();
			i != downloading_piece.end(); ++i)
		{
			int done = (std::min)(block_bytes_wanted(i->first), i->second);
			st.total_done += done;
			if (m_picker->piece_priority(i->first.piece_index) != 0)
				st.total_wanted_done += done;
		}

		TORRENT_ASSERT(st.total_done <= m_torrent_file->total_size() - m_padding);
		TORRENT_ASSERT(st.total_wanted_done <= m_torrent_file->total_size() - m_padding);

#ifdef TORRENT_DEBUG

		if (st.total_done >= m_torrent_file->total_size())
		{
			// Thist happens when a piece has been downloaded completely
			// but not yet verified against the hash
			fprintf(stderr, "num_have: %d\nunfinished:\n", num_have());
			for (std::vector<piece_picker::downloading_piece>::const_iterator i =
				dl_queue.begin(); i != dl_queue.end(); ++i)
			{
				fprintf(stderr, "  %d ", i->index);
				for (int j = 0; j < blocks_per_piece; ++j)
				{
					char const* state = i->info[j].state == piece_picker::block_info::state_finished ? "1" : "0";
					fputs(state, stderr);
				}
				fputs("\n", stderr);
			}
			
			fputs("downloading pieces:\n", stderr);

			for (std::map<piece_block, int>::iterator i = downloading_piece.begin();
				i != downloading_piece.end(); ++i)
			{
				fprintf(stderr, "   %d:%d  %d\n", int(i->first.piece_index), int(i->first.block_index), i->second);
			}

		}

		TORRENT_ASSERT(st.total_done <= m_torrent_file->total_size());
		TORRENT_ASSERT(st.total_wanted_done <= m_torrent_file->total_size());

#endif

		TORRENT_ASSERT(st.total_done >= st.total_wanted_done);
	}

	// passed_hash_check
	// 0: success, piece passed check
	// -1: disk failure
	// -2: piece failed check
	void torrent::piece_finished(int index, int passed_hash_check)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		debug_log("*** PIECE_FINISHED [ p: %d | chk: %s | size: %d ]"
			, index, ((passed_hash_check == 0)
				?"passed":passed_hash_check == -1
				?"disk failed":"failed")
			, m_torrent_file->piece_size(index));
#endif

		TORRENT_ASSERT(valid_metadata());

		// it's possible to get here if the last piece was downloaded
		// from peers and inserted with add_piece at the same time.
		// if we're a seed, we won't have a piece picker, and can't continue
		if (is_seed()) return;

		TORRENT_ASSERT(!m_picker->have_piece(index));

		state_updated();

		// even though the piece passed the hash-check
		// it might still have failed being written to disk
		// if so, piece_picker::write_failed() has been
		// called, and the piece is no longer finished.
		// in this case, we have to ignore the fact that
		// it passed the check
		if (!m_picker->is_piece_finished(index)) return;

		if (passed_hash_check == 0)
		{
			// the following call may cause picker to become invalid
			// in case we just became a seed
			piece_passed(index);
			// if we're in seed mode, we just acquired this piece
			// mark it as verified
			if (m_seed_mode) verified(index);
		}
		else if (passed_hash_check == -2)
		{
			// piece_failed() will restore the piece
			piece_failed(index);
		}
		else
		{
			TORRENT_ASSERT(passed_hash_check == -1);
			m_picker->restore_piece(index);
			restore_piece_state(index);
		}
	}

	void torrent::update_sparse_piece_prio(int i, int start, int end)
	{
		TORRENT_ASSERT(m_picker);
		if (m_picker->have_piece(i) || m_picker->piece_priority(i) == 0)
			return;
		bool have_before = i == 0 || m_picker->have_piece(i - 1);
		bool have_after = i == end - 1 || m_picker->have_piece(i + 1);
		if (have_after && have_before)
			m_picker->set_piece_priority(i, 7);
		else if (have_after || have_before)
			m_picker->set_piece_priority(i, 6);
	}

	void torrent::we_have(int index)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		// update m_file_progress
		TORRENT_ASSERT(m_picker);
		TORRENT_ASSERT(!have_piece(index));
		TORRENT_ASSERT(!m_picker->have_piece(index));

		const int piece_size = m_torrent_file->piece_length();
		size_type off = size_type(index) * piece_size;
		file_storage::iterator f = m_torrent_file->files().file_at_offset(off);
		int size = m_torrent_file->piece_size(index);
		int file_index = f - m_torrent_file->files().begin();
		for (; size > 0; ++f, ++file_index)
		{
			size_type file_offset = off - f->offset;
			TORRENT_ASSERT(f != m_torrent_file->files().end());
			TORRENT_ASSERT(file_offset <= f->size);
			int add = (std::min)(f->size - file_offset, (size_type)size);
			m_file_progress[file_index] += add;

			TORRENT_ASSERT(m_file_progress[file_index]
				<= m_torrent_file->files().at(file_index).size);

			size -= add;
			off += add;
			TORRENT_ASSERT(size >= 0);
		}

		m_picker->we_have(index);
	}

	void torrent::piece_passed(int index)
	{
//		INVARIANT_CHECK;
		TORRENT_ASSERT(m_ses.is_network_thread());

		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < m_torrent_file->num_pieces());
#ifdef TORRENT_DEBUG
		// make sure all blocks were successfully written before we
		// declare the piece as "we have".
		piece_picker::downloading_piece dp;
		m_picker->piece_info(index, dp);
		int blocks_in_piece = m_picker->blocks_in_piece(index);
		TORRENT_ASSERT(dp.finished == blocks_in_piece);
		TORRENT_ASSERT(dp.writing == 0);
		TORRENT_ASSERT(dp.requested == 0);
		TORRENT_ASSERT(dp.index == index);
#endif

		m_need_save_resume_data = true;
		state_updated();

		remove_time_critical_piece(index, true);

		bool was_finished = m_picker->num_filtered() + num_have()
			== torrent_file().num_pieces();

		std::vector<void*> downloaders;
		m_picker->get_downloaders(downloaders, index);

		// increase the trust point of all peers that sent
		// parts of this piece.
		std::set<void*> peers;

		// these policy::peer pointers are owned by m_policy and they may be
		// invalidated if a peer disconnects. We cannot keep them across any
		// significant operations, but we should use them right away
		// ignore NULL pointers
		std::remove_copy(downloaders.begin(), downloaders.end()
			, std::inserter(peers, peers.begin()), (policy::peer*)0);

		for (std::set<void*>::iterator i = peers.begin()
			, end(peers.end()); i != end; ++i)
		{
			policy::peer* p = static_cast<policy::peer*>(*i);
			TORRENT_ASSERT(p != 0);
			if (p == 0) continue;
			TORRENT_ASSERT(p->in_use);
			p->on_parole = false;
			int trust_points = p->trust_points;
			++trust_points;
			if (trust_points > 8) trust_points = 8;
			p->trust_points = trust_points;
			if (p->connection)
			{
				TORRENT_ASSERT(p->connection->m_in_use == 1337);
				p->connection->received_valid_data(index);
			}
		}

		// announcing a piece may invalidate the policy::peer pointers
		// so we can't use them anymore

		downloaders.clear();
		peers.clear();

		we_have(index);

		for (peer_iterator i = m_connections.begin(); i != m_connections.end();)
		{
			intrusive_ptr<peer_connection> p = *i;
			++i;
			p->announce_piece(index);
		}

		if (settings().max_sparse_regions > 0
			&& m_picker->sparse_regions() > settings().max_sparse_regions)
		{
			// we have too many sparse regions. Prioritize pieces
			// that won't introduce new sparse regions
			// prioritize pieces that will reduce the number of sparse
			// regions even higher
			int start = m_picker->cursor();
			int end = m_picker->reverse_cursor();
			if (index > start) update_sparse_piece_prio(index - 1, start, end);
			if (index < end - 1) update_sparse_piece_prio(index + 1, start, end);
		}

		// since this piece just passed, we might have
		// become uninterested in some peers where this
		// was the last piece we were interested in
		for (peer_iterator i = m_connections.begin();
			i != m_connections.end();)
		{
			peer_connection* p = *i;
			// update_interest may disconnect the peer and
			// invalidate the iterator
			++i;
			// if we're not interested already, no need to check
			if (!p->is_interesting()) continue;
			// if the peer doesn't have the piece we just got, it
			// wouldn't affect our interest
			if (!p->has_piece(index)) continue;
			p->update_interest();
		}

		if (!was_finished && is_finished())
		{
			// torrent finished
			// i.e. all the pieces we're interested in have
			// been downloaded. Release the files (they will open
			// in read only mode if needed)
			finished();
			// if we just became a seed, picker is now invalid, since it
			// is deallocated by the torrent once it starts seeding
		}

		m_last_download = 0;

		if (m_share_mode)
			recalc_share_mode();
	}

	void torrent::piece_failed(int index)
	{
		// if the last piece fails the peer connection will still
		// think that it has received all of it until this function
		// resets the download queue. So, we cannot do the
		// invariant check here since it assumes:
		// (total_done == m_torrent_file->total_size()) => is_seed()
		INVARIANT_CHECK;
		TORRENT_ASSERT(m_ses.is_network_thread());

		TORRENT_ASSERT(m_storage);
		TORRENT_ASSERT(m_storage->refcount() > 0);
		TORRENT_ASSERT(m_picker.get());
		TORRENT_ASSERT(index >= 0);
	  	TORRENT_ASSERT(index < m_torrent_file->num_pieces());

		// increase the total amount of failed bytes
		add_failed_bytes(m_torrent_file->piece_size(index));

		std::vector<void*> downloaders;
		m_picker->get_downloaders(downloaders, index);

		// decrease the trust point of all peers that sent
		// parts of this piece.
		// first, build a set of all peers that participated
		std::set<void*> peers;
		std::copy(downloaders.begin(), downloaders.end(), std::inserter(peers, peers.begin()));

#ifdef TORRENT_DEBUG
		for (std::vector<void*>::iterator i = downloaders.begin()
			, end(downloaders.end()); i != end; ++i)
		{
			policy::peer* p = (policy::peer*)*i;
			if (p && p->connection)
			{
				p->connection->piece_failed = true;
			}
		}
#endif

		for (std::set<void*>::iterator i = peers.begin()
			, end(peers.end()); i != end; ++i)
		{
			policy::peer* p = static_cast<policy::peer*>(*i);
			if (p == 0) continue;
			TORRENT_ASSERT(p->in_use);
			if (p->connection)
			{
				TORRENT_ASSERT(p->connection->m_in_use == 1337);
				p->connection->received_invalid_data(index);
			}

			if (m_ses.settings().use_parole_mode)
				p->on_parole = true;

			int hashfails = p->hashfails;
			int trust_points = p->trust_points;

			// we decrease more than we increase, to keep the
			// allowed failed/passed ratio low.
			trust_points -= 2;
			++hashfails;
			if (trust_points < -7) trust_points = -7;
			p->trust_points = trust_points;
			if (hashfails > 255) hashfails = 255;
			p->hashfails = hashfails;

			// either, we have received too many failed hashes
			// or this was the only peer that sent us this piece.
			if (p->trust_points <= -7
				|| peers.size() == 1)
			{
				// mark the peer as banned
				m_policy.ban_peer(p);
#ifdef TORRENT_STATS
				++m_ses.m_banned_for_hash_failure;
#endif

				if (p->connection)
				{
#ifdef TORRENT_LOGGING
					debug_log("*** BANNING PEER: \"%s\" Too many corrupt pieces"
						, print_endpoint(p->ip()).c_str());
#endif
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
					p->connection->peer_log("*** BANNING PEER: Too many corrupt pieces");
#endif
					p->connection->disconnect(errors::too_many_corrupt_pieces);
				}
			}
		}

		// we have to let the piece_picker know that
		// this piece failed the check as it can restore it
		// and mark it as being interesting for download
		m_picker->restore_piece(index);

		// we might still have outstanding requests to this
		// piece that hasn't been received yet. If this is the
		// case, we need to re-open the piece and mark any
		// blocks we're still waiting for as requested
		restore_piece_state(index);

		TORRENT_ASSERT(m_storage);

		TORRENT_ASSERT(m_picker->have_piece(index) == false);

#ifdef TORRENT_DEBUG
		for (std::vector<void*>::iterator i = downloaders.begin()
			, end(downloaders.end()); i != end; ++i)
		{
			policy::peer* p = (policy::peer*)*i;
			if (p && p->connection)
			{
				p->connection->piece_failed = false;
			}
		}
#endif
	}

	void torrent::restore_piece_state(int index)
	{
		TORRENT_ASSERT(has_picker());
		for (peer_iterator i = m_connections.begin();
			i != m_connections.end(); ++i)
		{
			peer_connection* p = *i;
			std::vector<pending_block> const& dq = p->download_queue();
			std::vector<pending_block> const& rq = p->request_queue();
			for (std::vector<pending_block>::const_iterator k = dq.begin()
				, end(dq.end()); k != end; ++k)
			{
				if (k->timed_out || k->not_wanted) continue;
				if (int(k->block.piece_index) != index) continue;
				m_picker->mark_as_downloading(k->block, p->peer_info_struct()
					, (piece_picker::piece_state_t)p->peer_speed());
			}
			for (std::vector<pending_block>::const_iterator k = rq.begin()
				, end(rq.end()); k != end; ++k)
			{
				if (int(k->block.piece_index) != index) continue;
				m_picker->mark_as_downloading(k->block, p->peer_info_struct()
					, (piece_picker::piece_state_t)p->peer_speed());
			}
		}
	}

	void torrent::abort()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		INVARIANT_CHECK;

		if (m_abort) return;

		m_abort = true;
		// if the torrent is paused, it doesn't need
		// to announce with even=stopped again.
	//	if (!is_paused())
	//	{
			stop_announcing();
	//	}

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING || defined TORRENT_LOGGING
		log_to_all_peers("ABORTING TORRENT");
#endif

		// disconnect all peers and close all
		// files belonging to the torrents
		disconnect_all(errors::torrent_aborted);

		// post a message to the main thread to destruct
		// the torrent object from there
		TORRENT_ASSERT(m_abort);
		
		//dequeue_torrent_check();

		if (m_state == torrent_status::checking_files)
			set_state(torrent_status::queued_for_checking);

		//m_owning_storage = 0;
	}

	void torrent::super_seeding(bool on)
	{
		if (on == m_super_seeding) return;

		// don't turn on super seeding if we're not a seed
		TORRENT_ASSERT(!on || is_seed() || !m_files_checked);
		if (on && !is_seed() && m_files_checked) return;
		m_super_seeding = on;

		if (m_super_seeding) return;

		// disable super seeding for all peers
		for (peer_iterator i = begin(); i != end(); ++i)
		{
			(*i)->superseed_piece(-1);
		}
	}

	int torrent::get_piece_to_super_seed(bitfield const& bits)
	{
		// return a piece with low availability that is not in
		// the bitfield and that is not currently being super
		// seeded by any peer
		TORRENT_ASSERT(m_super_seeding);
		
		// do a linear search from the first piece
		int min_availability = 9999;
		std::vector<int> avail_vec;
		for (int i = 0; i < m_torrent_file->num_pieces(); ++i)
		{
			if (bits[i]) continue;

			int availability = 0;
			for (const_peer_iterator j = begin(); j != end(); ++j)
			{
				if ((*j)->superseed_piece() == i)
				{
					// avoid superseeding the same piece to more than one
					// peer if we can avoid it. Do this by artificially
					// increase the availability
					availability = 999;
					break;
				}
				if ((*j)->has_piece(i)) ++availability;
			}
			if (availability > min_availability) continue;
			if (availability == min_availability)
			{
				avail_vec.push_back(i);
				continue;
			}
			TORRENT_ASSERT(availability < min_availability);
			min_availability = availability;
			avail_vec.clear();
			avail_vec.push_back(i);
		}

		if (min_availability > 1)
		{
			// if the minimum availability is 2 or more,
			// we shouldn't be super seeding any more
			super_seeding(false);
			return -1;
		}

		return avail_vec[random() % avail_vec.size()];
	}

	std::string torrent::tracker_login() const
	{
		if (m_username.empty() && m_password.empty()) return "";
		return m_username + ":" + m_password;
	}

    // TODO: 禁用磁盘读写
	/*boost::uint32_t torrent::tracker_key() const
	{
		uintptr_t self = (uintptr_t)this;
		uintptr_t ses = (uintptr_t)&m_ses;
		sha1_hash h = hasher((char*)&self, sizeof(self))
			.update((char*)&m_storage, sizeof(m_storage))
			.update((char*)&ses, sizeof(ses))
			.final();
		unsigned char const* ptr = &h[0];
		return detail::read_uint32(ptr);
	}*/

	void torrent::set_piece_deadline(int piece, int t, int flags)
	{
		if (m_abort)
		{
			// failed
			//if (flags & torrent_handle::alert_when_available)
			//{
				//m_ses.m_alerts.post_alert(read_piece_alert(
					//get_handle(), piece, boost::shared_array<char>(), 0));
			//}
			return;
		}

		ptime deadline = time_now() + milliseconds(t);

		if (is_seed() || m_picker->have_piece(piece))
		{
			if (flags & torrent_handle::alert_when_available)
				read_piece(piece);
			return;
		}

		for (std::deque<time_critical_piece>::iterator i = m_time_critical_pieces.begin()
			, end(m_time_critical_pieces.end()); i != end; ++i)
		{
			if (i->piece != piece) continue;
			i->deadline = deadline;
			i->flags = flags;

			// resort i since deadline might have changed
			while (boost::next(i) != m_time_critical_pieces.end() && i->deadline > boost::next(i)->deadline)
			{
				std::iter_swap(i, boost::next(i));
				++i;
			}
			while (i != m_time_critical_pieces.begin() && i->deadline < boost::prior(i)->deadline)
			{
				std::iter_swap(i, boost::prior(i));
				--i;
			}
			// just in case this piece had priority 0
			if (m_picker->piece_priority(piece) == 0)
				m_picker->set_piece_priority(piece, 1);
			return;
		}

		time_critical_piece p;
		p.first_requested = min_time();
		p.last_requested = min_time();
		p.flags = flags;
		p.deadline = deadline;
		p.peers = 0;
		p.piece = piece;
		std::deque<time_critical_piece>::iterator i = std::upper_bound(m_time_critical_pieces.begin()
			, m_time_critical_pieces.end(), p);
		m_time_critical_pieces.insert(i, p);

		// just in case this piece had priority 0
		if (m_picker->piece_priority(piece) == 0)
			m_picker->set_piece_priority(piece, 1);

		piece_picker::downloading_piece pi;
		m_picker->piece_info(piece, pi);
		if (pi.requested == 0) return;
		// this means we have outstanding requests (or queued
		// up requests that haven't been sent yet). Promote them
		// to deadline pieces immediately
		std::vector<void*> downloaders;
		m_picker->get_downloaders(downloaders, piece);

		int block = 0;
		for (std::vector<void*>::iterator i = downloaders.begin()
			, end(downloaders.end()); i != end; ++i, ++block)
		{
			policy::peer* p = (policy::peer*)*i;
			if (p == 0 || p->connection == 0) continue;
			p->connection->make_time_critical(piece_block(piece, block));
		}
	}

	void torrent::reset_piece_deadline(int piece)
	{
		remove_time_critical_piece(piece);
	}

	void torrent::remove_time_critical_piece(int piece, bool finished)
	{
		for (std::deque<time_critical_piece>::iterator i = m_time_critical_pieces.begin()
			, end(m_time_critical_pieces.end()); i != end; ++i)
		{
			if (i->piece != piece) continue;
			if (finished)
			{
				if (i->flags & torrent_handle::alert_when_available)
				{
					read_piece(i->piece);
				}

				// if first_requested is min_time(), it wasn't requested as a critical piece
				// and we shouldn't adjust any average download times
				if (i->first_requested != min_time())
				{
					// update the average download time and average
					// download time deviation
					int dl_time = total_milliseconds(time_now() - i->first_requested);
   
					if (m_average_piece_time == 0)
					{
						m_average_piece_time = dl_time;
					}
					else
					{
						int diff = abs(int(dl_time - m_average_piece_time));
						if (m_piece_time_deviation == 0) m_piece_time_deviation = diff;
						else m_piece_time_deviation = (m_piece_time_deviation * 6 + diff * 4) / 10;
   
						m_average_piece_time = (m_average_piece_time * 6 + dl_time * 4) / 10;
					}
				}
			}
			//else if (i->flags & torrent_handle::alert_when_available)
			//{
				// post an empty read_piece_alert to indicate it failed
				//m_ses.m_alerts.post_alert(read_piece_alert(
					//get_handle(), piece, boost::shared_array<char>(), 0));
			//}
			m_time_critical_pieces.erase(i);
			return;
		}
	}

	// remove time critical pieces where priority is 0
	void torrent::remove_time_critical_pieces(std::vector<int> const& priority)
	{
		for (std::deque<time_critical_piece>::iterator i = m_time_critical_pieces.begin();
			i != m_time_critical_pieces.end();)
		{
			if (priority[i->piece] == 0)
			{
				//if (i->flags & torrent_handle::alert_when_available)
				//{
					// post an empty read_piece_alert to indicate it failed
					//m_ses.m_alerts.post_alert(read_piece_alert(
						//get_handle(), i->piece, boost::shared_array<char>(), 0));
				//}
				i = m_time_critical_pieces.erase(i);
				continue;
			}
			++i;
		}
	}

	void torrent::piece_availability(std::vector<int>& avail) const
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(valid_metadata());
		if (is_seed())
		{
			avail.clear();
			return;
		}

		m_picker->get_availability(avail);
	}

	void torrent::set_piece_priority(int index, int priority)
	{
//		INVARIANT_CHECK;

		TORRENT_ASSERT(valid_metadata());
		if (is_seed()) return;

		// this call is only valid on torrents with metadata
		TORRENT_ASSERT(m_picker.get());
		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < m_torrent_file->num_pieces());
		if (index < 0 || index >= m_torrent_file->num_pieces()) return;

		bool was_finished = is_finished();
		bool filter_updated = m_picker->set_piece_priority(index, priority);
		TORRENT_ASSERT(num_have() >= m_picker->num_have_filtered());
		if (filter_updated)
		{
			update_peer_interest(was_finished);
			if (priority == 0) remove_time_critical_piece(index);
		}

	}

	int torrent::piece_priority(int index) const
	{
//		INVARIANT_CHECK;

		TORRENT_ASSERT(valid_metadata());
		if (is_seed()) return 1;

		// this call is only valid on torrents with metadata
		TORRENT_ASSERT(m_picker.get());
		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < m_torrent_file->num_pieces());
		if (index < 0 || index >= m_torrent_file->num_pieces()) return 0;

		return m_picker->piece_priority(index);
	}

	void torrent::prioritize_pieces(std::vector<int> const& pieces)
	{
		INVARIANT_CHECK;

		// this call is only valid on torrents with metadata
		TORRENT_ASSERT(valid_metadata());
		if (is_seed()) return;

		TORRENT_ASSERT(m_picker.get());

		int index = 0;
		bool filter_updated = false;
		bool was_finished = is_finished();
		for (std::vector<int>::const_iterator i = pieces.begin()
			, end(pieces.end()); i != end; ++i, ++index)
		{
			TORRENT_ASSERT(*i >= 0);
			TORRENT_ASSERT(*i <= 7);
			filter_updated |= m_picker->set_piece_priority(index, *i);
			TORRENT_ASSERT(num_have() >= m_picker->num_have_filtered());
		}
		if (filter_updated)
		{
			// we need to save this new state
			m_need_save_resume_data = true;

			update_peer_interest(was_finished);
			remove_time_critical_pieces(pieces);
		}

		state_updated();
	}

	void torrent::piece_priorities(std::vector<int>* pieces) const
	{
		INVARIANT_CHECK;

		// this call is only valid on torrents with metadata
		TORRENT_ASSERT(valid_metadata());
		if (is_seed())
		{
			pieces->clear();
			pieces->resize(m_torrent_file->num_pieces(), 1);
			return;
		}

		TORRENT_ASSERT(m_picker.get());
		m_picker->piece_priorities(*pieces);
	}

	namespace
	{
		void set_if_greater(int& piece_prio, int file_prio)
		{
			if (file_prio > piece_prio) piece_prio = file_prio;
		}
	}

	void torrent::prioritize_files(std::vector<int> const& files)
	{
		INVARIANT_CHECK;

		// this call is only valid on torrents with metadata
		if (!valid_metadata() || is_seed()) return;

		// the bitmask need to have exactly one bit for every file
		// in the torrent
		TORRENT_ASSERT(int(files.size()) == m_torrent_file->num_files());
		
		if (m_torrent_file->num_pieces() == 0) return;

		uint32_t limit = files.size();
		if (valid_metadata() && limit > m_torrent_file->num_files())
			limit = m_torrent_file->num_files();

		if (m_file_priority.size() < limit)
			m_file_priority.resize(limit);

		std::copy(files.begin(), files.begin() + limit, m_file_priority.begin());

		if (valid_metadata() && m_torrent_file->num_files() > m_file_priority.size())
			m_file_priority.resize(m_torrent_file->num_files(), 1);

		update_piece_priorities();
	}

	void torrent::set_file_priority(int index, int prio)
	{
		INVARIANT_CHECK;

		// this call is only valid on torrents with metadata
		if (!valid_metadata() || is_seed()) return;

		if (index < 0 || index >= (int)m_torrent_file->num_files()) return;
		if (prio < 0) prio = 0;
		else if (prio > 7) prio = 7;
		if (m_file_priority.size() <= (uint)index)
		{
			if (prio == 1) return;
			m_file_priority.resize(m_torrent_file->num_files(), 1);
		}
		if (m_file_priority[index] == prio) return;
		m_file_priority[index] = prio;
		update_piece_priorities();
	}
	
	int torrent::file_priority(int index) const
	{
		// this call is only valid on torrents with metadata
		if (!valid_metadata()) return 1;

		if (index < 0 || index >= (int)m_torrent_file->num_files()) return 0;
		if (m_file_priority.size() <= (uint)index) return 1;
		return m_file_priority[index];
	}

	void torrent::file_priorities(std::vector<int>* files) const
	{
		INVARIANT_CHECK;
		if (!valid_metadata())
		{
			files->resize(m_file_priority.size());
			std::copy(m_file_priority.begin(), m_file_priority.end(), files->begin());
			return;
		}

		files->resize(m_torrent_file->num_files(), 1);
		TORRENT_ASSERT(m_file_priority.size() <= m_torrent_file->num_files());
		std::copy(m_file_priority.begin(), m_file_priority.end(), files->begin());
	}

	void torrent::update_piece_priorities()
	{
		INVARIANT_CHECK;

		if (m_torrent_file->num_pieces() == 0) return;

		size_type position = 0;
		int piece_length = m_torrent_file->piece_length();
		// initialize the piece priorities to 0, then only allow
		// setting higher priorities
		std::vector<int> pieces(m_torrent_file->num_pieces(), 0);
		uint index = 0;
		for (file_storage::iterator i = m_torrent_file->files().begin()
			, end(m_torrent_file->files().end()); i != end; ++i, ++index)
		{
			if (index >= m_torrent_file->num_files()) break;
			size_type start = position;
			size_type size = m_torrent_file->files().file_size(*i);
			if (size == 0) continue;
			position += size;
			if (m_file_priority[index] == 0) continue;

			// mark all pieces of the file with this file's priority
			// but only if the priority is higher than the pieces
			// already set (to avoid problems with overlapping pieces)
			int start_piece = int(start / piece_length);
			int last_piece = int((position - 1) / piece_length);
			TORRENT_ASSERT(last_piece < int(pieces.size()));
			// if one piece spans several files, we might
			// come here several times with the same start_piece, end_piece
			std::for_each(pieces.begin() + start_piece
				, pieces.begin() + last_piece + 1
				, boost::bind(&set_if_greater, _1, m_file_priority[index]));
		}
		prioritize_pieces(pieces);
	}

	// this is called when piece priorities have been updated
	// updates the interested flag in peers
	void torrent::update_peer_interest(bool was_finished)
	{
		for (peer_iterator i = begin(); i != end();)
		{
			peer_connection* p = *i;
			// update_interest may disconnect the peer and
			// invalidate the iterator
			++i;
			p->update_interest();
		}

		// the torrent just became finished
		if (is_finished() && !was_finished)
		{
			finished();
		}
		else if (!is_finished() && was_finished)
		{
			// if we used to be finished, but we aren't anymore
			// we may need to connect to peers again
			resume_download();
		}
	}

	void torrent::filter_piece(int index, bool filter)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(valid_metadata());
		if (is_seed()) return;

		// this call is only valid on torrents with metadata
		TORRENT_ASSERT(m_picker.get());
		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < m_torrent_file->num_pieces());

		if (index < 0 || index >= m_torrent_file->num_pieces()) return;

		bool was_finished = is_finished();
		m_picker->set_piece_priority(index, filter ? 1 : 0);
		update_peer_interest(was_finished);
	}

	void torrent::filter_pieces(std::vector<bool> const& bitmask)
	{
		INVARIANT_CHECK;

		// this call is only valid on torrents with metadata
		TORRENT_ASSERT(valid_metadata());
		if (is_seed()) return;

		TORRENT_ASSERT(m_picker.get());

		bool was_finished = is_finished();
		int index = 0;
		for (std::vector<bool>::const_iterator i = bitmask.begin()
			, end(bitmask.end()); i != end; ++i, ++index)
		{
			if ((m_picker->piece_priority(index) == 0) == *i) continue;
			if (*i)
				m_picker->set_piece_priority(index, 0);
			else
				m_picker->set_piece_priority(index, 1);
		}
		update_peer_interest(was_finished);
	}

	bool torrent::is_piece_filtered(int index) const
	{
		// this call is only valid on torrents with metadata
		TORRENT_ASSERT(valid_metadata());
		if (is_seed()) return false;
		
		TORRENT_ASSERT(m_picker.get());
		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < m_torrent_file->num_pieces());

		if (index < 0 || index >= m_torrent_file->num_pieces()) return true;

		return m_picker->piece_priority(index) == 0;
	}

	void torrent::filtered_pieces(std::vector<bool>& bitmask) const
	{
		INVARIANT_CHECK;

		// this call is only valid on torrents with metadata
		TORRENT_ASSERT(valid_metadata());
		if (is_seed())
		{
			bitmask.clear();
			bitmask.resize(m_torrent_file->num_pieces(), false);
			return;
		}

		TORRENT_ASSERT(m_picker.get());
		m_picker->filtered_pieces(bitmask);
	}

	void torrent::filter_files(std::vector<bool> const& bitmask)
	{
		INVARIANT_CHECK;

		// this call is only valid on torrents with metadata
		if (!valid_metadata() || is_seed()) return;

		// the bitmask need to have exactly one bit for every file
		// in the torrent
		TORRENT_ASSERT(bitmask.size() == m_torrent_file->num_files());

		if (bitmask.size() != m_torrent_file->num_files()) return;
		
		size_type position = 0;

		if (m_torrent_file->num_pieces())
		{
			int piece_length = m_torrent_file->piece_length();
			// mark all pieces as filtered, then clear the bits for files
			// that should be downloaded
			std::vector<bool> piece_filter(m_torrent_file->num_pieces(), true);
			for (int i = 0; i < (int)bitmask.size(); ++i)
			{
				size_type start = position;
				position += m_torrent_file->files().at(i).size;
				// is the file selected for download?
				if (!bitmask[i])
				{           
					// mark all pieces of the file as downloadable
					int start_piece = int(start / piece_length);
					int last_piece = int(position / piece_length);
					// if one piece spans several files, we might
					// come here several times with the same start_piece, end_piece
					std::fill(piece_filter.begin() + start_piece, piece_filter.begin()
						+ last_piece + 1, false);
				}
			}
			filter_pieces(piece_filter);
		}
	}

	void torrent::replace_trackers(std::vector<announce_entry> const& urls)
	{
		m_trackers.clear();
		std::remove_copy_if(urls.begin(), urls.end(), back_inserter(m_trackers)
			, boost::bind(&std::string::empty, boost::bind(&announce_entry::url, _1)));

		m_last_working_tracker = -1;
		for (std::vector<announce_entry>::iterator i = m_trackers.begin()
			, end(m_trackers.end()); i != end; ++i)
			if (i->source == 0) i->source = announce_entry::source_client;

		if (settings().prefer_udp_trackers)
			prioritize_udp_trackers();

		if (!m_trackers.empty()) announce_with_tracker();

		m_need_save_resume_data = true;
	}

	void torrent::prioritize_udp_trackers()
	{
		// look for udp-trackers
		for (std::vector<announce_entry>::iterator i = m_trackers.begin()
			, end(m_trackers.end()); i != end; ++i)
		{
			if (i->url.substr(0, 6) != "udp://") continue;
			// now, look for trackers with the same hostname
			// that is has higher priority than this one
			// if we find one, swap with the udp-tracker
			error_code ec;
			std::string udp_hostname;
			using boost::tuples::ignore;
			boost::tie(ignore, ignore, udp_hostname, ignore, ignore)
				= parse_url_components(i->url, ec);
			for (std::vector<announce_entry>::iterator j = m_trackers.begin();
				j != i; ++j)
			{
				std::string hostname;
				boost::tie(ignore, ignore, hostname, ignore, ignore)
					= parse_url_components(j->url, ec);
				if (hostname != udp_hostname) continue;
				if (j->url.substr(0, 6) == "udp://") continue;
				using std::swap;
				using std::iter_swap;
				swap(i->tier, j->tier);
				iter_swap(i, j);
				break;
			}
		}
	}

	void torrent::add_tracker(announce_entry const& url)
	{
		std::vector<announce_entry>::iterator k = std::find_if(m_trackers.begin()
			, m_trackers.end(), boost::bind(&announce_entry::url, _1) == url.url);
		if (k != m_trackers.end()) 
		{
			k->source |= url.source;
			return;
		}
		k = std::upper_bound(m_trackers.begin(), m_trackers.end(), url
			, boost::bind(&announce_entry::tier, _1) < boost::bind(&announce_entry::tier, _2));
		if (k - m_trackers.begin() < m_last_working_tracker) ++m_last_working_tracker;
		k = m_trackers.insert(k, url);
		if (k->source == 0) k->source = announce_entry::source_client;
		if (!m_trackers.empty()) announce_with_tracker();
	}

	bool torrent::choke_peer(peer_connection& c)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(!c.is_choked());
		TORRENT_ASSERT(!c.ignore_unchoke_slots());
		TORRENT_ASSERT(m_num_uploads > 0);
		if (!c.send_choke()) return false;
		--m_num_uploads;
		state_updated();
		return true;
	}
	
	bool torrent::unchoke_peer(peer_connection& c, bool optimistic)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(!m_graceful_pause_mode);
		TORRENT_ASSERT(c.is_choked());
		TORRENT_ASSERT(!c.ignore_unchoke_slots());
		// when we're unchoking the optimistic slots, we might
		// exceed the limit temporarily while we're iterating
		// over the peers
		if (m_num_uploads >= m_max_uploads && !optimistic) return false;
		if (!c.send_unchoke()) return false;
		++m_num_uploads;
		state_updated();
		return true;
	}

	void torrent::cancel_block(piece_block block)
	{
		INVARIANT_CHECK;

		for (peer_iterator i = m_connections.begin()
			, end(m_connections.end()); i != end; ++i)
		{
			(*i)->cancel_request(block);
		}
	}

	void torrent::remove_peer(peer_connection* p)
	{
//		INVARIANT_CHECK;

		TORRENT_ASSERT(p != 0);
		TORRENT_ASSERT(m_ses.is_network_thread());

		peer_iterator i = m_connections.find(p);
		if (i == m_connections.end())
		{
			TORRENT_ASSERT(false);
			return;
		}

		if (ready_for_connections())
		{
			TORRENT_ASSERT(p->associated_torrent().lock().get() == this);

			if (p->is_seed())
			{
				if (m_picker.get())
				{
					m_picker->dec_refcount_all();
				}
			}
			else
			{
				if (m_picker.get())
				{
					bitfield const& pieces = p->get_bitfield();
					TORRENT_ASSERT(pieces.count() <= int(pieces.size()));
					m_picker->dec_refcount(pieces);
				}
			}
		}

		if (!p->is_choked() && !p->ignore_unchoke_slots())
		{
			--m_num_uploads;
			m_ses.m_unchoke_time_scaler = 0;
		}

		policy::peer* pp = p->peer_info_struct();
		if (pp)
		{
			if (pp->optimistically_unchoked)
				m_ses.m_optimistic_unchoke_time_scaler = 0;

			// if the share ratio is 0 (infinite), the
			// m_available_free_upload isn't used,
			// because it isn't necessary.
			if (ratio() != 0.f)
			{
				TORRENT_ASSERT(p->associated_torrent().lock().get() == this);
				TORRENT_ASSERT(p->share_diff() < (std::numeric_limits<size_type>::max)());
				add_free_upload(p->share_diff());
			}
			TORRENT_ASSERT(pp->prev_amount_upload == 0);
			TORRENT_ASSERT(pp->prev_amount_download == 0);
			pp->prev_amount_download += p->statistics().total_payload_download() >> 10;
			pp->prev_amount_upload += p->statistics().total_payload_upload() >> 10;
		}

		m_policy.connection_closed(*p, m_ses.session_time());
		p->set_peer_info(0);
		TORRENT_ASSERT(i != m_connections.end());
		m_connections.erase(i);
	}

    // TODO: 禁用磁盘文件
	/*void torrent::read_resume_data(lazy_entry const& rd)
	{
		m_total_uploaded = rd.dict_find_int_value("total_uploaded");
		m_total_downloaded = rd.dict_find_int_value("total_downloaded");
		m_active_time = rd.dict_find_int_value("active_time");
		m_finished_time = rd.dict_find_int_value("finished_time");
		m_seeding_time = rd.dict_find_int_value("seeding_time");
		m_last_seen_complete = rd.dict_find_int_value("last_seen_complete");
		m_complete = rd.dict_find_int_value("num_seeds", 0xffffff);
		m_incomplete = rd.dict_find_int_value("num_incomplete", 0xffffff);
		m_downloaders = rd.dict_find_int_value("num_downloaders", 0xffffff);
		set_upload_limit(rd.dict_find_int_value("upload_rate_limit", -1));
		set_download_limit(rd.dict_find_int_value("download_rate_limit", -1));
		set_max_connections(rd.dict_find_int_value("max_connections", -1));
		set_max_uploads(rd.dict_find_int_value("max_uploads", -1));
		m_seed_mode = rd.dict_find_int_value("seed_mode", 0) && m_torrent_file->is_valid();
		if (m_seed_mode) m_verified.resize(m_torrent_file->num_pieces(), false);
		super_seeding(rd.dict_find_int_value("super_seeding", 0));

		m_last_scrape = rd.dict_find_int_value("last_scrape", 0);
		m_last_download = rd.dict_find_int_value("last_download", 0);
		m_last_upload = rd.dict_find_int_value("last_upload", 0);

		//m_url = rd.dict_find_string_value("url");
		//m_uuid = rd.dict_find_string_value("uuid");
		//m_source_feed_url = rd.dict_find_string_value("feed");

		if (!m_uuid.empty() || !m_url.empty())
		{
			boost::shared_ptr<torrent> me(shared_from_this());

			// insert this torrent in the uuid index
			m_ses.m_uuids.insert(std::make_pair(m_uuid.empty()
				? m_url : m_uuid, me));
        }

		// TODO: make this more generic to not just work if files have been
		// renamed, but also if they have been merged into a single file for instance
		// maybe use the same format as .torrent files and reuse some code from torrent_info
		// The mapped_files needs to be read both in the network thread
		// and in the disk thread, since they both have their own mapped files structures
		// which are kept in sync
		lazy_entry const* mapped_files = rd.dict_find_list("mapped_files");
		if (mapped_files && mapped_files->list_size() == m_torrent_file->num_files())
		{
			for (uint32_t i = 0; i < m_torrent_file->num_files(); ++i)
			{
				std::string new_filename = mapped_files->list_string_value_at(i);
				if (new_filename.empty()) continue;
				m_torrent_file->rename_file(i, new_filename);
			}
		}
		
		m_added_time = rd.dict_find_int_value("added_time", m_added_time);
		m_completed_time = rd.dict_find_int_value("completed_time", m_completed_time);
		if (m_completed_time != 0 && m_completed_time < m_added_time)
			m_completed_time = m_added_time;

		lazy_entry const* file_priority = rd.dict_find_list("file_priority");
		if (file_priority && file_priority->list_size()
			== m_torrent_file->num_files())
		{
			for (uint32_t i = 0; i < file_priority->list_size(); ++i)
				m_file_priority[i] = file_priority->list_int_value_at(i, 1);
			update_piece_priorities();
		}

		lazy_entry const* piece_priority = rd.dict_find_string("piece_priority");
		if (piece_priority && piece_priority->string_length()
			== m_torrent_file->num_pieces())
		{
			char const* p = piece_priority->string_ptr();
			for (int i = 0; i < piece_priority->string_length(); ++i)
				m_picker->set_piece_priority(i, p[i]);
			m_policy.recalculate_connect_candidates();
		}

		if (!m_override_resume_data)
		{
			int auto_managed_ = rd.dict_find_int_value("auto_managed", -1);
			if (auto_managed_ != -1) m_auto_managed = auto_managed_;
		}

		int sequential_ = rd.dict_find_int_value("sequential_download", -1);
		if (sequential_ != -1) set_sequential_download(sequential_);

		if (!m_override_resume_data)
		{
			int paused_ = rd.dict_find_int_value("paused", -1);
			if (paused_ != -1)
			{
				m_allow_peers = !paused_;
				m_announce_to_dht = !paused_;
				m_announce_to_trackers = !paused_;
			}
			int dht_ = rd.dict_find_int_value("announce_to_dht", -1);
			if (dht_ != -1) m_announce_to_dht = dht_;
			int lsd_ = rd.dict_find_int_value("announce_to_lsd", -1);
			int track_ = rd.dict_find_int_value("announce_to_trackers", -1);
			if (track_ != -1) m_announce_to_trackers = track_;
		}

		lazy_entry const* trackers = rd.dict_find_list("trackers");
		if (trackers)
		{
			if (!m_merge_resume_trackers) m_trackers.clear();
			int tier = 0;
			for (uint32_t i = 0; i < trackers->list_size(); ++i)
			{
				lazy_entry const* tier_list = trackers->list_at(i);
				if (tier_list == 0 || tier_list->type() != lazy_entry::list_t)
					continue;
				for (uint32_t j = 0; j < tier_list->list_size(); ++j)
				{
					announce_entry e(tier_list->list_string_value_at(j));
					if (std::find_if(m_trackers.begin(), m_trackers.end()
						, boost::bind(&announce_entry::url, _1) == e.url) != m_trackers.end())
						continue;
					e.tier = tier;
					e.fail_limit = 0;
					m_trackers.push_back(e);
				}
				++tier;
			}
			std::sort(m_trackers.begin(), m_trackers.end(), boost::bind(&announce_entry::tier, _1)
				< boost::bind(&announce_entry::tier, _2));

			if (settings().prefer_udp_trackers)
				prioritize_udp_trackers();
		}

		if (m_torrent_file->is_merkle_torrent())
		{
			lazy_entry const* mt = rd.dict_find_string("merkle tree");
			if (mt)
			{
				std::vector<sha1_hash> tree;
				tree.resize(m_torrent_file->merkle_tree().size());
				std::memcpy(&tree[0], mt->string_ptr()
					, (std::min)(mt->string_length(), int(tree.size()) * 20));
				if (mt->string_length() < int(tree.size()) * 20)
					std::memset(&tree[0] + mt->string_length() / 20, 0
						, tree.size() - mt->string_length() / 20);
				m_torrent_file->set_merkle_tree(tree);
			}
			else
			{
				// TODO: if this is a merkle torrent and we can't
				// restore the tree, we need to wipe all the
				// bits in the have array, but not necessarily
				// we might want to do a full check to see if we have
				// all the pieces
				TORRENT_ASSERT(false);
			}
		}
	}
	
	void torrent::write_resume_data(entry& ret) const
	{
		using namespace libtorrent::detail; // for write_*_endpoint()
		ret["file-format"] = "libtorrent resume file";
		ret["file-version"] = 1;
		ret["libtorrent-version"] = LIBTORRENT_VERSION;

		ret["total_uploaded"] = m_total_uploaded;
		ret["total_downloaded"] = m_total_downloaded;

		ret["active_time"] = m_active_time;
		ret["finished_time"] = m_finished_time;
		ret["seeding_time"] = m_seeding_time;
		ret["last_seen_complete"] = m_last_seen_complete;

		ret["num_seeds"] = m_complete;
		ret["num_incomplete"] = m_incomplete;
		ret["num_downloaders"] = m_downloaders;

		ret["sequential_download"] = m_sequential_download;

		ret["seed_mode"] = m_seed_mode;
		ret["super_seeding"] = m_super_seeding;

		ret["added_time"] = m_added_time;
		ret["completed_time"] = m_completed_time;

		ret["last_scrape"] = m_last_scrape;
		ret["last_download"] = m_last_download;
		ret["last_upload"] = m_last_upload;

		//if (!m_url.empty()) ret["url"] = m_url;
		//if (!m_uuid.empty()) ret["uuid"] = m_uuid;
		//if (!m_source_feed_url.empty()) ret["feed"] = m_source_feed_url;
		
		const sha1_hash& info_hash = torrent_file().info_hash();
		ret["info-hash"] = std::string((char*)info_hash.begin(), (char*)info_hash.end());

		if (valid_metadata())
		{
			if (m_magnet_link || (m_save_resume_flags & torrent_handle::save_info_dict))
				ret["info"] = bdecode(&torrent_file().metadata()[0]
					, &torrent_file().metadata()[0] + torrent_file().metadata_size());
		}

		// blocks per piece
		int num_blocks_per_piece =
			static_cast<int>(torrent_file().piece_length()) / block_size();
		ret["blocks per piece"] = num_blocks_per_piece;

		if (m_torrent_file->is_merkle_torrent())
		{
			// we need to save the whole merkle hash tree
			// in order to resume
			std::string& tree_str = ret["merkle tree"].string();
			std::vector<sha1_hash> const& tree = m_torrent_file->merkle_tree();
			tree_str.resize(tree.size() * 20);
			std::memcpy(&tree_str[0], &tree[0], tree.size() * 20);
		}

		// if this torrent is a seed, we won't have a piece picker
		// and there will be no half-finished pieces.
		if (!is_seed())
		{
			const std::vector<piece_picker::downloading_piece>& q
				= m_picker->get_download_queue();

			// unfinished pieces
			ret["unfinished"] = entry::list_type();
			entry::list_type& up = ret["unfinished"].list();

			// info for each unfinished piece
			for (std::vector<piece_picker::downloading_piece>::const_iterator i
				= q.begin(); i != q.end(); ++i)
			{
				if (i->finished == 0) continue;

				entry piece_struct(entry::dictionary_t);

				// the unfinished piece's index
				piece_struct["piece"] = i->index;

				std::string bitmask;
				const int num_bitmask_bytes
					= (std::max)(num_blocks_per_piece / 8, 1);

				for (int j = 0; j < num_bitmask_bytes; ++j)
				{
					unsigned char v = 0;
					int bits = (std::min)(num_blocks_per_piece - j*8, 8);
					for (int k = 0; k < bits; ++k)
						v |= (i->info[j*8+k].state == piece_picker::block_info::state_finished)
						? (1 << k) : 0;
					bitmask.append(1, v);
					TORRENT_ASSERT(bits == 8 || j == num_bitmask_bytes - 1);
				}
				piece_struct["bitmask"] = bitmask;
				// push the struct onto the unfinished-piece list
				up.push_back(piece_struct);
			}
		}

		// save trackers
		if (!m_trackers.empty())
		{
			entry::list_type& tr_list = ret["trackers"].list();
			tr_list.push_back(entry::list_type());
			int tier = 0;
			for (std::vector<announce_entry>::const_iterator i = m_trackers.begin()
				, end(m_trackers.end()); i != end; ++i)
			{
				// don't save trackers we can't trust
				// TODO: save the send_stats state instead
				if (i->send_stats == false) continue;
				if (i->tier == tier)
				{
					tr_list.back().list().push_back(i->url);
				}
				else
				{
					tr_list.push_back(entry::list_t);
					tr_list.back().list().push_back(i->url);
					tier = i->tier;
				}
			}
		}

		// write have bitmask
		// the pieces string has one byte per piece. Each
		// byte is a bitmask representing different properties
		// for the piece
		// bit 0: set if we have the piece
		// bit 1: set if we have verified the piece (in seed mode)
		entry::string_type& pieces = ret["pieces"].string();
		pieces.resize(m_torrent_file->num_pieces());
		if (is_seed())
		{
			std::memset(&pieces[0], 1, pieces.size());
		}
		else
		{
			for (int i = 0, end(pieces.size()); i < end; ++i)
				pieces[i] = m_picker->have_piece(i) ? 1 : 0;
		}

		if (m_seed_mode)
		{
			TORRENT_ASSERT(m_verified.size() == pieces.size());
			for (int i = 0, end(pieces.size()); i < end; ++i)
				pieces[i] |= m_verified[i] ? 2 : 0;
		}

		// write renamed files
		// TODO: make this more generic to not just work if files have been
		// renamed, but also if they have been merged into a single file for instance
		if (&m_torrent_file->files() != &m_torrent_file->orig_files()
			&& m_torrent_file->files().num_files() == m_torrent_file->orig_files().num_files())
		{
			entry::list_type& fl = ret["mapped_files"].list();
			for (torrent_info::file_iterator i = m_torrent_file->begin_files()
				, end(m_torrent_file->end_files()); i != end; ++i)
			{
				fl.push_back(m_torrent_file->files().file_path(*i));
			}
		}

		// write local peers

		std::back_insert_iterator<entry::string_type> peers(ret["peers"].string());
		std::back_insert_iterator<entry::string_type> banned_peers(ret["banned_peers"].string());

		// failcount is a 5 bit value
		int max_failcount = (std::min)(settings().max_failcount, 31);

		int num_saved_peers = 0;

		for (policy::const_iterator i = m_policy.begin_peer()
			, end(m_policy.end_peer()); i != end; ++i)
		{
			error_code ec;
			policy::peer const* p = *i;
			address addr = p->address();
			if (p->banned)
			{
				{
					write_address(addr, banned_peers);
					write_uint16(p->port, banned_peers);
				}
				continue;
			}

			// we cannot save remote connection
			// since we don't know their listen port
			// unless they gave us their listen port
			// through the extension handshake
			// so, if the peer is not connectable (i.e. we
			// don't know its listen port) or if it has
			// been banned, don't save it.
			if (!p->connectable) continue;

			// don't save peers that don't work
			if (int(p->failcount) >= max_failcount) continue;

			// the more peers we've saved, the more picky we get
			// about which ones are worth saving
			if (num_saved_peers > 10
				&& int (p->failcount) > 0
				&& int(p->failcount) > (40 - (num_saved_peers - 10)) * max_failcount / 40)
				continue;

			// if we have 40 peers, don't save any peers whom
			// we've only heard from through the resume data
			if (num_saved_peers > 40 && p->source == peer_info::resume_data)
				continue;

			{
				write_address(addr, peers);
				write_uint16(p->port, peers);
			}
			++num_saved_peers;
		}

		ret["upload_rate_limit"] = upload_limit();
		ret["download_rate_limit"] = download_limit();
		ret["max_connections"] = max_connections();
		ret["max_uploads"] = max_uploads();
		ret["paused"] = is_torrent_paused();
		ret["announce_to_dht"] = m_announce_to_dht;
		ret["announce_to_trackers"] = m_announce_to_trackers;
		ret["auto_managed"] = m_auto_managed;

		// write piece priorities
		entry::string_type& piece_priority = ret["piece_priority"].string();
		piece_priority.resize(m_torrent_file->num_pieces());
		if (is_seed())
		{
			std::memset(&piece_priority[0], 1, pieces.size());
		}
		else
		{
			for (int i = 0, end(piece_priority.size()); i < end; ++i)
				piece_priority[i] = m_picker->piece_priority(i);
		}

		// write file priorities
		entry::list_type& file_priority = ret["file_priority"].list();
		file_priority.clear();
		for (int i = 0, end(m_file_priority.size()); i < end; ++i)
			file_priority.push_back(m_file_priority[i]);
	}*/

    // TODO: 禁用asio
	/*void torrent::get_full_peer_list(std::vector<peer_list_entry>& v) const
	{
		v.clear();
		v.reserve(m_policy.num_peers());
		for (policy::const_iterator i = m_policy.begin_peer();
			i != m_policy.end_peer(); ++i)
		{
			peer_list_entry e;
			e.ip = (*i)->ip();
			e.flags = (*i)->banned ? peer_list_entry::banned : 0;
			e.failcount = (*i)->failcount;
			e.source = (*i)->source;
			v.push_back(e);
		}
	}*/

	/*void torrent::get_peer_info(std::vector<peer_info>& v)
	{
		v.clear();
		for (peer_iterator i = begin();
			i != end(); ++i)
		{
			peer_connection* peer = *i;
			TORRENT_ASSERT(peer->m_in_use == 1337);

			// incoming peers that haven't finished the handshake should
			// not be included in this list
			if (peer->associated_torrent().expired()) continue;

			v.push_back(peer_info());
			peer_info& p = v.back();
			
			peer->get_peer_info(p);
		}
	}*/

	void torrent::get_download_queue(std::vector<partial_piece_info>* queue)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		queue->clear();
		std::vector<block_info>& blk = m_ses.m_block_info_storage;
		blk.clear();

		if (!valid_metadata() || is_seed()) return;
		piece_picker const& p = picker();
		std::vector<piece_picker::downloading_piece> const& q
			= p.get_download_queue();

		const int blocks_per_piece = m_picker->blocks_in_piece(0);
		blk.resize(q.size() * blocks_per_piece);
		// for some weird reason valgrind claims these are uninitialized
		// unless it's zeroed out here (block_info has a construct that's
		// supposed to initialize it)
		if (!blk.empty())
			memset(&blk[0], 0, sizeof(blk[0]) * blk.size());

		int counter = 0;
		for (std::vector<piece_picker::downloading_piece>::const_iterator i
			= q.begin(); i != q.end(); ++i, ++counter)
		{
			partial_piece_info pi;
			pi.piece_state = (partial_piece_info::state_t)i->state;
			pi.blocks_in_piece = p.blocks_in_piece(i->index);
			pi.finished = (int)i->finished;
			pi.writing = (int)i->writing;
			pi.requested = (int)i->requested;
			TORRENT_ASSERT(counter * blocks_per_piece + pi.blocks_in_piece <= int(blk.size()));
			pi.blocks = &blk[counter * blocks_per_piece];
			int piece_size = int(torrent_file().piece_size(i->index));
			for (int j = 0; j < pi.blocks_in_piece; ++j)
			{
				block_info& bi = pi.blocks[j];
				bi.state = i->info[j].state;
				bi.block_size = j < pi.blocks_in_piece - 1 ? block_size()
					: piece_size - (j * block_size());
				bool complete = bi.state == block_info::writing
					|| bi.state == block_info::finished;
				if (i->info[j].peer == 0)
				{
                    // TODO: 禁用ASIO
					bi.set_peer(ns3::Ipv4EndPoint());
					bi.bytes_progress = complete ? bi.block_size : 0;
				}
				else
				{
					policy::peer* p = static_cast<policy::peer*>(i->info[j].peer);
					if (p->connection)
					{
						bi.set_peer(p->connection->remote());
						if (bi.state == block_info::requested)
						{
							boost::optional<piece_block_progress> pbp
								= p->connection->downloading_piece_progress();
							if (pbp && pbp->piece_index == i->index && pbp->block_index == j)
							{
								bi.bytes_progress = pbp->bytes_downloaded;
								TORRENT_ASSERT(bi.bytes_progress <= bi.block_size);
							}
							else
							{
								bi.bytes_progress = 0;
							}
						}
						else
						{
							bi.bytes_progress = complete ? bi.block_size : 0;
						}
					}
					else
					{
						bi.set_peer(p->ip());
						bi.bytes_progress = complete ? bi.block_size : 0;
					}
				}

				pi.blocks[j].num_peers = i->info[j].num_peers;
			}
			pi.piece_index = i->index;
			queue->push_back(pi);
		}
	
	}

    void torrent::sendData()
    {
        NS_LOG_IP_FUNCTION(ip,this);
    }

   // void torrent::ConnectionSucceeded(ns3::Ptr<ns3::Socket> socket)
   // {
   //     NS_LOG_IP_FUNCTION(ip,this);
   // }

   // void torrent::ConnectionFailed(ns3::Ptr<ns3::Socket> socket)
   // {
   //     NS_LOG_IP_FUNCTION(ip,this);
   // }
    void torrent::onSockReceive(ns3::Ptr<ns3::Socket> sock)
    {
        NS_LOG_IP_FUNCTION(ip, this);
        ccmap.find(sock)->second->on_connection_complete(sock);
    }
	
	bool torrent::connect_to_peer(policy::peer* peerinfo, bool ignore_limit)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(peerinfo);
		TORRENT_ASSERT(peerinfo->connection == 0);

		peerinfo->last_connected = m_ses.session_time();
#ifdef TORRENT_DEBUG
		if (!settings().allow_multiple_connections_per_ip)
		{
			// this asserts that we don't have duplicates in the policy's peer list
			peer_iterator i_ = std::find_if(m_connections.begin(), m_connections.end()
				, boost::bind(&peer_connection::remote, _1) == peerinfo->ip());
			TORRENT_ASSERT(i_ == m_connections.end()
				|| (*i_)->type() != peer_connection::bittorrent_connection);
		}
#endif

		// extend connect timeout by this many seconds
		//int timeout_extend = 0;

		TORRENT_ASSERT(want_more_peers() || ignore_limit);
		TORRENT_ASSERT(m_ses.num_connections() < m_ses.settings().connections_limit || ignore_limit);

		ns3::Ipv4EndPoint a(peerinfo->ip());
		//TORRENT_ASSERT(!m_apply_ip_filter
		//	|| (m_ses.m_ip_filter.access(peerinfo->address()) & ip_filter::blocked) == 0);

        ns3::TypeId tid = ns3::TypeId::LookupByName ("ns3::TcpSocketFactory");
        ns3::Ptr<ns3::Socket> socket = ns3::Socket::CreateSocket (m_node, tid);
        socket->Bind();

      //  ns3::Ptr<ns3::Packet> p = ns3::Create<ns3::Packet> (120);
      //  int result = s->Send(p);
      //  NS_LOG_INFO("connect to ip "<< a.GetLocalAddress() << ", port " << a.GetLocalPort() << ", send data count "<< result);
       // NS_LOG_INFO("connect to ip "<< a.GetLocalAddress() << ", port " << a.GetLocalPort());// << ", send data count "<< result);
        //ns3::Simulator::Schedule (Seconds (0.0), &torrent::sendData, this);

		// don't make a TCP connection if it's disabled
		if (!m_ses.m_settings.enable_outgoing_tcp)
            return false;

//		m_ses.setup_socket_buffers(*s);

		boost::intrusive_ptr<peer_connection> c(new bt_peer_connection(
			m_ses, shared_from_this(), socket, a, peerinfo));

        socket->SetConnectCallback (
            MakeCallback (&torrent::onSockReceive, this),
            MakeNullCallback<void, ns3::Ptr<ns3::Socket> >());
        ccmap.insert(std::pair<ns3::Ptr<ns3::Socket>, boost::intrusive_ptr<peer_connection> >(socket, c));
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		c->m_in_constructor = false;
#endif

 		//c->add_stat(size_type(peerinfo->prev_amount_download) << 10
		//	, size_type(peerinfo->prev_amount_upload) << 10);
 		peerinfo->prev_amount_download = 0;
 		peerinfo->prev_amount_upload = 0;

		// add the newly connected peer to this torrent's peer list
		m_connections.insert(boost::get_pointer(c));
		m_policy.set_connection(peerinfo, c.get());

        c->on_connect(m_ticket_count);
		c->start();
        m_ticket_count++;
/*		TORRENT_TRY
		{
			m_ses.m_half_open.enqueue(
				boost::bind(&peer_connection::on_connect, c, _1)
				, boost::bind(&peer_connection::on_timeout, c)
				, seconds(timeout));
		}
		TORRENT_CATCH (std::exception&)
		{
			std::set<peer_connection*>::iterator i
				= m_connections.find(boost::get_pointer(c));
			if (i != m_connections.end()) m_connections.erase(i);
			c->disconnect(errors::no_error, 1);
			return false;
		}*/

		if (m_share_mode)
			recalc_share_mode();

		return peerinfo->connection;
	}

	bool torrent::set_metadata(char const* metadata_buf, int metadata_size)
	{
		INVARIANT_CHECK;

		if (m_torrent_file->is_valid()) return false;

		hasher h;
		h.update(metadata_buf, metadata_size);
		sha1_hash info_hash = h.final();

		if (info_hash != m_torrent_file->info_hash())
		{
			//if (alerts().should_post<metadata_failed_alert>())
			//{
				//alerts().post_alert(metadata_failed_alert(get_handle()));
			//}
			return false;
		}

		lazy_entry metadata;
		error_code ec;
		int ret = lazy_bdecode(metadata_buf, metadata_buf + metadata_size, metadata, ec);
		if (ret != 0 || !m_torrent_file->parse_info_section(metadata, ec, 0))
		{
			// this means the metadata is correct, since we
			// verified it against the info-hash, but we
			// failed to parse it. Pause the torrent
			//if (alerts().should_post<metadata_failed_alert>())
			//{
				// TODO: pass in ec along with the alert
				//alerts().post_alert(metadata_failed_alert(get_handle()));
			//}
			set_error(errors::invalid_swarm_metadata, "");
			return false;
		}

		// this makes the resume data "paused" and
		// "auto_managed" fields be ignored. If the paused
		// field is not ignored, the invariant check will fail
		// since we will be paused but without having disconnected
		// any of the peers.
		m_override_resume_data = true;

		// we have to initialize the torrent before we start
		// disconnecting redundant peers, otherwise we'll think
		// we're a seed, because we have all 0 pieces
		init();

		// disconnect redundant peers
		for (std::set<peer_connection*>::iterator i = m_connections.begin()
			, end(m_connections.end()); i != end;)
		{
			std::set<peer_connection*>::iterator p = i++;
			(*p)->disconnect_if_redundant();
		}

		m_need_save_resume_data = true;

		return true;
	}

	bool torrent::attach_peer(peer_connection* p)
	{
//		INVARIANT_CHECK;

		if (is_ssl_torrent())
		{
			// Don't accidentally allow seeding of SSL torrents, just
			// because libtorrent wasn't built with SSL support
			p->disconnect(errors::requires_ssl_connection);
			return false;
		}

		TORRENT_ASSERT(p != 0);
		TORRENT_ASSERT(!p->is_outgoing());

		m_has_incoming = true;

		if (m_apply_ip_filter)
			//&& m_ses.m_ip_filter.access(p->remote().GetIpv4()) & ip_filter::blocked)
		{
			p->disconnect(errors::banned_by_ip_filter);
			return false;
		}

		if ((m_state == torrent_status::queued_for_checking
			|| m_state == torrent_status::checking_files
			|| m_state == torrent_status::checking_resume_data)
			&& valid_metadata())
		{
			p->disconnect(errors::torrent_not_ready);
			return false;
		}
		
        // 将m_ses中的连接检测放在这里做
		if (m_connections.find(p) == m_connections.end())
		{
			p->disconnect(errors::peer_not_constructed);
			return false;
		}

		//if (m_ses.is_aborted())
		//{
		//	p->disconnect(errors::session_closing);
		//	return false;
		//}

		if (m_connections.size() >= m_max_connections)
		{
			// if more than 10% of the connections are outgoing
			// connection attempts that haven't completed yet,
			// disconnect one of them and let this incoming
			// connection through.
			if (m_num_connecting < m_max_connections / 10)
			{
				p->disconnect(errors::too_many_connections);
				return false;
			}

			// find one of the connecting peers and disconnect it
			// TODO: ideally, we would disconnect the oldest connection
			// i.e. the one that has waited the longest to connect.
			for (std::set<peer_connection*>::iterator i = m_connections.begin()
				, end(m_connections.end()); i != end; ++i)
			{
				peer_connection* peer = *i;
				if (!peer->is_connecting()) continue;
				peer->disconnect(errors::too_many_connections);
				break;
			}
		}

		TORRENT_TRY
		{
			if (!m_policy.new_connection(*p, m_ses.session_time()))
			{
#if defined TORRENT_LOGGING
				debug_log("CLOSING CONNECTION \"%s\" peer list full"
					, print_endpoint(p->remote()).c_str());
#endif
				p->disconnect(errors::too_many_connections);
				return false;
			}
		}
		TORRENT_CATCH (std::exception& e)
		{
			TORRENT_DECLARE_DUMMY(std::exception, e);
			(void)e;
#if defined TORRENT_LOGGING
			debug_log("CLOSING CONNECTION \"%s\" caught exception: %s"
				, print_endpoint(p->remote()).c_str(), e.what());
#endif
			p->disconnect(errors::no_error);
			return false;
		}
		TORRENT_ASSERT(m_connections.find(p) == m_connections.end());
		m_connections.insert(p);
#ifdef TORRENT_DEBUG
		error_code ec;
		TORRENT_ASSERT(p->remote() == p->get_socket()->remote_endpoint(ec) || ec);
#endif

#if defined TORRENT_DEBUG && !defined TORRENT_DISABLE_INVARIANT_CHECKS
		m_policy.check_invariant();
#endif

		if (m_share_mode)
			recalc_share_mode();

		return true;
	}

	bool torrent::want_more_peers() const
	{
		return m_connections.size() < m_max_connections
			//&& !is_paused()
			&& ((m_state != torrent_status::checking_files
			&& m_state != torrent_status::checking_resume_data
			&& m_state != torrent_status::queued_for_checking)
				|| !valid_metadata())
			&& m_policy.num_connect_candidates() > 0
			&& !m_abort
			&& (m_ses.settings().seeding_outgoing_connections
				|| (m_state != torrent_status::seeding
				&& m_state != torrent_status::finished));
	}

	void torrent::disconnect_all(error_code const& ec)
	{
// doesn't work with the !m_allow_peers -> m_num_peers == 0 condition
//		INVARIANT_CHECK;

		while (!m_connections.empty())
		{
			peer_connection* p = *m_connections.begin();
			TORRENT_ASSERT(p->associated_torrent().lock().get() == this);

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			p->peer_log("*** CLOSING CONNECTION \"%s\"", ec.message().c_str());
#endif
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			std::size_t size = m_connections.size();
#endif
			if (p->is_disconnecting())
				m_connections.erase(m_connections.begin());
			else
				p->disconnect(ec);
			TORRENT_ASSERT(m_connections.size() <= size);
		}
	}

	// this returns true if lhs is a better disconnect candidate than rhs
	bool compare_disconnect_peer(peer_connection const* lhs, peer_connection const* rhs)
	{
		// prefer to disconnect peers that are already disconnecting
		if (lhs->is_disconnecting() != rhs->is_disconnecting())
			return lhs->is_disconnecting();

		// prefer to disconnect peers we're not interested in
		if (lhs->is_interesting() != rhs->is_interesting())
			return rhs->is_interesting();

		// prefer to disconnect peers that are not seeds
		if (lhs->is_seed() != rhs->is_seed())
			return rhs->is_seed();

		// prefer to disconnect peers that are on parole
		if (lhs->on_parole() != rhs->on_parole())
			return lhs->on_parole();

		// prefer to disconnect peers that send data at a lower rate
		size_type lhs_transferred = lhs->statistics().total_payload_download();
		size_type rhs_transferred = rhs->statistics().total_payload_download();

		ptime now = time_now();
		size_type lhs_time_connected = total_seconds(now - lhs->connected_time());
		size_type rhs_time_connected = total_seconds(now - rhs->connected_time());

		lhs_transferred /= lhs_time_connected + 1;
		rhs_transferred /= (rhs_time_connected + 1);
		if (lhs_transferred != rhs_transferred)	
			return lhs_transferred < rhs_transferred;

		// prefer to disconnect peers that chokes us
		if (lhs->is_choked() != rhs->is_choked())
			return lhs->is_choked();

		return lhs->last_received() < rhs->last_received();
	}

	int torrent::disconnect_peers(int num, error_code const& ec)
	{
		INVARIANT_CHECK;

#ifdef TORRENT_DEBUG
		for (std::set<peer_connection*>::iterator i = m_connections.begin()
			, end(m_connections.end()); i != end; ++i)
		{
			// make sure this peer is not a dangling pointer
			TORRENT_ASSERT(m_ses.has_peer(*i));
		}
#endif
		int ret = 0;
		while (ret < num && !m_connections.empty())
		{
			std::set<peer_connection*>::iterator i = std::min_element(
				m_connections.begin(), m_connections.end(), compare_disconnect_peer);

			peer_connection* p = *i;
			++ret;
			TORRENT_ASSERT(p->associated_torrent().lock().get() == this);
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			int num_conns = m_connections.size();
#endif
			p->disconnect(ec);
			TORRENT_ASSERT(int(m_connections.size()) == num_conns - 1);
		}

		return ret;
	}

	int torrent::bandwidth_throttle(int channel) const
	{
		return m_bandwidth_channel[channel].throttle();
	}

	// called when torrent is finished (all interesting
	// pieces have been downloaded)
	void torrent::finished()
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(is_finished());
		TORRENT_ASSERT(m_state != torrent_status::finished && m_state != torrent_status::seeding);

		//if (alerts().should_post<torrent_finished_alert>())
		//{
			//alerts().post_alert(torrent_finished_alert(
				//get_handle()));
		//}

		set_state(torrent_status::finished);
		set_queue_position(-1);

		// we have to call completed() before we start
		// disconnecting peers, since there's an assert
		// to make sure we're cleared the piece picker
		if (is_seed()) completed();

		//send_upload_only();

		state_updated();

		m_completed_time = time(0);

		// disconnect all seeds
		if (settings().close_redundant_connections)
		{
			// TODO: should disconnect all peers that have the pieces we have
			// not just seeds
			std::vector<peer_connection*> seeds;
			for (peer_iterator i = m_connections.begin();
				i != m_connections.end(); ++i)
			{
				peer_connection* p = *i;
				TORRENT_ASSERT(p->associated_torrent().lock().get() == this);
				if (p->upload_only())
				{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
					p->peer_log("*** SEED, CLOSING CONNECTION");
#endif
					seeds.push_back(p);
				}
			}
			std::for_each(seeds.begin(), seeds.end()
				, boost::bind(&peer_connection::disconnect, _1, errors::torrent_finished, 0));
		}

		if (m_abort) return;

		m_policy.recalculate_connect_candidates();

		TORRENT_ASSERT(m_storage);
		// we need to keep the object alive during this operation
		//m_storage->async_release_files(
		//	boost::bind(&torrent::on_files_released, shared_from_this(), _1, _2));
		
		// this torrent just completed downloads, which means it will fall
		// under a different limit with the auto-manager. Make sure we
		// update auto-manage torrents in that case
		if (m_auto_managed)
			m_ses.m_auto_manage_time_scaler = 2;
	}

	// this is called when we were finished, but some files were
	// marked for downloading, and we are no longer finished	
	void torrent::resume_download()
	{
		INVARIANT_CHECK;
	
		TORRENT_ASSERT(!is_finished());
		set_state(torrent_status::downloading);
		set_queue_position((std::numeric_limits<int>::max)());
		m_policy.recalculate_connect_candidates();

		m_completed_time = 0;

		//send_upload_only();
	}

	// called when torrent is complete (all pieces downloaded)
	void torrent::completed()
	{
        NS_LOG_IP_FUNCTION(ip, this);
		m_picker.reset();

		set_state(torrent_status::seeding);
		if (!m_announcing) return;

		ptime now = time_now();
		for (std::vector<announce_entry>::iterator i = m_trackers.begin()
			, end(m_trackers.end()); i != end; ++i)
		{
			if (i->complete_sent) continue;
			i->next_announce = now;
			i->min_announce = now;
		}
		announce_with_tracker();
	}

	// this will move the tracker with the given index
	// to a prioritized position in the list (move it towards
	// the begining) and return the new index to the tracker.
	int torrent::prioritize_tracker(int index)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < int(m_trackers.size()));
		if (index >= (int)m_trackers.size()) return -1;

		while (index > 0 && m_trackers[index].tier == m_trackers[index-1].tier)
		{
			using std::swap;
			swap(m_trackers[index], m_trackers[index-1]);
			if (m_last_working_tracker == index) --m_last_working_tracker;
			else if (m_last_working_tracker == index - 1) ++m_last_working_tracker;
			--index;
		}
		return index;
	}

	int torrent::deprioritize_tracker(int index)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < int(m_trackers.size()));
		if (index >= (int)m_trackers.size()) return -1;

		while (index < int(m_trackers.size()) - 1 && m_trackers[index].tier == m_trackers[index + 1].tier)
		{
			using std::swap;
			swap(m_trackers[index], m_trackers[index + 1]);
			if (m_last_working_tracker == index) ++m_last_working_tracker;
			else if (m_last_working_tracker == index + 1) --m_last_working_tracker;
			++index;
		}
		return index;
	}

	std::string torrent::save_path() const
	{
		return m_save_path;
	}

	/*bool torrent::rename_file(int index, std::string const& name)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < m_torrent_file->num_files());

		if (!m_owning_storage.get()) return false;

		m_owning_storage->async_rename_file(index, name
			, boost::bind(&torrent::on_file_renamed, shared_from_this(), _1, _2));
		return true;
	}

	void torrent::move_storage(std::string const& save_path)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		INVARIANT_CHECK;

		if (m_abort)
		{
			if (alerts().should_post<storage_moved_failed_alert>())
				alerts().post_alert(storage_moved_failed_alert(get_handle(), boost::asio::error::operation_aborted));
			return;
		}

		// storage may be NULL during shutdown
		if (m_owning_storage.get())
		{
#if TORRENT_USE_UNC_PATHS
			std::string path = canonicalize_path(save_path);
#else
			std::string const& path = save_path;
#endif
			m_owning_storage->async_move_storage(path
				, boost::bind(&torrent::on_storage_moved, shared_from_this(), _1, _2));
		}
		else
		{
#if TORRENT_USE_UNC_PATHS
			m_save_path = canonicalize_path(save_path);
#else

			m_save_path = save_path;
#endif
			if (alerts().should_post<storage_moved_alert>())
			{
				alerts().post_alert(storage_moved_alert(get_handle(), m_save_path));
			}
		}
	}

	void torrent::on_storage_moved(int ret, disk_io_job const& j)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());

		if (ret == 0)
		{
			if (alerts().should_post<storage_moved_alert>())
			{
				alerts().post_alert(storage_moved_alert(get_handle(), j.str));
			}
			m_save_path = j.str;
		}
		else
		{
			if (alerts().should_post<storage_moved_failed_alert>())
			{
				alerts().post_alert(storage_moved_failed_alert(get_handle(), j.error));
			}
		}
	}*/

	/*piece_manager& torrent::filesystem()
	{
		TORRENT_ASSERT(m_owning_storage.get());
		TORRENT_ASSERT(m_storage);
		return *m_storage;
	}*/


	torrent_handle torrent::get_handle()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		return torrent_handle(shared_from_this());
	}

	session_settings const& torrent::settings() const
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		return m_ses.settings();
	}

#ifdef TORRENT_DEBUG
	void torrent::check_invariant() const
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		//if (is_paused()) TORRENT_ASSERT(num_peers() == 0 || m_graceful_pause_mode);

		//if (!should_check_files())
		//	TORRENT_ASSERT(m_state != torrent_status::checking_files);
		//else
			TORRENT_ASSERT(m_queued_for_checking);

		if (!m_ses.m_queued_for_checking.empty())
		{
			// if there are torrents waiting to be checked
			// assert that there's a torrent that is being
			// processed right now
			int found = 0;
			int found_active = 0;
			for (aux::session_impl::torrent_map::iterator i = m_ses.m_torrents.begin()
				, end(m_ses.m_torrents.end()); i != end; ++i)
				if (i->second->m_state == torrent_status::checking_files)
				{
					++found;
					//if (i->second->should_check_files()) ++found_active;
				}

			// if the session is paused, there might still be some torrents
			// in the checking_files state that haven't been dequeued yet
		//	if (m_ses.is_paused())
		//	{
		//		TORRENT_ASSERT(found_active == 0);
		//	}
		//	else
			{
				// the case of 2 is in the special case where one switches over from
				// checking to complete.
				TORRENT_ASSERT(found_active >= 1);
				TORRENT_ASSERT(found_active <= 2);
				TORRENT_ASSERT(found >= 1);
			}
		}

		TORRENT_ASSERT(m_resume_entry.type() == lazy_entry::dict_t
			|| m_resume_entry.type() == lazy_entry::none_t);

		int num_uploads = 0;
		std::map<piece_block, int> num_requests;
		for (const_peer_iterator i = begin(); i != end(); ++i)
		{
#ifdef TORRENT_EXPENSIVE_INVARIANT_CHECKS
			// make sure this peer is not a dangling pointer
			TORRENT_ASSERT(m_ses.has_peer(*i));
#endif
			peer_connection const& p = *(*i);
			for (std::vector<pending_block>::const_iterator i = p.request_queue().begin()
				, end(p.request_queue().end()); i != end; ++i)
				++num_requests[i->block];
			for (std::vector<pending_block>::const_iterator i = p.download_queue().begin()
				, end(p.download_queue().end()); i != end; ++i)
				if (!i->not_wanted && !i->timed_out) ++num_requests[i->block];
			if (!p.is_choked() && !p.ignore_unchoke_slots()) ++num_uploads;
			torrent* associated_torrent = p.associated_torrent().lock().get();
			if (associated_torrent != this && associated_torrent != 0)
				TORRENT_ASSERT(false);
		}
		TORRENT_ASSERT(num_uploads == int(m_num_uploads));

		if (has_picker())
		{
			for (std::map<piece_block, int>::iterator i = num_requests.begin()
				, end(num_requests.end()); i != end; ++i)
			{
				piece_block b = i->first;
				int count = i->second;
				int picker_count = m_picker->num_peers(b);
				if (!m_picker->is_downloaded(b))
					TORRENT_ASSERT(picker_count == count);
			}
			TORRENT_ASSERT(num_have() >= m_picker->num_have_filtered());
		}

		if (valid_metadata())
		{
			TORRENT_ASSERT(m_abort || m_error || !m_picker || m_picker->num_pieces() == m_torrent_file->num_pieces());
		}
		else
		{
			TORRENT_ASSERT(m_abort || m_error || !m_picker || m_picker->num_pieces() == 0);
		}

#ifdef TORRENT_EXPENSIVE_INVARIANT_CHECKS
		// make sure we haven't modified the peer object
		// in a way that breaks the sort order
		if (m_policy.begin_peer() != m_policy.end_peer())
		{
			policy::const_iterator i = m_policy.begin_peer();
			policy::const_iterator prev = i++;
			policy::const_iterator end(m_policy.end_peer());
			policy::peer_address_compare cmp;
			for (; i != end; ++i, ++prev)
			{
				TORRENT_ASSERT(!cmp(*i, *prev));
			}
		}
#endif

		size_type total_done = quantized_bytes_done();
		if (m_torrent_file->is_valid())
		{
			if (is_seed())
				TORRENT_ASSERT(total_done == m_torrent_file->total_size());
			else
				TORRENT_ASSERT(total_done != m_torrent_file->total_size() || !m_files_checked);

			TORRENT_ASSERT(block_size() <= m_torrent_file->piece_length());
		}
		else
		{
			TORRENT_ASSERT(total_done == 0);
		}

		if (m_picker && !m_abort)
		{
			// make sure that pieces that have completed the download
			// of all their blocks are in the disk io thread's queue
			// to be checked.
			const std::vector<piece_picker::downloading_piece>& dl_queue
				= m_picker->get_download_queue();
			for (std::vector<piece_picker::downloading_piece>::const_iterator i =
				dl_queue.begin(); i != dl_queue.end(); ++i)
			{
				const int blocks_per_piece = m_picker->blocks_in_piece(i->index);

				bool complete = true;
				for (int j = 0; j < blocks_per_piece; ++j)
				{
					if (i->info[j].state == piece_picker::block_info::state_finished)
						continue;
					complete = false;
					break;
				}
			}
		}
			
		if (m_files_checked && valid_metadata())
		{
			TORRENT_ASSERT(block_size() > 0);
		}
//		if (is_seed()) TORRENT_ASSERT(m_picker.get() == 0);


		for (std::vector<size_type>::const_iterator i = m_file_progress.begin()
			, end(m_file_progress.end()); i != end; ++i)
		{
			int index = i - m_file_progress.begin();
			TORRENT_ASSERT(*i <= m_torrent_file->files().at(index).size);
		}
	}
#endif

	void torrent::set_sequential_download(bool sd)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		if (m_sequential_download == sd) return;
		m_sequential_download = sd;

		m_need_save_resume_data = true;

		state_updated();
	}

	void torrent::queue_up()
	{
		set_queue_position(queue_position() == 0
			? queue_position() : queue_position() - 1);
	}

	void torrent::queue_down()
	{
		set_queue_position(queue_position() + 1);
	}

	void torrent::set_queue_position(int p)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT((p == -1) == is_finished()
			|| (!m_auto_managed && p == -1)
			|| (m_abort && p == -1));
		if (is_finished() && p != -1) return;
		if (p == m_sequence_number) return;

		state_updated();

		session_impl::torrent_map& torrents = m_ses.m_torrents;
		if (p >= 0 && m_sequence_number == -1)
		{
			int max_seq = -1;
			for (session_impl::torrent_map::iterator i = torrents.begin()
				, end(torrents.end()); i != end; ++i)
			{
				torrent* t = i->second.get();
				if (t->m_sequence_number > max_seq) max_seq = t->m_sequence_number;
				if (t->m_sequence_number >= p)
				{
					++t->m_sequence_number;
					t->state_updated();
				}
			}
			m_sequence_number = (std::min)(max_seq + 1, p);
		}
		else if (p < 0)
		{
			for (session_impl::torrent_map::iterator i = torrents.begin()
				, end(torrents.end()); i != end; ++i)
			{
				torrent* t = i->second.get();
				if (t == this) continue;
				if (t->m_sequence_number >= m_sequence_number
					&& t->m_sequence_number != -1)
				{
					--t->m_sequence_number;
					t->state_updated();
				}
			}
			m_sequence_number = p;
		}
		else if (p < m_sequence_number)
		{
			for (session_impl::torrent_map::iterator i = torrents.begin()
				, end(torrents.end()); i != end; ++i)
			{
				torrent* t = i->second.get();
				if (t == this) continue;
				if (t->m_sequence_number >= p 
					&& t->m_sequence_number < m_sequence_number
					&& t->m_sequence_number != -1)
				{
					++t->m_sequence_number;
					t->state_updated();
				}
			}
			m_sequence_number = p;
		}
		else if (p > m_sequence_number)
		{
			int max_seq = 0;
			for (session_impl::torrent_map::iterator i = torrents.begin()
				, end(torrents.end()); i != end; ++i)
			{
				torrent* t = i->second.get();
				int pos = t->m_sequence_number;
				if (pos > max_seq) max_seq = pos;
				if (t == this) continue;

				if (pos <= p
						&& pos > m_sequence_number
						&& pos != -1)
				{
					--t->m_sequence_number;
					t->state_updated();
				}

			}
			m_sequence_number = (std::min)(max_seq, p);
		}

		m_ses.m_auto_manage_time_scaler = 2;
	}

	void torrent::set_max_uploads(int limit)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT(limit >= -1);
		if (limit <= 0) limit = (1<<24)-1;
		if (m_max_uploads != limit) state_updated();
		m_max_uploads = limit;

		m_need_save_resume_data = true;
	}

	void torrent::set_max_connections(int limit)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT(limit >= -1);
		if (limit <= 0) limit = (1<<24)-1;
		if (m_max_connections != limit) state_updated();
		m_max_connections = limit;

		if (num_peers() > int(m_max_connections))
		{
			disconnect_peers(num_peers() - m_max_connections
				, error_code(errors::too_many_connections, get_libtorrent_category()));
		}

		m_need_save_resume_data = true;
	}

	int torrent::get_peer_upload_limit(ns3::Ipv4EndPoint ip) const
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		const_peer_iterator i = std::find_if(m_connections.begin(), m_connections.end()
			, boost::bind(&peer_connection::remote, _1) == ip);
		if (i == m_connections.end()) return -1;
		return (*i)->get_upload_limit();
	}

	int torrent::get_peer_download_limit(ns3::Ipv4EndPoint ip) const
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		const_peer_iterator i = std::find_if(m_connections.begin(), m_connections.end()
			, boost::bind(&peer_connection::remote, _1) == ip);
		if (i == m_connections.end()) return -1;
		return (*i)->get_download_limit();
	}

	void torrent::set_peer_upload_limit(ns3::Ipv4EndPoint ip, int limit)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT(limit >= -1);
		peer_iterator i = std::find_if(m_connections.begin(), m_connections.end()
			, boost::bind(&peer_connection::remote, _1) == ip);
		if (i == m_connections.end()) return;
		(*i)->set_upload_limit(limit);
	}

	void torrent::set_peer_download_limit(ns3::Ipv4EndPoint ip, int limit)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT(limit >= -1);
		peer_iterator i = std::find_if(m_connections.begin(), m_connections.end()
			, boost::bind(&peer_connection::remote, _1) == ip);
		if (i == m_connections.end()) return;
		(*i)->set_download_limit(limit);
	}

	void torrent::set_upload_limit(int limit)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT(limit >= -1);
		if (limit <= 0) limit = 0;
		if (m_bandwidth_channel[peer_connection::upload_channel].throttle() != limit)
			state_updated();
		m_bandwidth_channel[peer_connection::upload_channel].throttle(limit);

		m_need_save_resume_data = true;
	}

	int torrent::upload_limit() const
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		int limit = m_bandwidth_channel[peer_connection::upload_channel].throttle();
		if (limit == (std::numeric_limits<int>::max)()) limit = -1;
		return limit;
	}

	void torrent::set_download_limit(int limit)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT(limit >= -1);
		if (limit <= 0) limit = 0;
		if (m_bandwidth_channel[peer_connection::download_channel].throttle() != limit)
			state_updated();
		m_bandwidth_channel[peer_connection::download_channel].throttle(limit);

		m_need_save_resume_data = true;
	}

	int torrent::download_limit() const
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		int limit = m_bandwidth_channel[peer_connection::download_channel].throttle();
		if (limit == (std::numeric_limits<int>::max)()) limit = -1;
		return limit;
	}

    // TODO: 禁用piece操作
/*	void torrent::delete_files()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING || defined TORRENT_LOGGING
		log_to_all_peers("DELETING FILES IN TORRENT");
#endif

		disconnect_all(errors::torrent_removed);
		stop_announcing();

		// storage may be NULL during shutdown
		if (m_owning_storage.get())
		{
			TORRENT_ASSERT(m_storage);
			m_storage->async_delete_files(
				boost::bind(&torrent::on_files_deleted, shared_from_this(), _1, _2));
		}
	}*/

	void torrent::clear_error()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		if (!m_error) return;
		//bool checking_files = should_check_files();
		m_ses.m_auto_manage_time_scaler = 2;
		m_error = error_code();
		m_error_file.clear();

		state_updated();

		// if we haven't downloaded the metadata from m_url, try again
		/*if (!m_url.empty() && !m_torrent_file->is_valid())
		{
			start_download_url();
			return;
		}*/
		// if the error happened during initialization, try again now
        // TODO: 禁用piece操作
		//if (!m_storage) init();
		//if (!checking_files && should_check_files())
		//	queue_torrent_check();
	}

	void torrent::set_error(error_code const& ec, std::string const& error_file)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		//bool checking_files = should_check_files();
		m_error = ec;
		m_error_file = error_file;

		//if (alerts().should_post<torrent_error_alert>())
			//alerts().post_alert(torrent_error_alert(get_handle(), ec));

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING || defined TORRENT_LOGGING
		if (ec)
		{
			char buf[1024];
			snprintf(buf, sizeof(buf), "TORRENT ERROR: %s: %s", ec.message().c_str(), error_file.c_str());
			log_to_all_peers(buf);
		}
#endif

	//	if (checking_files && !should_check_files())
	//	{
	//		// stop checking
    //        // TODO: 禁用piece操作
	//		//m_storage->abort_disk_io();
	//		dequeue_torrent_check();
	//		set_state(torrent_status::queued_for_checking);
	//	}

		state_updated();
	}

	void torrent::auto_managed(bool a)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		INVARIANT_CHECK;

		if (m_auto_managed == a) return;
		//bool checking_files = should_check_files();
		m_auto_managed = a;

		state_updated();

		// we need to save this new state as well
		m_need_save_resume_data = true;

		// recalculate which torrents should be
		// paused
		m_ses.m_auto_manage_time_scaler = 2;

		//if (!checking_files && should_check_files())
		//{
		//	queue_torrent_check();
		//}
		//else if (checking_files && !should_check_files())
	//	{
	//		// stop checking
    //        // TODO: 禁用piece操作
	//		//m_storage->abort_disk_io();
	//		dequeue_torrent_check();
	//		set_state(torrent_status::queued_for_checking);
	//	}

		// if this torrent is running and just became auto-managed
		// we might want to pause it in favor of some other torrent
		if (m_auto_managed /*&& !is_paused()*/)
			m_ses.m_auto_manage_time_scaler = 2;
	}

	// the higher seed rank, the more important to seed
	int torrent::seed_rank(session_settings const& s) const
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		enum flags
		{
			seed_ratio_not_met = 0x40000000,
			no_seeds = 0x20000000,
			recently_started = 0x10000000,
			prio_mask = 0x0fffffff
		};

		if (!is_finished()) return 0;

		int scale = 1000;
		if (!is_seed()) scale = 500;

		int ret = 0;

		ptime now = time_now();

		int finished_time = m_finished_time;
		int download_time = int(m_active_time) - finished_time;

		// if we haven't yet met the seed limits, set the seed_ratio_not_met
		// flag. That will make this seed prioritized
		// downloaded may be 0 if the torrent is 0-sized
		size_type downloaded = (std::max)(m_total_downloaded, m_torrent_file->total_size());
		if (finished_time < s.seed_time_limit
			&& (download_time > 1 && finished_time / download_time < s.seed_time_ratio_limit)
			&& downloaded > 0
			&& m_total_uploaded / downloaded < s.share_ratio_limit)
			ret |= seed_ratio_not_met;

		// if this torrent is running, and it was started less
		// than 30 minutes ago, give it priority, to avoid oscillation
		if (/*!is_paused() &&*/ now - m_started < minutes(30))
			ret |= recently_started;

		// if we have any scrape data, use it to calculate
		// seed rank
		int seeds = 0;
		int downloaders = 0;

		if (m_complete != 0xffffff) seeds = m_complete;
		else seeds = m_policy.num_seeds();

		if (m_downloaders != 0xffffff) downloaders = m_downloaders;
		else if (m_incomplete != 0xffffff) downloaders = m_incomplete;
		else downloaders = m_policy.num_peers() - m_policy.num_seeds();

		if (seeds == 0)
		{
			ret |= no_seeds;
			ret |= downloaders & prio_mask;
		}
		else
		{
			ret |= ((1 + downloaders) * scale / seeds) & prio_mask;
		}

		return ret;
	}

	// this is an async operation triggered by the client	
            // TODO: 禁用piece操作
	/*void torrent::save_resume_data(int flags)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		INVARIANT_CHECK;
	
		if (!valid_metadata())
		{
			alerts().post_alert(save_resume_data_failed_alert(get_handle()
				, errors::no_metadata));
			return;
		}

		if (!m_owning_storage.get())
		{
			alerts().post_alert(save_resume_data_failed_alert(get_handle()
				, errors::destructing_torrent));
			return;
		}

		m_need_save_resume_data = false;
		m_last_saved_resume = time(0);
		m_save_resume_flags = boost::uint8_t(flags);
		state_updated();

		TORRENT_ASSERT(m_storage);
		if (m_state == torrent_status::queued_for_checking
			|| m_state == torrent_status::checking_files
			|| m_state == torrent_status::checking_resume_data)
		{
			boost::shared_ptr<entry> rd(new entry);
			write_resume_data(*rd);
			alerts().post_alert(save_resume_data_alert(rd
				, get_handle()));
			return;
		}

		// storage may be NULL during shutdown
		if ((flags & torrent_handle::flush_disk_cache) && m_storage)
			m_storage->async_release_files();

		m_storage->async_save_resume_data(
			boost::bind(&torrent::on_save_resume_data, shared_from_this(), _1, _2));
	}*/
	
//	bool torrent::should_check_files() const
//	{
//		TORRENT_ASSERT(m_ses.is_network_thread());
//		// #error should m_allow_peers really affect checking?
//		return (m_state == torrent_status::checking_files
//			|| m_state == torrent_status::queued_for_checking)
//			&& (m_allow_peers || m_auto_managed)
//			&& !has_error()
//			&& !m_abort
//			&& !m_graceful_pause_mode
//			&& !m_ses.is_paused();
//	}

//	bool torrent::is_paused() const
//	{
//		TORRENT_ASSERT(m_ses.is_network_thread());
//		return !m_allow_peers || m_ses.is_paused() || m_graceful_pause_mode;
//	}

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING || defined TORRENT_LOGGING
	void torrent::log_to_all_peers(char const* message)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
		for (peer_iterator i = m_connections.begin();
				i != m_connections.end(); ++i)
		{
			(*i)->peer_log("*** %s", message);
		}
#endif

		debug_log("%s", message);
	}
#endif

	void torrent::set_allow_peers(bool b, bool graceful)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());

		if (m_allow_peers == b
			&& m_graceful_pause_mode == graceful) return;

		m_allow_peers = b;
		//if (!m_ses.is_paused())
		//	m_graceful_pause_mode = graceful;

		if (!b)
		{
			//m_announce_to_dht = false;
			m_announce_to_trackers = false;
		}
	}

	void torrent::update_tracker_timer(ptime now)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		if (!m_announcing)
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
			debug_log("*** update tracker timer: not announcing");
#endif
			return;
		}

		ptime next_announce = max_time();
		int tier = INT_MAX;

		bool found_working = false;

		for (std::vector<announce_entry>::iterator i = m_trackers.begin()
			, end(m_trackers.end()); i != end; ++i)
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
			char msg[1000];
			snprintf(msg, sizeof(msg), "*** update tracker timer: considering \"%s\" "
				"[ announce_to_all_tiers: %d announce_to_all_trackers: %d"
				" found_working: %d i->tier: %d tier: %d "
				" is_working: %d fails: %d fail_limit: %d updating: %d ]"
				, i->url.c_str(), settings().announce_to_all_tiers
				, settings().announce_to_all_trackers, found_working
				, i->tier, tier, i->is_working(), i->fails, i->fail_limit
				, i->updating);
			debug_log(msg);
#endif
			if (settings().announce_to_all_tiers
				&& found_working
				&& i->tier <= tier
				&& tier != INT_MAX)
				continue;

			if (i->tier > tier && !settings().announce_to_all_tiers) break;
			if (i->is_working()) { tier = i->tier; found_working = false; }
			if (i->fails >= i->fail_limit && i->fail_limit != 0) continue;
			if (i->updating)
			{
				found_working = true;
			}
			else
			{
				ptime next_tracker_announce = (std::max)(i->next_announce, i->min_announce);
				if (next_tracker_announce < next_announce
					&& (!found_working || i->is_working()))
					next_announce = next_tracker_announce;
			}
			if (i->is_working()) found_working = true;
			if (found_working
				&& !settings().announce_to_all_trackers
				&& !settings().announce_to_all_tiers) break;
		}

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
		char msg[200];
		snprintf(msg, sizeof(msg), "*** update tracker timer: next_announce < now %d"
			" m_waiting_tracker: %d next_announce_in: %d"
			, next_announce <= now, m_waiting_tracker, total_seconds(now - next_announce));
		debug_log(msg);
#endif
		if (next_announce <= now) next_announce = now;

		m_waiting_tracker = true;
		error_code ec;
		boost::weak_ptr<torrent> self(shared_from_this());

        // TODO: 暂时禁用boost::asio
		// don't re-issue the timer if it's the same expiration time as last time
	/*	if (m_tracker_timer.expires_at() == next_announce) return;

#if defined TORRENT_ASIO_DEBUGGING
		add_outstanding_async("tracker::on_tracker_announce_disp");
#endif
		m_tracker_timer.expires_at(next_announce, ec);
		m_tracker_timer.async_wait(boost::bind(&torrent::on_tracker_announce_disp, self, _1));*/
	}

	void torrent::start_announcing()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		TORRENT_ASSERT(m_ses.is_network_thread());
//		if (is_paused())
//		{
//#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
//			debug_log("start_announcing(), paused");
//#endif
//			return;
//		}
		// if we don't have metadata, we need to announce
		// before checking files, to get peers to
		// request the metadata from
//		if (!m_files_checked && valid_metadata())
//		{
//#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
//			debug_log("start_announcing(), files not checked (with valid metadata)");
//#endif
//			return;
//		}
		/*if (!m_torrent_file->is_valid() && !m_url.empty())
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
			debug_log("start_announcing(), downloading URL");
#endif
			return;
		}*/
		if (m_announcing) return;

		m_announcing = true;

		if (!m_trackers.empty())
		{
			// tell the tracker that we're back
			std::for_each(m_trackers.begin(), m_trackers.end()
				, boost::bind(&announce_entry::reset, _1));
		}

		// reset the stats, since from the tracker's
		// point of view, this is a new session
		m_total_failed_bytes = 0;
		m_total_redundant_bytes = 0;
		m_stat.clear();

		announce_with_tracker();
	}

	void torrent::stop_announcing()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		if (!m_announcing) return;

        // TODO: 禁用boost::asio
		//error_code ec;
		//m_tracker_timer.cancel(ec);

		m_announcing = false;

		ptime now = time_now();
		for (std::vector<announce_entry>::iterator i = m_trackers.begin()
			, end(m_trackers.end()); i != end; ++i)
		{
			i->next_announce = now;
			i->min_announce = now;
		}
		announce_with_tracker(tracker_request::stopped);
	}

	void torrent::second_tick(stat& accumulator, int tick_interval_ms)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		TORRENT_ASSERT(m_ses.is_network_thread());
		INVARIANT_CHECK;

		boost::weak_ptr<torrent> self(shared_from_this());

		m_time_scaler--;
		if (m_time_scaler <= 0)
		{
			m_time_scaler = 10;

			if (settings().max_sparse_regions > 0
				&& m_picker
				&& m_picker->sparse_regions() > settings().max_sparse_regions)
			{
				// we have too many sparse regions. Prioritize pieces
				// that won't introduce new sparse regions
				// prioritize pieces that will reduce the number of sparse
				// regions even higher
				int start = m_picker->cursor();
				int end = m_picker->reverse_cursor();
				for (int i = start; i < end; ++i)
					update_sparse_piece_prio(i, start, end);
			}

			// ------------------------
			// upload shift
			// ------------------------

			// this part will shift downloads
			// from peers that are seeds and peers
			// that don't want to download from us
			// to peers that cannot upload anything
			// to us. The shifting will make sure
			// that the torrent's share ratio
			// will be maintained

			// if the share ratio is 0 (infinite)
			// m_available_free_upload isn't used
			// because it isn't necessary
			if (ratio() != 0.f)
			{
				// accumulate all the free download we get
				// and add it to the available free upload
				add_free_upload(collect_free_download(
					this->begin(), this->end()));

				// distribute the free upload among the peers
				m_available_free_upload = distribute_free_upload(
					this->begin(), this->end(), m_available_free_upload);
			}
		}

		// if we're in upload only mode and we're auto-managed
		// leave upload mode every 10 minutes hoping that the error
		// condition has been fixed
		if (m_upload_mode && m_auto_managed && int(m_upload_mode_time)
			>= settings().optimistic_disk_retry)
		{
			set_upload_mode(false);
		}

//		if (is_paused())
//		{
//			// let the stats fade out to 0
//			accumulator += m_stat;
// 			m_stat.second_tick(tick_interval_ms);
//			// if the rate is 0, there's no update because of network transfers
//			if (m_stat.low_pass_upload_rate() > 0 || m_stat.low_pass_download_rate() > 0)
//				state_updated();
//			return;
//		}

		if (settings().rate_limit_ip_overhead)
		{
			//int up_limit = m_bandwidth_channel[peer_connection::upload_channel].throttle();
			//int down_limit = m_bandwidth_channel[peer_connection::download_channel].throttle();

            // TODO: 禁用alert
			/*if (down_limit > 0
				&& m_stat.download_ip_overhead() >= down_limit
    			&& alerts().should_post<performance_alert>())
			{
				alerts().post_alert(performance_alert(get_handle()
					, performance_alert::download_limit_too_low));
			}

			if (up_limit > 0
				&& m_stat.upload_ip_overhead() >= up_limit
				&& alerts().should_post<performance_alert>())
			{
				alerts().post_alert(performance_alert(get_handle()
					, performance_alert::upload_limit_too_low));
			}*/
		}

		int seconds_since_last_tick = 1;
		if (m_ses.m_tick_residual >= 1000) ++seconds_since_last_tick;

		if (is_seed()) m_seeding_time += seconds_since_last_tick;
		if (is_finished()) m_finished_time += seconds_since_last_tick;
		if (m_upload_mode) m_upload_mode_time += seconds_since_last_tick;
		m_last_scrape += seconds_since_last_tick;
		m_active_time += seconds_since_last_tick;
		m_last_download += seconds_since_last_tick;
		m_last_upload += seconds_since_last_tick;

		// ---- TIME CRITICAL PIECES ----

		if (!m_time_critical_pieces.empty())
		{
			request_time_critical_pieces();
		}

		// ---- WEB SEEDS ----

		for (peer_iterator i = m_connections.begin();
			i != m_connections.end();)
		{
			peer_connection* p = *i;
			++i;

			if (!p->ignore_stats())
				m_stat += p->statistics();

			// updates the peer connection's ul/dl bandwidth
			// resource requests
			TORRENT_TRY {
				p->second_tick(tick_interval_ms);
			}
			TORRENT_CATCH (std::exception& e)
			{
				TORRENT_DECLARE_DUMMY(std::exception, e);
				(void)e;
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
				p->peer_log("*** ERROR %s", e.what());
#endif
				p->disconnect(errors::no_error, 1);
			}
		}
		accumulator += m_stat;
		m_total_uploaded += m_stat.last_payload_uploaded();
		m_total_downloaded += m_stat.last_payload_downloaded();
		m_stat.second_tick(tick_interval_ms);

		// if the rate is 0, there's no update because of network transfers
		if (m_stat.low_pass_upload_rate() > 0 || m_stat.low_pass_download_rate() > 0)
			state_updated();
	}

	void torrent::recalc_share_mode()
	{
		TORRENT_ASSERT(share_mode());
		if (is_seed()) return;

		int pieces_in_torrent = m_torrent_file->num_pieces();
		int num_seeds = 0;
		int num_peers = 0;
		int num_downloaders = 0;
		int missing_pieces = 0;
		int num_interested = 0;
		for (std::set<peer_connection*>::iterator i = m_connections.begin()
			, end(m_connections.end()); i != end; ++i)
		{
			peer_connection* p = *i;
			if (p->is_connecting()) continue;
			++num_peers;
			if (p->is_seed())
			{
				++num_seeds;
				continue;
			}

			if (p->share_mode()) continue;

			if ((*i)->is_peer_interested()) ++num_interested;
			++num_downloaders;
			missing_pieces += pieces_in_torrent - p->num_have_pieces();
		}

		if (num_peers == 0) return;

		if (num_seeds * 100 / num_peers > 50
			&& (num_peers * 100 / m_max_connections > 90
				|| num_peers > 20))
		{
			// we are connected to more than 90% seeds (and we're beyond
			// 90% of the max number of connections). That will
			// limit our ability to upload. We need more downloaders.
			// disconnect some seeds so that we don't have more than 50%
			int to_disconnect = num_seeds - num_peers / 2;
			std::vector<peer_connection*> seeds;
			seeds.reserve(num_seeds);
			for (std::set<peer_connection*>::iterator i = m_connections.begin()
				, end(m_connections.end()); i != end; ++i)
			{
				peer_connection* p = *i;
				if (p->is_seed()) seeds.push_back(p);
			}

			std::random_shuffle(seeds.begin(), seeds.end());
			TORRENT_ASSERT(to_disconnect <= int(seeds.size()));
			for (int i = 0; i < to_disconnect; ++i)
				seeds[i]->disconnect(errors::upload_upload_connection);
		}

		if (num_downloaders == 0) return;

		// assume that the seeds are about as fast as us. During the time
		// we can download one piece, and upload one piece, each seed
		// can upload two pieces.
		missing_pieces -= 2 * num_seeds;

		if (missing_pieces <= 0) return;
		
		// missing_pieces represents our opportunity to download pieces
		// and share them more than once each

		// now, download at least one piece, otherwise download one more
		// piece if our downloaded (and downloading) pieces is less than 50%
		// of the uploaded bytes
		int num_downloaded_pieces = (std::max)(m_picker->num_have()
			, pieces_in_torrent - m_picker->num_filtered());

		if (num_downloaded_pieces * m_torrent_file->piece_length()
			* settings().share_mode_target > m_total_uploaded
			&& num_downloaded_pieces > 0)
			return;

		// don't have more pieces downloading in parallel than 5% of the total
		// number of pieces we have downloaded
		if (int(m_picker->get_download_queue().size()) > num_downloaded_pieces / 20)
			return;

		// one more important property is that there are enough pieces
		// that more than one peer wants to download
		// make sure that there are enough downloaders for the rarest
		// piece. Go through all pieces, figure out which one is the rarest
		// and how many peers that has that piece

		std::vector<int> rarest_pieces;

		int num_pieces = m_torrent_file->num_pieces();
		int rarest_rarity = INT_MAX;
		bool prio_updated = false;
		for (int i = 0; i < num_pieces; ++i)
		{
			piece_picker::piece_pos const& pp = m_picker->piece_stats(i);
			if (pp.peer_count == 0) continue;
			if (pp.filtered() && (pp.have() || pp.downloading))
			{
				m_picker->set_piece_priority(i, 1);
				prio_updated = true;
				continue;
			}
			// don't count pieces we already have or are downloading
			if (!pp.filtered() || pp.have()) continue;
			if (int(pp.peer_count) > rarest_rarity) continue;
			if (int(pp.peer_count) == rarest_rarity)
			{
				rarest_pieces.push_back(i);
				continue;
			}

			rarest_pieces.clear();
			rarest_rarity = pp.peer_count;
			rarest_pieces.push_back(i);
		}

		if (prio_updated)
			m_policy.recalculate_connect_candidates();

		// now, rarest_pieces is a list of all pieces that are the rarest ones.
		// and rarest_rarity is the number of peers that have the rarest pieces

		// if there's only a single peer that doesn't have the rarest piece
		// it's impossible for us to download one piece and upload it
		// twice. i.e. we cannot get a positive share ratio
		if (num_peers - rarest_rarity < settings().share_mode_target) return;

		// we might be able to do better than a share ratio of 2 if there are
		// enough downloaders of the pieces we already have.
		// TODO: go through the pieces we have and count the total number
		// of downloaders we have. Only count peers that are interested in us
		// since some peers might not send have messages for pieces we have
		// it num_interested == 0, we need to pick a new piece

		// now, pick one of the rarest pieces to download
		int pick = random() % rarest_pieces.size();
		bool was_finished = is_finished();
		m_picker->set_piece_priority(rarest_pieces[pick], 1);
		update_peer_interest(was_finished);

		m_policy.recalculate_connect_candidates();
	}

	void torrent::refresh_explicit_cache(int cache_size)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		if (!ready_for_connections()) return;

		if (m_abort) return;
		TORRENT_ASSERT(m_storage);

		// rotate the cached pieces

		// add blocks_per_piece / 2 in order to round to closest whole piece
		int blocks_per_piece = m_torrent_file->piece_length() / block_size();
		int num_cache_pieces = (cache_size + blocks_per_piece / 2) / blocks_per_piece;
		if (num_cache_pieces > m_torrent_file->num_pieces())
			num_cache_pieces = m_torrent_file->num_pieces();

		std::vector<int> avail_vec;
		if (has_picker())
		{
			m_picker->get_availability(avail_vec);
		}
		else
		{
			// we don't keep track of availability, do it the expensive way
			// do a linear search from the first piece
			for (int i = 0; i < m_torrent_file->num_pieces(); ++i)
			{
				int availability = 0;
				if (!have_piece(i))
				{
					avail_vec.push_back(INT_MAX);
					continue;
				}

				for (const_peer_iterator j = this->begin(); j != this->end(); ++j)
					if ((*j)->has_piece(i)) ++availability;
				avail_vec.push_back(availability);
			}
		}

		// now pick the num_cache_pieces rarest pieces from avail_vec
		std::vector<std::pair<int, int> > pieces(m_torrent_file->num_pieces());
		for (int i = 0; i < m_torrent_file->num_pieces(); ++i)
		{
			pieces[i].second = i;
			if (!have_piece(i)) pieces[i].first = INT_MAX;
			else pieces[i].first = avail_vec[i];
		}

		// decrease the availability of the pieces that are
		// already in the read cache, to move them closer to
		// the beginning of the pieces list, and more likely
		// to be included in this round of cache pieces
		std::vector<cached_piece_info> ret;
		//m_ses.m_disk_thread.get_cache_info(info_hash(), ret);
		// remove write cache entries
		ret.erase(std::remove_if(ret.begin(), ret.end()
			, boost::bind(&cached_piece_info::kind, _1) == cached_piece_info::write_cache)
			, ret.end());
		for (std::vector<cached_piece_info>::iterator i = ret.begin()
			, end(ret.end()); i != end; ++i)
		{
			--pieces[i->piece].first;
		}

		std::random_shuffle(pieces.begin(), pieces.end());
		std::stable_sort(pieces.begin(), pieces.end()
			, boost::bind(&std::pair<int, int>::first, _1) <
			boost::bind(&std::pair<int, int>::first, _2));
		avail_vec.clear();
		for (int i = 0; i < num_cache_pieces; ++i)
		{
			if (pieces[i].first == INT_MAX) break;
			avail_vec.push_back(pieces[i].second);
		}

		if (!avail_vec.empty())
		{
			// the number of pieces to cache for this torrent is proportional
			// the number of peers it has, divided by the total number of peers.
			// Each peer gets an equal share of the cache

			avail_vec.resize((std::min)(num_cache_pieces, int(avail_vec.size())));

	//		for (std::vector<int>::iterator i = avail_vec.begin()
	//			, end(avail_vec.end()); i != end; ++i)
				//filesystem().async_cache(*i, boost::bind(&torrent::on_disk_cache_complete
				//	, shared_from_this(), _1, _2));
		}
	}

	void torrent::get_suggested_pieces(std::vector<int>& s) const
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		if (settings().suggest_mode == session_settings::no_piece_suggestions)
		{
			s.clear();
			return;
		}

//		std::vector<cached_piece_info> ret;
		//m_ses.m_disk_thread.get_cache_info(info_hash(), ret);

		// remove write cache entries
	//	ret.erase(std::remove_if(ret.begin(), ret.end()
	//		, boost::bind(&cached_piece_info::kind, _1) == cached_piece_info::write_cache)
	//		, ret.end());

	//	// sort by how new the cached entry is, new pieces first
	//	std::sort(ret.begin(), ret.end()
	//		, boost::bind(&cached_piece_info::last_use, _1)
	//		< boost::bind(&cached_piece_info::last_use, _2));

		// cut off the oldest pieces that we don't want to suggest
		// if we have an explicit cache, it's much more likely to
		// stick around, so we should suggest all pieces
//		int num_pieces_to_suggest = int(ret.size());
//		if (num_pieces_to_suggest == 0) return;

//		if (!settings().explicit_read_cache)
//			num_pieces_to_suggest = (std::max)(1, int(ret.size() / 2));
//		ret.resize(num_pieces_to_suggest);
//
//		std::transform(ret.begin(), ret.end(), std::back_inserter(s)
//			, boost::bind(&cached_piece_info::piece, _1));
	}

	void torrent::add_stats(stat const& s)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		// these stats are propagated to the session
		// stats the next time second_tick is called
		m_stat += s;
	}

	void torrent::request_time_critical_pieces()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		// build a list of peers and sort it by download_queue_time
		// we use this sorted list to determine which peer we should
		// request a block from. The higher up a peer is in the list,
		// the sooner we will fully download the block we request.
		std::vector<peer_connection*> peers;
		peers.reserve(m_connections.size());
		std::remove_copy_if(m_connections.begin(), m_connections.end()
			, std::back_inserter(peers), !boost::bind(&peer_connection::can_request_time_critical, _1));
		std::sort(peers.begin(), peers.end()
			, boost::bind(&peer_connection::download_queue_time, _1, 16*1024)
			< boost::bind(&peer_connection::download_queue_time, _2, 16*1024));

		// remove the bottom 10% of peers from the candidate set
		int new_size = (peers.size() * 9 + 9) / 10;
		TORRENT_ASSERT(new_size <= peers.size());
		peers.resize(new_size);

		std::set<peer_connection*> peers_with_requests;

		std::vector<piece_block> interesting_blocks;
		std::vector<piece_block> backup1;
		std::vector<piece_block> backup2;
		std::vector<int> ignore;

		// peers that should be temporarily ignored for a specific piece
		// in order to give priority to other peers. They should be used for
		// subsequent pieces, so they are stored in this vector until the
		// piece is done
		std::vector<peer_connection*> ignore_peers;

		ptime now = time_now_hires();

		// now, iterate over all time critical pieces, in order of importance, and
		// request them from the peers, in order of responsiveness. i.e. request
		// the most time critical pieces from the fastest peers.
		for (std::deque<time_critical_piece>::iterator i = m_time_critical_pieces.begin()
			, end(m_time_critical_pieces.end()); i != end && !peers.empty(); ++i)
		{
			// the +1000 is to compensate for the fact that we only call this function
			// once per second, so if we need to request it 500 ms from now, we should request
			// it right away
			if (i != m_time_critical_pieces.begin() && i->deadline > now
				+ milliseconds(m_average_piece_time + m_piece_time_deviation * 4 + 1000))
			{
				// don't request pieces whose deadline is too far in the future
				// this is one of the termination conditions. We don't want to
				// send requests for all pieces in the torrent right away
				break;
			}

			piece_picker::downloading_piece pi;
			m_picker->piece_info(i->piece, pi);

			bool timed_out = false;

			int free_to_request = m_picker->blocks_in_piece(i->piece) - pi.finished - pi.writing - pi.requested;
			if (free_to_request == 0)
			{
				// every block in this piece is already requested
				// there's no need to consider this piece, unless it
				// appears to be stalled.
				if (pi.requested == 0 || i->last_requested + milliseconds(m_average_piece_time) > now)
				{
					// if requested is 0, it meants all blocks have been received, and
					// we're just waiting for it to flush them to disk.
					// if last_requested is recent enough, we should give it some
					// more time
					// skip to the next piece
					continue;
				}

				// it's been too long since we requested the last block from this piece. Allow re-requesting
				// blocks from this piece
				timed_out = true;
			}

			// loop until every block has been requested from this piece (i->piece)
			do
			{
				// pick the peer with the lowest download_queue_time that has i->piece
				std::vector<peer_connection*>::iterator p = std::find_if(peers.begin(), peers.end()
					, boost::bind(&peer_connection::has_piece, _1, i->piece));

				// obviously we'll have to skip it if we don't have a peer that has this piece
				if (p == peers.end()) break;
				peer_connection& c = **p;

				interesting_blocks.clear();
				backup1.clear();
				backup2.clear();
				// specifically request blocks with no affinity towards fast or slow
				// pieces. If we would, the picked block might end up in one of
				// the backup lists
				m_picker->add_blocks(i->piece, c.get_bitfield(), interesting_blocks
					, backup1, backup2, 1, 0, c.peer_info_struct()
					, ignore, piece_picker::none, 0);

				std::vector<pending_block> const& rq = c.request_queue();
				std::vector<pending_block> const& dq = c.download_queue();

				bool added_request = false;
				bool busy_blocks = false;

				if (timed_out && interesting_blocks.empty())
				{
					// if the piece has timed out, allow requesting back-up blocks
					interesting_blocks.swap(backup1.empty() ? backup2 : backup1);
					busy_blocks = true;
				}

				if (!interesting_blocks.empty())
				{
					bool already_requested = std::find_if(dq.begin(), dq.end()
						, has_block(interesting_blocks.front())) != dq.end();
					if (already_requested)
					{
						// if the piece is stalled, we may end up picking a block
						// that we've already requested from this peer. If so, we should
						// simply disregard this peer from this piece, since this peer
						// is likely to be causing the stall. We should request it
						// from the next peer in the list
						// the peer will be put back in the set for the next piece
						ignore_peers.push_back(*p);
						peers.erase(p);
						continue;
					}

					bool already_in_queue = std::find_if(rq.begin(), rq.end()
						, has_block(interesting_blocks.front())) != rq.end();

					if (already_in_queue)
					{
						c.make_time_critical(interesting_blocks.front());
						added_request = true;
					}
					else
					{
						if (!c.add_request(interesting_blocks.front(), peer_connection::req_time_critical
							| (busy_blocks ? peer_connection::req_busy : 0)))
						{
							peers.erase(p);
							continue;
						}
						added_request = true;
					}
				}

				if (added_request)
				{
					peers_with_requests.insert(peers_with_requests.begin(), &c);
					if (i->first_requested == min_time()) i->first_requested = now;

					if (!c.can_request_time_critical())
					{
						peers.erase(p);
					}
					else
					{
						// resort p, since it will have a higher download_queue_time now
						while (p != peers.end()-1 && (*p)->download_queue_time() > (*(p+1))->download_queue_time())
						{
							std::iter_swap(p, p+1);
							++p;
						}
					}
				}

				// TODO: 2 will pick_pieces ever return an empty set?
			} while (!interesting_blocks.empty());

			peers.insert(peers.begin(), ignore_peers.begin(), ignore_peers.end());
			ignore_peers.clear();
		}

		// commit all the time critical requests
		for (std::set<peer_connection*>::iterator i = peers_with_requests.begin()
			, end(peers_with_requests.end()); i != end; ++i)
		{
			(*i)->send_block_requests();
		}
	}

	bool torrent::try_connect_peer()
	{
		TORRENT_ASSERT(want_more_peers());
		bool ret = m_policy.connect_one_peer(m_ses.session_time());
		return ret;
	}

	void torrent::add_peer(ns3::Ipv4EndPoint const& adr, int source)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		peer_id id(0);
		m_policy.add_peer(adr, id, source, 0);

		state_updated();
	}

	void torrent::async_verify_piece(int piece_index, boost::function<void(int)> const& f)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
//		INVARIANT_CHECK;

		//TORRENT_ASSERT(m_storage);
		//TORRENT_ASSERT(m_storage->refcount() > 0);
		TORRENT_ASSERT(piece_index >= 0);
		TORRENT_ASSERT(piece_index < m_torrent_file->num_pieces());
		TORRENT_ASSERT(piece_index < (int)m_picker->num_pieces());
		TORRENT_ASSERT(!m_picker || !m_picker->have_piece(piece_index));
#ifdef TORRENT_DEBUG
		if (m_picker)
		{
			int blocks_in_piece = m_picker->blocks_in_piece(piece_index);
			for (int i = 0; i < blocks_in_piece; ++i)
			{
				TORRENT_ASSERT(m_picker->num_peers(piece_block(piece_index, i)) == 0);
			}
		}
#endif

		//m_storage->async_hash(piece_index, boost::bind(&torrent::on_piece_verified
			//, shared_from_this(), _1, _2, f));
#if defined TORRENT_DEBUG && !defined TORRENT_DISABLE_INVARIANT_CHECKS
		check_invariant();
#endif
	}

    // TODO: 临时禁用数据的校验
	/*void torrent::on_piece_verified(int ret, disk_io_job const& j
		, boost::function<void(int)> f)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());

		// return value:
		// 0: success, piece passed hash check
		// -1: disk failure
		// -2: hash check failed

		state_updated();

		if (ret == -1) handle_disk_error(j);
		f(ret);
	}*/

	/*ns3::Ipv4EndPoint torrent::current_tracker() const
	{
		return m_tracker_address;
	}*/

	announce_entry* torrent::find_tracker(tracker_request const& r)
	{
		std::vector<announce_entry>::iterator i = std::find_if(
			m_trackers.begin(), m_trackers.end()
			, boost::bind(&announce_entry::url, _1) == r.url);
		if (i == m_trackers.end()) return 0;
		return &*i;
	}

#if !TORRENT_NO_FPU
	void torrent::file_progress(std::vector<float>& fp) const
	{
		fp.clear();
		if (!valid_metadata()) return;
	
		fp.resize(m_torrent_file->num_files(), 1.f);
		if (is_seed()) return;

		std::vector<size_type> progress;
		file_progress(progress);
		for (uint32_t i = 0; i < m_torrent_file->num_files(); ++i)
		{
			file_entry const& f = m_torrent_file->file_at(i);
			if (f.size == 0) fp[i] = 1.f;
			else fp[i] = float(progress[i]) / f.size;
		}
	}
#endif

	void torrent::file_progress(std::vector<size_type>& fp, int flags) const
	{
		if (!valid_metadata())
		{
			fp.clear();
			return;
		}
	
		fp.resize(m_torrent_file->num_files(), 0);

		if (flags & torrent_handle::piece_granularity)
		{
			std::copy(m_file_progress.begin(), m_file_progress.end(), fp.begin());
			return;
		}

		if (is_seed())
		{
			for (uint32_t i = 0; i < m_torrent_file->num_files(); ++i)
				fp[i] = m_torrent_file->files().at(i).size;
			return;
		}
		
		TORRENT_ASSERT(has_picker());

		for (uint32_t i = 0; i < m_torrent_file->num_files(); ++i)
		{
			peer_request ret = m_torrent_file->files().map_file(i, 0, 0);
			size_type size = m_torrent_file->files().at(i).size;

// zero sized files are considered
// 100% done all the time
			if (size == 0)
			{
				fp[i] = 0;
				continue;
			}

			size_type done = 0;
			while (size > 0)
			{
				size_type bytes_step = (std::min)(size_type(m_torrent_file->piece_size(ret.piece)
					- ret.start), size);
				if (m_picker->have_piece(ret.piece)) done += bytes_step;
				++ret.piece;
				ret.start = 0;
				size -= bytes_step;
			}
			TORRENT_ASSERT(size == 0);

			fp[i] = done;
		}

		const std::vector<piece_picker::downloading_piece>& q
			= m_picker->get_download_queue();

		for (std::vector<piece_picker::downloading_piece>::const_iterator
			i = q.begin(), end(q.end()); i != end; ++i)
		{
			size_type offset = size_type(i->index) * m_torrent_file->piece_length();
			torrent_info::file_iterator file = m_torrent_file->file_at_offset(offset);
			int file_index = file - m_torrent_file->begin_files();
			int num_blocks = m_picker->blocks_in_piece(i->index);
			piece_picker::block_info const* info = i->info;
			for (int k = 0; k < num_blocks; ++k)
			{
				TORRENT_ASSERT(file != m_torrent_file->end_files());
				TORRENT_ASSERT(offset == size_type(i->index) * m_torrent_file->piece_length()
					+ k * block_size());
				TORRENT_ASSERT(offset < m_torrent_file->total_size());
				while (offset >= file->offset + file->size)
				{
					++file;
					++file_index;
				}
				TORRENT_ASSERT(file != m_torrent_file->end_files());

				size_type block = block_size();

				if (info[k].state == piece_picker::block_info::state_none)
				{
					offset += block;
					continue;
				}

				if (info[k].state == piece_picker::block_info::state_requested)
				{
					block = 0;
					policy::peer* p = static_cast<policy::peer*>(info[k].peer);
					if (p && p->connection)
					{
						boost::optional<piece_block_progress> pbp
							= p->connection->downloading_piece_progress();
						if (pbp && pbp->piece_index == i->index && pbp->block_index == k)
							block = pbp->bytes_downloaded;
						TORRENT_ASSERT(block <= block_size());
					}

					if (block == 0)
					{
						offset += block_size();
						continue;
					}
				}

				if (offset + block > file->offset + file->size)
				{
					int left_over = int(block_size() - block);
					// split the block on multiple files
					while (block > 0)
					{
						TORRENT_ASSERT(offset <= file->offset + file->size);
						size_type slice = (std::min)(file->offset + file->size - offset
							, block);
						fp[file_index] += slice;
						offset += slice;
						block -= slice;
						TORRENT_ASSERT(offset <= file->offset + file->size);
						if (offset == file->offset + file->size)
						{
							++file;
							++file_index;
							if (file == m_torrent_file->end_files())
							{
								offset += block;
								break;
							}
						}
					}
					offset += left_over;
					TORRENT_ASSERT(offset == size_type(i->index) * m_torrent_file->piece_length()
						+ (k+1) * block_size());
				}
				else
				{
					fp[file_index] += block;
					offset += block_size();
				}
				TORRENT_ASSERT(file_index <= m_torrent_file->num_files());
			}
		}
	}
	
	void torrent::set_state(torrent_status::state_t s)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
#ifdef TORRENT_DEBUG
		if (s != torrent_status::checking_files
			&& s != torrent_status::queued_for_checking)
		{
			// the only valid transition away from queued_for_checking
			// is to checking_files. One exception is to finished
			// in case all the files are marked with priority 0
			if (m_queued_for_checking)
			{
				std::vector<int> pieces;
				m_picker->piece_priorities(pieces);
				// make sure all pieces have priority 0
				TORRENT_ASSERT(std::accumulate(pieces.begin(), pieces.end(), 0) == 0);
			}
		}
		if (s == torrent_status::seeding)
			TORRENT_ASSERT(is_seed());
		if (s == torrent_status::finished)
			TORRENT_ASSERT(is_finished());
		if (s == torrent_status::downloading && m_state == torrent_status::finished)
			TORRENT_ASSERT(!is_finished());
#endif

		if (int(m_state) == s) return;
		m_state = s;

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
		debug_log("set_state() %d", m_state);
#endif
		state_updated();
	}

	void torrent::state_updated()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		// if this fails, this function is probably called 
		// from within the torrent constructor, which it
		// shouldn't be. Whichever function ends up calling
		// this should probably be moved to torrent::start()
		TORRENT_ASSERT(shared_from_this());

		// we're either not subscribing to this torrent, or
		// it has already been updated this round, no need to
		// add it to the list twice
		if (!m_state_subscription) return;
		if (m_in_state_updates)
		{
			TORRENT_ASSERT(m_ses.in_state_updates(shared_from_this()));
			return;
		}

		m_ses.add_to_update_queue(shared_from_this());
		m_in_state_updates = true;
	}

	void torrent::status(torrent_status* st, boost::uint32_t flags)
	{
		INVARIANT_CHECK;

		//ptime now = time_now();

		st->handle = get_handle();
		st->info_hash = info_hash();

		st->listen_port = 0;

		st->has_incoming = m_has_incoming;
		if (m_error) st->error = convert_from_native(m_error.message()) + ": " + m_error_file;
		st->seed_mode = m_seed_mode;

		st->added_time = m_added_time;
		st->completed_time = m_completed_time;

		st->last_scrape = m_last_scrape;
		st->share_mode = m_share_mode;
		st->upload_mode = m_upload_mode;
		st->up_bandwidth_queue = 0;
		st->down_bandwidth_queue = 0;
		st->priority = m_priority;

		st->num_peers = (int)std::count_if(m_connections.begin(), m_connections.end()
			, !boost::bind(&peer_connection::is_connecting, _1));

		st->list_peers = m_policy.num_peers();
		st->list_seeds = m_policy.num_seeds();
		st->connect_candidates = m_policy.num_connect_candidates();
		st->seed_rank = seed_rank(settings());

		st->all_time_upload = m_total_uploaded;
		st->all_time_download = m_total_downloaded;

		// activity time
		st->finished_time = m_finished_time;
		st->active_time = m_active_time;
		st->seeding_time = m_seeding_time;
		st->time_since_upload = m_last_upload;
		st->time_since_download = m_last_download;

		//st->storage_mode = (storage_mode_t)m_storage_mode;

		st->num_complete = (m_complete == 0xffffff) ? -1 : m_complete;
		st->num_incomplete = (m_incomplete == 0xffffff) ? -1 : m_incomplete;
		st->paused = is_torrent_paused();
		st->auto_managed = m_auto_managed;
		st->sequential_download = m_sequential_download;
		st->is_seeding = is_seed();
		st->is_finished = is_finished();
		st->super_seeding = m_super_seeding;
		st->has_metadata = valid_metadata();
		bytes_done(*st, flags & torrent_handle::query_accurate_download_counters);
		TORRENT_ASSERT(st->total_wanted_done >= 0);
		TORRENT_ASSERT(st->total_done >= st->total_wanted_done);

		// payload transfer
		st->total_payload_download = m_stat.total_payload_download();
		st->total_payload_upload = m_stat.total_payload_upload();

		// total transfer
		st->total_download = m_stat.total_payload_download()
			+ m_stat.total_protocol_download();
		st->total_upload = m_stat.total_payload_upload()
			+ m_stat.total_protocol_upload();

		// failed bytes
		st->total_failed_bytes = m_total_failed_bytes;
		st->total_redundant_bytes = m_total_redundant_bytes;

		// transfer rate
		st->download_rate = m_stat.download_rate();
		st->upload_rate = m_stat.upload_rate();
		st->download_payload_rate = m_stat.download_payload_rate();
		st->upload_payload_rate = m_stat.upload_payload_rate();

//		if (m_waiting_tracker && !is_paused())
//			st->next_announce = boost::posix_time::seconds(
//				total_seconds(next_announce() - now));
//		else
			st->next_announce = boost::posix_time::seconds(0);

		if (st->next_announce.is_negative())
			st->next_announce = boost::posix_time::seconds(0);

		st->announce_interval = boost::posix_time::seconds(0);

	//	st->current_tracker.clear();
	//	if (m_last_working_tracker >= 0)
	//	{
	//		TORRENT_ASSERT(m_last_working_tracker < int(m_trackers.size()));
	//		st->current_tracker = m_trackers[m_last_working_tracker].url;
	//	}
	//	else
	//	{
	//		std::vector<announce_entry>::const_iterator i;
	//		for (i = m_trackers.begin(); i != m_trackers.end(); ++i)
	//		{
	//			if (!i->updating) continue;
	//			st->current_tracker = i->url;
	//			break;
	//		}
	//	}

		if ((flags & torrent_handle::query_verified_pieces))
		{
			st->verified_pieces = m_verified;
		}

		st->num_uploads = m_num_uploads;
		st->uploads_limit = m_max_uploads == (1<<24)-1 ? -1 : m_max_uploads;
		st->num_connections = int(m_connections.size());
		st->connections_limit = m_max_connections == (1<<24)-1 ? -1 : m_max_connections;
		// if we don't have any metadata, stop here

		st->queue_position = queue_position();
		st->need_save_resume = need_save_resume_data();
		st->ip_filter_applies = m_apply_ip_filter;

		st->state = (torrent_status::state_t)m_state;

		if (!valid_metadata())
		{
			st->state = torrent_status::downloading_metadata;
			st->progress_ppm = m_progress_ppm;
#if !TORRENT_NO_FPU
			st->progress = m_progress_ppm / 1000000.f;
#endif
			st->block_size = 0;
			return;
		}

		st->block_size = block_size();

		if (m_state == torrent_status::checking_files)
		{
			st->progress_ppm = m_progress_ppm;
#if !TORRENT_NO_FPU
			st->progress = m_progress_ppm / 1000000.f;
#endif
		}
		else if (st->total_wanted == 0)
		{
			st->progress_ppm = 1000000;
			st->progress = 1.f;
		}
		else
		{
			st->progress_ppm = st->total_wanted_done * 1000000
				/ st->total_wanted;
#if !TORRENT_NO_FPU
			st->progress = st->progress_ppm / 1000000.f;
#endif
		}

		if (has_picker() && (flags & torrent_handle::query_pieces))
		{
			st->sparse_regions = m_picker->sparse_regions();
			int num_pieces = m_picker->num_pieces();
			st->pieces.resize(num_pieces, false);
			for (int i = 0; i < num_pieces; ++i)
				if (m_picker->have_piece(i)) st->pieces.set_bit(i);
		}
		else if (is_seed())
		{
			int num_pieces = m_torrent_file->num_pieces();
			st->pieces.resize(num_pieces, true);
		}
		st->num_pieces = num_have();
		st->num_seeds = num_seeds();
		if ((flags & torrent_handle::query_distributed_copies) && m_picker.get())
		{
			boost::tie(st->distributed_full_copies, st->distributed_fraction) =
				m_picker->distributed_copies();
#if TORRENT_NO_FPU
			st->distributed_copies = -1.f;
#else
			st->distributed_copies = st->distributed_full_copies
				+ float(st->distributed_fraction) / 1000;
#endif
		}
		else
		{
			st->distributed_full_copies = -1;
			st->distributed_fraction = -1;
			st->distributed_copies = -1.f;
		}

		if (flags & torrent_handle::query_last_seen_complete)
		{
			time_t last = last_seen_complete();
			for (std::set<peer_connection*>::const_iterator i = m_connections.begin()
				, end(m_connections.end()); i != end; ++i)
			{
				last = (std::max)(last, (*i)->last_seen_complete());
			}
			st->last_seen_complete = last;
		}
		else
		{
			st->last_seen_complete = 0;
		}
	}

	void torrent::add_redundant_bytes(int b, torrent::wasted_reason_t reason)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT(b > 0);
		m_total_redundant_bytes += b;
		m_ses.add_redundant_bytes(b, reason);
//		TORRENT_ASSERT(m_total_redundant_bytes + m_total_failed_bytes
//			<= m_stat.total_payload_download());
	}

	void torrent::add_failed_bytes(int b)
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		TORRENT_ASSERT(b > 0);
		m_total_failed_bytes += b;
		m_ses.add_failed_bytes(b);
//		TORRENT_ASSERT(m_total_redundant_bytes + m_total_failed_bytes
//			<= m_stat.total_payload_download());
	}

	int torrent::num_seeds() const
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
		INVARIANT_CHECK;

		int ret = 0;
		for (std::set<peer_connection*>::const_iterator i = m_connections.begin()
			, end(m_connections.end()); i != end; ++i)
			if ((*i)->is_seed()) ++ret;
		return ret;
	}

	void torrent::tracker_request_error(tracker_request const& r
		, int response_code, const std::string& msg
		, int retry_interval)
	{
        error_code ec;
		TORRENT_ASSERT(m_ses.is_network_thread());

		INVARIANT_CHECK;

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
		debug_log("*** tracker error: (%d) %s %s", ec.value(), ec.message().c_str(), msg.c_str());
#endif
		if (r.kind == tracker_request::announce_request)
		{
			announce_entry* ae = find_tracker(r);
			if (ae)
			{
				ae->failed(settings(), retry_interval);
				ae->last_error = ec;
				ae->message = msg;
				int tracker_index = ae - &m_trackers[0];
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
				debug_log("*** increment tracker fail count [%d]", ae->fails);
#endif
				// never talk to this tracker again
				if (response_code == 410) ae->fail_limit = 1;

				deprioritize_tracker(tracker_index);
			}
		}
		else if (r.kind == tracker_request::scrape_request)
		{
			if (response_code == 410)
			{
				// never talk to this tracker again
				announce_entry* ae = find_tracker(r);
				if (ae) ae->fail_limit = 1;
			}

		}
		// announce to the next working tracker
		if (/*(!m_abort && !is_paused()) ||*/ r.event == tracker_request::stopped)
			announce_with_tracker(r.event);
		update_tracker_timer(time_now());
	}


#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
	void torrent::debug_log(const char* fmt, ...) const
	{
		if (!m_ses.m_logger) return;

		va_list v;	
		va_start(v, fmt);
	
		char usr[1024];
		vsnprintf(usr, sizeof(usr), fmt, v);
		va_end(v);
		char buf[1280];
		snprintf(buf, sizeof(buf), "%s: %s: %s\n", time_now_string()
			, to_hex(info_hash().to_string()).substr(0, 6).c_str(), usr);
		(*m_ses.m_logger) << buf;
	}
#endif

}

