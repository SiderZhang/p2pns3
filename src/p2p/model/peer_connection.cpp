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

#include <vector>
#include <boost/limits.hpp>
#include <boost/bind.hpp>
#include <stdarg.h> // for va_start, va_end

#include "libtorrent/peer_connection.hpp"
#include "libtorrent/identify_client.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/invariant_check.hpp"
#include "libtorrent/io.hpp"
#include "libtorrent/file.hpp"
#include "libtorrent/version.hpp"
#include "libtorrent/extensions.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/policy.hpp"
#include "libtorrent/assert.hpp"
#include "libtorrent/torrent.hpp"
#include "libtorrent/peer_info.hpp"
#include "libtorrent/bt_peer_connection.hpp"
#include "libtorrent/error.hpp"
#include "libtorrent/broadcast_socket.hpp"
#include <sstream>

#include "ns3/packet.h"
#include "ns3/peerHeader.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

using namespace ns3;

#ifdef TORRENT_DEBUG
#include <set>
#endif

//#define TORRENT_CORRUPT_DATA

using namespace std;
using boost::shared_ptr;
using libtorrent::aux::session_impl;
using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Peer_Connection");

namespace libtorrent
{
	int round_up8(int v)
	{
		return ((v & 7) == 0) ? v : v + (8 - (v & 7));
	}

#if defined TORRENT_REQUEST_LOGGING
	void write_request_log(FILE* f, sha1_hash const& ih
		, peer_connection* p, peer_request const& r)
	{
		// the event format in the log is:
		// uint64_t timestamp (microseconds)
		// uint64_t info-hash prefix
		// uint32_t peer identifier
		// uint32_t piece
		// uint32_t start offset
		// uint32_t length
		char event[32];
		char* ptr = event;
		detail::write_uint64(total_microseconds((time_now_hires() - min_time())), ptr);
		memcpy(ptr, &ih[0], 8);
		ptr += 8;
		detail::write_uint32(boost::uint32_t(p), ptr);
		detail::write_uint32(r.piece, ptr);
		detail::write_uint32(r.start, ptr);
		detail::write_uint32(r.length, ptr);

		int ret = fwrite(event, 1, sizeof(event), f);
		if (ret != sizeof(event))
		{
			fprintf(stderr, "ERROR writing to request log: (%d) %s\n"
				, errno, strerror(errno));
		}
	}
#endif

	// outbound connection
	peer_connection::peer_connection(
		session_impl& ses
        , ns3::Ipv4Address& addr 
		, boost::shared_ptr<torrent> tor
        , Ptr<ns3::Socket> s
        , ns3::Ipv4EndPoint const& endp
		, policy::peer* peerinfo
		, bool outgoing)
		:
#ifdef TORRENT_DEBUG
		m_last_choke(time_now() - hours(1))
		,
#endif
		  m_ses(ses)
		, m_max_out_request_queue(m_ses.settings().max_out_request_queue)
		, m_last_piece(time_now())
		, m_last_request(time_now())
		, m_last_incoming_request(min_time())
		, m_last_unchoke(time_now())
		, m_last_unchoked(time_now())
		, m_last_receive(time_now())
		, m_last_sent(time_now())
		, m_requested(min_time())
		, m_remote_dl_update(time_now())
		, m_connect(time_now())
		, m_became_uninterested(time_now())
		, m_became_uninteresting(time_now())
		, m_free_upload(0)
		, m_downloaded_at_last_round(0)
		, m_uploaded_at_last_round(0)
		, m_uploaded_at_last_unchoke(0)
		//, m_disk_recv_buffer(ses, 0)
		, m_remote(endp)
		, m_torrent(tor)
		, m_receiving_block(piece_block::invalid)
		, m_last_seen_complete(0)
		, m_timeout_extend(0)
		, m_outstanding_bytes(0)
		, m_extension_outstanding_bytes(0)
		, m_queued_time_critical(0)
		, m_num_pieces(0)
		, m_timeout(m_ses.settings().peer_timeout)
		, m_packet_size(0)
		, m_soft_packet_size(0)
		, m_recv_pos(0)
		//, m_disk_recv_buffer_size(0)
		//, m_reading_bytes(0)
		, m_num_invalid_requests(0)
		, m_priority(1)
		, m_upload_limit(0)
		, m_download_limit(0)
		, m_peer_info(peerinfo)
		, m_speed(slow)
		, m_connection_ticket(-1)
		, m_superseed_piece(-1)
		, m_remote_bytes_dled(0)
		, m_remote_dl_rate(0)
		, m_outstanding_writing_bytes(0)
		, m_download_rate_peak(0)
		, m_upload_rate_peak(0)
		, m_rtt(0)
		, m_prefer_whole_pieces(0)
		, m_desired_queue_size(2)
		, m_choke_rejects(0)
		, m_fast_reconnect(false)
		, m_outgoing(outgoing)
		, m_received_listen_port(false)
		, m_peer_interested(false)
		, m_peer_choked(true)
		, m_interesting(false)
		, m_choked(true)
		, m_failed(false)
		, m_ignore_bandwidth_limits(false)
		, m_ignore_unchoke_slots(false)
		, m_have_all(false)
		, m_disconnecting(false)
		, m_connecting(outgoing)
		, m_queued(outgoing)
		, m_request_large_blocks(false)
		, m_share_mode(false)
		, m_upload_only(false)
		, m_snubbed(false)
		, m_bitfield_received(false)
		, m_no_download(false)
		, m_endgame_mode(false)
		, m_sent_suggests(false)
		, m_ignore_stats(false)
		//, m_corked(false)
		, m_has_metadata(true)
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		, m_in_constructor(true)
		, m_disconnect_started(false)
		, m_initialized(false)
		, m_in_use(1337)
		, m_received_in_piece(0)
#endif
	{
		m_socket = s;
        ip = addr;
        if (m_torrent == boost::shared_ptr<torrent>())
        {
            NS_LOG_ERROR("not right");
        }
		boost::shared_ptr<torrent> t = m_torrent;
		// if t is NULL, we better not be connecting, since
		// we can't decrement the connecting counter
		TORRENT_ASSERT(t || !m_connecting);
		if (m_connecting && t) t->inc_num_connecting();

		m_channel_state[upload_channel] = peer_info::bw_idle;
		m_channel_state[download_channel] = peer_info::bw_idle;

		m_quota[0] = 0;
		m_quota[1] = 0;

        int num_piece = m_torrent->torrent_file().num_pieces();
        m_have_piece.resize(num_piece, m_have_all);

		TORRENT_ASSERT(peerinfo == 0 || peerinfo->banned == false);
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
        // TODO: 暂时禁用log
		/*error_code ec;
		m_logger = m_ses.create_log(m_remote.GetPeerAddress().to_string(ec) + "_"
			+ to_string(m_remote.port()).elems, m_ses.listen_port());
        // TODO: 禁用boost::asio
	    *peer_log("%s [ ep: %s type: %s seed: %d p: %p local: %s]"
			, m_outgoing ? ">>> OUTGOING_CONNECTION" : "<<< INCOMING CONNECTION"
			, print_endpoint(m_remote).c_str()
			, m_socket->type_name()
			, m_peer_info ? m_peer_info->seed : 0, m_peer_info
			, print_endpoint(m_socket->local_endpoint(ec)).c_str());*/
#endif
#ifdef TORRENT_DEBUG
		piece_failed = false;
#endif
		std::fill(m_peer_id.begin(), m_peer_id.end(), 0);
	}

	// incoming connection
	peer_connection::peer_connection(
		session_impl& ses
        , ns3::Ipv4Address& addr
        , Ptr<Socket> s
        , ns3::Ipv4EndPoint const& endp
		, policy::peer* peerinfo)
		:
#ifdef TORRENT_DEBUG
		m_last_choke(time_now() - hours(1))
		,
#endif
		  m_ses(ses)
		, m_max_out_request_queue(m_ses.settings().max_out_request_queue)
		, m_last_piece(time_now())
		, m_last_request(time_now())
		, m_last_incoming_request(min_time())
		, m_last_unchoke(time_now())
		, m_last_unchoked(time_now())
		, m_last_receive(time_now())
		, m_last_sent(time_now())
		, m_requested(min_time())
		, m_remote_dl_update(time_now())
		, m_connect(time_now())
		, m_became_uninterested(time_now())
		, m_became_uninteresting(time_now())
		, m_free_upload(0)
		, m_downloaded_at_last_round(0)
		, m_uploaded_at_last_round(0)
		, m_uploaded_at_last_unchoke(0)
		//, m_disk_recv_buffer(ses, 0)
		, m_remote(endp)
		, m_receiving_block(piece_block::invalid)
		, m_last_seen_complete(0)
		, m_timeout_extend(0)
		, m_outstanding_bytes(0)
		, m_extension_outstanding_bytes(0)
		, m_queued_time_critical(0)
		, m_num_pieces(0)
		, m_timeout(m_ses.settings().peer_timeout)
		, m_packet_size(0)
		, m_soft_packet_size(0)
		, m_recv_pos(0)
		//, m_disk_recv_buffer_size(0)
		//, m_reading_bytes(0)
		, m_num_invalid_requests(0)
		, m_priority(1)
		, m_upload_limit(0)
		, m_download_limit(0)
		, m_peer_info(peerinfo)
		, m_speed(slow)
		, m_connection_ticket(-1)
		, m_superseed_piece(-1)
		, m_remote_bytes_dled(0)
		, m_remote_dl_rate(0)
		, m_outstanding_writing_bytes(0)
		, m_download_rate_peak(0)
		, m_upload_rate_peak(0)
		, m_rtt(0)
		, m_prefer_whole_pieces(0)
		, m_desired_queue_size(2)
		, m_choke_rejects(0)
		, m_fast_reconnect(false)
		, m_outgoing(false)
		, m_received_listen_port(false)
		, m_peer_interested(false)
		, m_peer_choked(true)
		, m_interesting(false)
		, m_choked(true)
		, m_failed(false)
		, m_ignore_bandwidth_limits(false)
		, m_ignore_unchoke_slots(false)
		, m_have_all(false)
		, m_disconnecting(false)
		, m_connecting(false)
		, m_queued(false)
		, m_request_large_blocks(false)
		, m_share_mode(false)
		, m_upload_only(false)
		, m_snubbed(false)
		, m_bitfield_received(false)
		, m_no_download(false)
		, m_endgame_mode(false)
		, m_sent_suggests(false)
		, m_ignore_stats(false)
		, m_has_metadata(true)
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		, m_in_constructor(true)
		, m_disconnect_started(false)
		, m_initialized(false)
		, m_in_use(1337)
		, m_received_in_piece(0)
#endif
	{
		m_socket = s;
        ip = addr;

		m_channel_state[upload_channel] = peer_info::bw_idle;
		m_channel_state[download_channel] = peer_info::bw_idle;

		m_quota[0] = 0;
		m_quota[1] = 0;

        // TODO: 禁用boost::asio
/*
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
		error_code ec;
		TORRENT_ASSERT(m_socket->remote_endpoint(ec) == m_remote || ec);
		m_logger = m_ses.create_log(remote().address().to_string(ec) + "_"
			+ to_string(remote().port()).elems, m_ses.listen_port());
		peer_log("%s [ ep: %s type: %s local: %s]"
			, m_outgoing ? ">>> OUTGOING_CONNECTION" : "<<< INCOMING CONNECTION"
			, print_endpoint(m_remote).c_str()
			, m_socket->type_name()
			, print_endpoint(m_socket->local_endpoint(ec)).c_str());
#endif*/
		
#ifdef TORRENT_DEBUG
		piece_failed = false;
#endif
		std::fill(m_peer_id.begin(), m_peer_id.end(), 0);
	}

#ifdef TORRENT_DISK_STATS
	void peer_connection::log_buffer_usage(char* buffer, int size, char const* label)
	{
		if (m_ses.m_disk_thread.is_disk_buffer(buffer))
			m_ses.m_disk_thread.rename_buffer(buffer, label);
	
		m_ses.m_buffer_usage_logger << log_time() << " append_send_buffer: " << size << std::endl;
		m_ses.log_buffer_usage();
	}
#endif

	bool peer_connection::bittyrant_unchoke_compare(
		boost::intrusive_ptr<peer_connection const> const& p) const
	{
		TORRENT_ASSERT(p);
		peer_connection const& rhs = *p;

		size_type d1, d2, u1, u2;

		// first compare how many bytes they've sent us
		d1 = downloaded_in_last_round();
		d2 = rhs.downloaded_in_last_round();
		// divided by the number of bytes we've sent them
		u1 = uploaded_in_last_round();
		u2 = rhs.uploaded_in_last_round();

		boost::shared_ptr<torrent> t1 = m_torrent;
		TORRENT_ASSERT(t1);
		boost::shared_ptr<torrent> t2 = rhs.associated_torrent();
		TORRENT_ASSERT(t2);

		// take torrent priority into account
		d1 *= 1 + t1->priority();
		d2 *= 1 + t2->priority();

		d1 = d1 * 1000 / (std::max)(size_type(1), u1);
		d2 = d2 * 1000 / (std::max)(size_type(1), u2);
		if (d1 > d2) return true;
		if (d1 < d2) return false;

		// if both peers are still in their send quota or not in their send quota
		// prioritize the one that has waited the longest to be unchoked
		return m_last_unchoke < rhs.m_last_unchoke;
	}

	// return true if 'this' peer should be preferred to be unchoke over p
	bool peer_connection::unchoke_compare(boost::intrusive_ptr<peer_connection const> const& p) const
	{
		TORRENT_ASSERT(p);
		peer_connection const& rhs = *p;

		// if one peer belongs to a higher priority torrent than the other one
		// that one should be unchoked.
		boost::shared_ptr<torrent> t1 = m_torrent;
		TORRENT_ASSERT(t1);
		boost::shared_ptr<torrent> t2 = rhs.associated_torrent();
		TORRENT_ASSERT(t2);

		if (t1->priority() != t2->priority())
			return t1->priority() > t2->priority();

		// compare how many bytes they've sent us
		size_type c1;
		size_type c2;
		c1 = downloaded_in_last_round();
		c2 = rhs.downloaded_in_last_round();

		if (c1 != c2) return c1 > c2;

		if (m_ses.settings().seed_choking_algorithm == session_settings::round_robin)
		{
			// the amount uploaded since unchoked (not just in the last round)
			c1 = uploaded_since_unchoked();
			c2 = rhs.uploaded_since_unchoked();

			// the way the round-robin unchoker works is that it,
			// by default, prioritizes any peer that is already unchoked.
			// this maintain the status quo across unchoke rounds. However,
			// peers that are unchoked, but have sent more than one quota
			// since they were unchoked, they get de-prioritized.

			int pieces = m_ses.settings().seeding_piece_quota;
			// if a peer is already unchoked, and the number of bytes sent since it was unchoked
			// is greater than the send quanta, then it's done with it' upload slot, and we
			// can de-prioritize it
			bool c1_quota_complete = !is_choked() && c1 > (std::max)(t1->torrent_file().piece_length() * pieces, 256 * 1024);
			bool c2_quota_complete = !rhs.is_choked() && c2 > (std::max)(t2->torrent_file().piece_length() * pieces, 256 * 1024);

			// if c2 has completed a quanta, it shuold be de-prioritized
			// and vice versa
			if (c1_quota_complete < c2_quota_complete) return true;
			if (c1_quota_complete > c2_quota_complete) return false;

			// if both peers have either completed a quanta, or not.
			// keep unchoked peers prioritized over choked ones, to let
			// peers keep working on uploading a full quanta
			if (is_choked() < rhs.is_choked()) return true;
			if (is_choked() > rhs.is_choked()) return false;

			// if the peers are still identical (say, they're both waiting to be unchoked)
			// fall through and rely on the logic to prioritize peers who have waited
			// the longest to be unchoked
		}	
		else if (m_ses.settings().seed_choking_algorithm == session_settings::fastest_upload)
		{
			c1 = uploaded_in_last_round();
			c2 = rhs.uploaded_in_last_round();
		
			// take torrent priority into account
			c1 *= 1 + t1->priority();
			c2 *= 1 + t2->priority();

			if (c1 > c2) return true;
			if (c2 > c1) return false;
		}
		else if (m_ses.settings().seed_choking_algorithm == session_settings::anti_leech)
		{
			// the anti-leech seeding algorithm is based on the paper "Improving
			// BitTorrent: A Simple Approach" from Chow et. al. and ranks peers based
			// on how many pieces they have, prefering to unchoke peers that just
			// started and peers that are close to completing. Like this:
			//   ^
			//   | \                       / |
			//   |  \                     /  |
			//   |   \                   /   |
			// s |    \                 /    |
			// c |     \               /     |
			// o |      \             /      |
			// r |       \           /       |
			// e |        \         /        |
			//   |         \       /         |
			//   |          \     /          |
			//   |           \   /           |
			//   |            \ /            |
			//   |             V             |
			//   +---------------------------+
			//   0%    num have pieces     100%
			int t1_total = t1->torrent_file().num_pieces();
			int t2_total = t2->torrent_file().num_pieces();
			int score1 = (num_have_pieces() < t1_total / 2
				? t1_total - num_have_pieces() : num_have_pieces()) * 1000 / t1_total;
			int score2 = (rhs.num_have_pieces() < t2_total / 2
				? t2_total - rhs.num_have_pieces() : rhs.num_have_pieces()) * 1000 / t2_total;
			if (score1 > score2) return true;
			if (score2 > score1) return false;
		}
		
		// prioritize the one that has waited the longest to be unchoked
		// the round-robin unchoker relies on this logic. Don't change it
		// without moving this into that unchoker logic
		return m_last_unchoke < rhs.m_last_unchoke;
	}

	bool peer_connection::upload_rate_compare(peer_connection const* p) const
	{
		size_type c1;
		size_type c2;

		boost::shared_ptr<torrent> t1 = m_torrent;
		TORRENT_ASSERT(t1);
		boost::shared_ptr<torrent> t2 = p->associated_torrent();
		TORRENT_ASSERT(t2);

		c1 = uploaded_in_last_round();
		c2 = p->uploaded_in_last_round();
		
		// take torrent priority into account
		c1 *= 1 + t1->priority();
		c2 *= 1 + t2->priority();

		return c1 > c2;
	}

	void peer_connection::reset_choke_counters()
	{
		m_downloaded_at_last_round= m_statistics.total_payload_download();
		m_uploaded_at_last_round = m_statistics.total_payload_upload();
	}

	void peer_connection::start()
	{
        NS_LOG_IP_FUNCTION(ip,this);

		if (!m_outgoing)
        {
            m_socket->SetRecvCallback(MakeCallback (&peer_connection::setup_packet_receive, this));
            setup_packet_receive(m_socket);
        }

		boost::shared_ptr<torrent> t = m_torrent;
        if (t)
        {
	        //init();
        }
	}

	void peer_connection::update_interest()
	{
		boost::shared_ptr<torrent> t = m_torrent;
		if (!t) return;

		// if m_have_piece is 0, it means the connections
		// have not been initialized yet. The interested
		// flag will be updated once they are.
		if (m_have_piece.size() == 0) return;

		bool interested = false;
		if (!t->is_upload_only())
		{
			piece_picker const& p = t->picker();
			int num_pieces = p.num_pieces();
			for (int j = 0; j != num_pieces; ++j)
			{
				if (!p.have_piece(j)
					&& t->piece_priority(j) > 0
					&& m_have_piece[j])
				{
					interested = true;
					break;
				}
			}
		}
		if (!interested) send_not_interested();
		else t->get_policy().peer_is_interesting(*this);

		TORRENT_ASSERT(in_handshake() || is_interesting() == interested);
	}

	void peer_connection::peer_log(char const* fmt, ...) const
	{
		va_list v;	
		va_start(v, fmt);
	
		char usr[400];
		vsnprintf(usr, sizeof(usr), fmt, v);
		va_end(v);
		char buf[450];
		snprintf(buf, sizeof(buf), "%s: %s\n", time_now_string(), usr);
        NS_LOG_IP_INFO(ip, buf);
	}

	void peer_connection::send_allowed_set()
	{
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		if (t->super_seeding())
		{
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("*** SKIPPING ALLOWED SET BECAUSE OF SUPER SEEDING");
#endif
			return;
		}

		if (upload_only())
		{
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("*** SKIPPING ALLOWED SET BECAUSE PEER IS UPLOAD ONLY");
#endif
			return;
		}

		int num_allowed_pieces = m_ses.settings().allowed_fast_set_size;
		if (num_allowed_pieces == 0) return;

		int num_pieces = t->torrent_file().num_pieces();

		if (num_allowed_pieces >= num_pieces)
		{
			// this is a special case where we have more allowed
			// fast pieces than pieces in the torrent. Just send
			// an allowed fast message for every single piece
			for (int i = 0; i < num_pieces; ++i)
			{
				// there's no point in offering fast pieces
				// that the peer already has
				if (has_piece(i)) continue;

#ifdef TORRENT_VERBOSE_LOGGING
				peer_log("==> ALLOWED_FAST [ %d ]", i);
#endif
				write_allow_fast(i);
				TORRENT_ASSERT(std::find(m_accept_fast.begin()
					, m_accept_fast.end(), i)
					== m_accept_fast.end());
				if (m_accept_fast.empty())
				{
					m_accept_fast.reserve(10);
					m_accept_fast_piece_cnt.reserve(10);
				}
				m_accept_fast.push_back(i);
				m_accept_fast_piece_cnt.push_back(0);
			}
			return;
		}

		std::string x;
		/*Ipv4Address const& addr = m_remote.GetPeerAddress();
        // TODO: 临时禁用boost::asio
		//address_v4::bytes_type bytes = addr.to_v4().to_bytes();
		//x.assign((char*)&bytes[0], bytes.size());
		*/
		x.append((char*)&t->torrent_file().info_hash()[0], 20);

		sha1_hash hash = hasher(x.c_str(), x.size()).final();
		for (;;)
		{
			char* p = (char*)&hash[0];
			for (int i = 0; i < 5; ++i)
			{
				int piece = detail::read_uint32(p) % num_pieces;
				if (std::find(m_accept_fast.begin(), m_accept_fast.end(), piece)
					== m_accept_fast.end())
				{
#ifdef TORRENT_VERBOSE_LOGGING
					peer_log("==> ALLOWED_FAST [ %d ]", piece);
#endif
					write_allow_fast(piece);
					if (m_accept_fast.empty())
					{
						m_accept_fast.reserve(10);
						m_accept_fast_piece_cnt.reserve(10);
					}
					m_accept_fast.push_back(piece);
					m_accept_fast_piece_cnt.push_back(0);
					if (int(m_accept_fast.size()) >= num_allowed_pieces
						|| int(m_accept_fast.size()) == num_pieces) return;
				}
			}
			hash = hasher((char*)&hash[0], 20).final();
		}
	}

	void peer_connection::on_metadata_impl()
	{
		boost::shared_ptr<torrent> t = associated_torrent();
		m_have_piece.resize(t->torrent_file().num_pieces(), m_have_all);
		m_num_pieces = m_have_piece.count();

		// now that we know how many pieces there are
		// remove any invalid allowed_fast and suggest pieces
		// now that we know what the number of pieces are
		for (std::vector<int>::iterator i = m_allowed_fast.begin();
			i != m_allowed_fast.end();)
		{
			if (*i < m_num_pieces)
			{
				++i;
				continue;
			}
			i = m_allowed_fast.erase(i);
		}

		for (std::vector<int>::iterator i = m_suggested_pieces.begin();
			i != m_suggested_pieces.end();)
		{
			if (*i < m_num_pieces)
			{
				++i;
				continue;
			}
			i = m_suggested_pieces.erase(i);
		}
		
		if (m_num_pieces == int(m_have_piece.size()))
		{
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("*** on_metadata(): THIS IS A SEED [ p: %p ]", m_peer_info);
#endif
			// if this is a web seed. we don't have a peer_info struct
			t->get_policy().set_seed(m_peer_info, true);
			m_upload_only = true;

			t->peer_has_all();
			disconnect_if_redundant();
			if (m_disconnecting) return;

			on_metadata();
			if (m_disconnecting) return;

			if (!t->is_upload_only())
				t->get_policy().peer_is_interesting(*this);

			return;
		}
		TORRENT_ASSERT(!m_have_all);

		on_metadata();
		if (m_disconnecting) return;

		disconnect_if_redundant();
		if (m_disconnecting) return;

		// let the torrent know which pieces the
		// peer has
		// if we're a seed, we don't keep track of piece availability
		bool interesting = false;
		if (!t->is_seed())
		{
			t->peer_has(m_have_piece);

			for (int i = 0; i < (int)m_have_piece.size(); ++i)
			{
				if (!m_have_piece[i]) continue;
				if (t->have_piece(i) || t->picker().piece_priority(i) == 0) continue;
				interesting = true;
				break;
			}
		}

		if (interesting) t->get_policy().peer_is_interesting(*this);
		else if (upload_only()) disconnect(errors::upload_upload_connection);
	}

	void peer_connection::init()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(m_torrent);
        
        if (m_connecting)
            return;

		if (m_have_all)
            m_num_pieces = m_torrent->torrent_file().num_pieces();
		// now that we have a piece_picker,
		// update it with this peer's pieces

		if (m_num_pieces == int(m_have_piece.size()))
		{
			NS_LOG_IP_INFO(ip,"*** THIS IS A SEED [ p: "<< m_peer_info << " ]");
			// if this is a web seed. we don't have a peer_info struct
			m_torrent->get_policy().set_seed(m_peer_info, true);
			m_upload_only = true;

			m_torrent->peer_has_all();
			if (m_torrent->is_upload_only())
                send_not_interested();
			else
                m_torrent->get_policy().peer_is_interesting(*this);
			return;
		}

		// if we're a seed, we don't keep track of piece availability
		if (!m_torrent->is_seed())
		{
			m_torrent->peer_has(m_have_piece);
			bool interesting = false;
			for (int i = 0; i < int(m_have_piece.size()); ++i)
			{
				if (m_have_piece[i])
				{
					// if the peer has a piece and we don't, the peer is interesting
					if (!m_torrent->have_piece(i)
						&& m_torrent->picker().piece_priority(i) != 0)
						interesting = true;
				}
			}
			if (interesting)
            {
                m_torrent->get_policy().peer_is_interesting(*this);
            }
			else
            {
                send_not_interested();
            }
		}
		else
		{
			update_interest();
		}
	}

	peer_connection::~peer_connection()
	{
//		INVARIANT_CHECK;
		TORRENT_ASSERT(!m_in_constructor);
		TORRENT_ASSERT(m_disconnecting);
		TORRENT_ASSERT(m_disconnect_started);
		TORRENT_ASSERT(m_ses.is_network_thread());

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_in_use = 0;
#endif

		// defensive

		boost::shared_ptr<torrent> t = m_torrent;
		// if t is NULL, we better not be connecting, since
		// we can't decrement the connecting counter
		TORRENT_ASSERT(t || !m_connecting);

		// we should really have dealt with this already
		TORRENT_ASSERT(!m_connecting);
		if (m_connecting && t)
		{
			t->dec_num_connecting();
			m_connecting = false;
		}

		//m_disk_recv_buffer_size = 0;

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
		peer_log("*** CONNECTION CLOSED");
#endif
//		TORRENT_ASSERT(!m_ses.has_peer(this));
		TORRENT_ASSERT(m_request_queue.empty());
		TORRENT_ASSERT(m_download_queue.empty());
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		for (aux::session_impl::torrent_map::const_iterator i = m_ses.m_torrents.begin()
			, end(m_ses.m_torrents.end()); i != end; ++i)
			TORRENT_ASSERT(!i->second->has_peer(this));
		if (m_peer_info)
			TORRENT_ASSERT(m_peer_info->connection == 0);
#endif
	}

//	int peer_connection::picker_options() const
//	{
//		int ret = 0; 
//		boost::shared_ptr<torrent> t = m_torrent;
//		TORRENT_ASSERT(t);
//		if (!t) return 0;
//
//		if (t->is_sequential_download())
//		{
//			ret |= piece_picker::sequential | piece_picker::ignore_whole_pieces;
//		}
//		else if (t->num_have() < t->settings().initial_picker_threshold)
//		{
//			// if we have fewer pieces than a certain threshols
//			// don't pick rare pieces, just pick random ones,
//			// and prioritize finishing them
//			ret |= piece_picker::prioritize_partials;
//		}
//		else
//		{
//			ret |= piece_picker::rarest_first | piece_picker::speed_affinity;
//		}
//
//		if (m_snubbed)
//		{
//			// snubbed peers should request
//			// the common pieces first, just to make
//			// it more likely for all snubbed peers to
//			// request blocks from the same piece
//			ret |= piece_picker::reverse;
//		}
//
//		if (t->settings().prioritize_partial_pieces)
//			ret |= piece_picker::prioritize_partials;
//
//		if (on_parole()) ret |= piece_picker::on_parole
//			| piece_picker::prioritize_partials;
//
//		// only one of rarest_first, common_first and sequential can be set.
//		TORRENT_ASSERT((ret & piece_picker::rarest_first) ? 1 : 0
//			+ (ret & piece_picker::sequential) ? 1 : 0 <= 1);
//		return ret;
//	}

//	void peer_connection::fast_reconnect(bool r)
//	{
//		if (!peer_info_struct() || peer_info_struct()->fast_reconnects > 1)
//			return;
//		m_fast_reconnect = r;
//		peer_info_struct()->last_connected = m_ses.session_time();
//		int rewind = m_ses.settings().min_reconnect_time * m_ses.settings().max_failcount;
//		if (peer_info_struct()->last_connected < rewind) peer_info_struct()->last_connected = 0;
//		else peer_info_struct()->last_connected -= rewind;
//
//		if (peer_info_struct()->fast_reconnects < 15)
//			++peer_info_struct()->fast_reconnects;
//	}

	void peer_connection::announce_piece(int index)
	{
		// dont announce during handshake
		if (in_handshake()) return;

		// remove suggested pieces once we have them
		std::vector<int>::iterator i = std::find(
			m_suggested_pieces.begin(), m_suggested_pieces.end(), index);
		if (i != m_suggested_pieces.end()) m_suggested_pieces.erase(i);

		// remove allowed fast pieces
		i = std::find(m_allowed_fast.begin(), m_allowed_fast.end(), index);
		if (i != m_allowed_fast.end()) m_allowed_fast.erase(i);

		if (has_piece(index))
		{
			// if we got a piece that this peer has
			// it might have been the last interesting
			// piece this peer had. We might not be
			// interested anymore
			update_interest();
			if (is_disconnecting()) return;

			// optimization, don't send have messages
			// to peers that already have the piece
			if (!m_ses.settings().send_redundant_have)
			{
				peer_log("==> HAVE    [ piece: %d ] SUPRESSED", index);
				return;
			}
		}

		peer_log("==> HAVE    [ piece: %d ]", index);

		write_have(index);
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);
#endif
	}

	bool peer_connection::has_piece(int i) const
	{
		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);
		TORRENT_ASSERT(i >= 0);
		TORRENT_ASSERT(i < t->torrent_file().num_pieces());
		return m_have_piece[i];
	}

	std::vector<pending_block> const& peer_connection::request_queue() const
	{
		return m_request_queue;
	}
	
	std::vector<pending_block> const& peer_connection::download_queue() const
	{
		return m_download_queue;
	}
	
	std::vector<peer_request> const& peer_connection::upload_queue() const
	{
		return m_requests;
	}

	time_duration peer_connection::download_queue_time(int extra_bytes) const
	{
		int rate = m_statistics.transfer_rate(stat::download_payload)
			+ m_statistics.transfer_rate(stat::download_protocol);
		// avoid division by zero
		if (rate < 50) rate = 50;
		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);
		return seconds((m_outstanding_bytes + m_queued_time_critical * t->block_size()) / rate);
	}

	void peer_connection::add_stat(size_type downloaded, size_type uploaded)
	{
		m_statistics.add_stat(downloaded, uploaded);
	}

	bitfield const& peer_connection::get_bitfield() const
	{
		return m_have_piece;
	}

    // TODO: remove these empty functions
	void peer_connection::received_valid_data(int index)
	{
		// this fails because we haven't had time to disconnect
		// seeds yet, and we might have just become one
//		INVARIANT_CHECK;
	}

	void peer_connection::received_invalid_data(int index)
	{
		INVARIANT_CHECK;
	}
	
	size_type peer_connection::total_free_upload() const
	{
		return m_free_upload;
	}

	void peer_connection::add_free_upload(size_type free_upload)
	{
		INVARIANT_CHECK;

		m_free_upload += free_upload;
	}

	// verifies a piece to see if it is valid (is within a valid range)
	// and if it can correspond to a request generated by libtorrent.
	bool peer_connection::verify_piece(const peer_request& p) const
	{
		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		torrent_info const& ti = t->torrent_file();

		return p.piece >= 0
			&& p.piece < ti.num_pieces()
			&& p.start >= 0
			&& p.start < ti.piece_length()
			&& t->to_req(piece_block(p.piece, p.start / t->block_size())) == p;
	}

	void peer_connection::attach_to_torrent(sha1_hash const& ih, bool allow_encrypted)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(!m_disconnecting);
		TORRENT_ASSERT(m_torrent.expired());
		boost::shared_ptr<torrent> wpt = m_ses.find_torrent(ih);
		boost::shared_ptr<torrent> t = wpt;

        int num_piece = t->torrent_file().num_pieces();
        m_have_piece.resize(num_piece, m_have_all);

		if (t && t->is_aborted())
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** the torrent has been aborted");
#endif
			t.reset();
		}

		if (!t)
		{
			// we couldn't find the torrent!
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** couldn't find a torrent with the given info_hash: %s torrents:", to_hex(ih.to_string()).c_str());
			session_impl::torrent_map const& torrents = m_ses.m_torrents;
			for (session_impl::torrent_map::const_iterator i = torrents.begin()
				, end(torrents.end()); i != end; ++i)
			{
				peer_log("   %s", to_hex(i->second->torrent_file().info_hash().to_string()).c_str());
			}
#endif
			disconnect(errors::invalid_info_hash, 1);
			return;
		}

//		if (/*t->is_paused() &&*/ 
//			!m_ses.m_settings.incoming_starts_queued_torrents)
//		{
//			// paused torrents will not accept
//			// incoming connections unless they are auto managed
//			// and inconing_starts_queued_torrents is true
//			// torrents that have errors should always reject
//			// incoming peers
//#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
//			peer_log("rejected connection to paused torrent");
//#endif
//			disconnect(errors::torrent_paused, 2);
//			return;
//		}

		TORRENT_ASSERT(m_torrent.expired());

        // TODO: 禁用VCR操作
/*		if (t->is_paused()
			&& m_ses.m_settings.incoming_starts_queued_torrents
			&& !m_ses.is_paused()
			&& !t->is_aborted()
			&& !m_ses.is_aborted())
		{
			t->resume();
		}*/

		// check to make sure we don't have another connection with the same
		// info_hash and peer_id. If we do. close this connection.
		t->attach_peer(this);
		if (m_disconnecting) return;
		m_torrent = wpt;

		TORRENT_ASSERT(!m_torrent.expired());

		// if the torrent isn't ready to accept
		// connections yet, we'll have to wait with
		// our initialization
		//init();

		TORRENT_ASSERT(!m_torrent.expired());

		// assume the other end has no pieces
		// if we don't have valid metadata yet,
		// leave the vector unallocated
		TORRENT_ASSERT(m_num_pieces == 0);
		m_have_piece.clear_all();
		TORRENT_ASSERT(!m_torrent.expired());
	}

	// message handlers

	// -----------------------------
	// --------- KEEPALIVE ---------
	// -----------------------------

	void peer_connection::incoming_keepalive()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== KEEPALIVE");
#endif
	}

	// -----------------------------
	// ----------- CHOKE -----------
	// -----------------------------

	void peer_connection::incoming_choke()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		if (is_disconnecting()) return;

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== CHOKE");
#endif
		m_peer_choked = true;
		set_endgame(false);

		clear_request_queue();
	}

	void peer_connection::clear_request_queue()
	{
		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		// clear the requests that haven't been sent yet
		if (peer_info_struct() == 0 || !peer_info_struct()->on_parole)
		{
			// if the peer is not in parole mode, clear the queued
			// up block requests
			if (!t->is_seed())
			{
				piece_picker& p = t->picker();
				for (std::vector<pending_block>::const_iterator i = m_request_queue.begin()
					, end(m_request_queue.end()); i != end; ++i)
				{
					p.abort_download(i->block, peer_info_struct());
				}
			}
			m_request_queue.clear();
			m_queued_time_critical = 0;
		}
	}

	bool match_request(peer_request const& r, piece_block const& b, int block_size)
	{
		if (int(b.piece_index) != r.piece) return false;
		if (int(b.block_index) != r.start / block_size) return false;
		if (r.start % block_size != 0) return false;
		return true;
	}

	// -----------------------------
	// -------- REJECT PIECE -------
	// -----------------------------

	void peer_connection::incoming_reject_request(peer_request const& r)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		if (is_disconnecting()) return;

		std::vector<pending_block>::iterator i = std::find_if(
			m_download_queue.begin(), m_download_queue.end()
			, boost::bind(match_request, boost::cref(r), boost::bind(&pending_block::block, _1)
			, t->block_size()));
	
		peer_log("<== REJECT_PIECE [ piece: %d | s: %d | l: %d ]"
			, r.piece, r.start, r.length);

        // 从下载队列中删除不需要的数据
		if (i != m_download_queue.end())
		{
			pending_block b = *i;
			bool remove_from_picker = !i->timed_out && !i->not_wanted;
			m_download_queue.erase(i);
			TORRENT_ASSERT(m_outstanding_bytes >= r.length);
			m_outstanding_bytes -= r.length;
			if (m_outstanding_bytes < 0) m_outstanding_bytes = 0;
			
			// if the peer is in parole mode, keep the request
			if (peer_info_struct() && peer_info_struct()->on_parole)
			{
				// we should only add it if the block is marked as
				// busy in the piece-picker
				if (remove_from_picker)
					m_request_queue.insert(m_request_queue.begin(), b);
			}
			else if (!t->is_seed() && remove_from_picker)
			{
				piece_picker& p = t->picker();
				p.abort_download(b.block, peer_info_struct());
			}
#if !defined TORRENT_DISABLE_INVARIANT_CHECKS && defined TORRENT_DEBUG
			check_invariant();
#endif
		}
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
		else
		{
			peer_log("*** PIECE NOT IN REQUEST QUEUE");
		}
#endif
		if (has_peer_choked())
		{
			// if we're choked and we got a rejection of
			// a piece in the allowed fast set, remove it
			// from the allow fast set.
			std::vector<int>::iterator i = std::find(
				m_allowed_fast.begin(), m_allowed_fast.end(), r.piece);
			if (i != m_allowed_fast.end()) m_allowed_fast.erase(i);
		}
		else
		{
			std::vector<int>::iterator i = std::find(m_suggested_pieces.begin()
				, m_suggested_pieces.end(), r.piece);
			if (i != m_suggested_pieces.end())
				m_suggested_pieces.erase(i);
		}

		if (m_request_queue.empty() && m_download_queue.size() < 2)
		{
#ifdef TORRENT_STATS
			++m_ses.m_reject_piece_picks;
#endif
			request_a_block(*t, *this);
			send_block_requests();
		}
	}
	
	// -----------------------------
	// ------- SUGGEST PIECE -------
	// -----------------------------

	void peer_connection::incoming_suggest(int index)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== SUGGEST_PIECE [ piece: %d ]", index);
#endif
		boost::shared_ptr<torrent> t = m_torrent;
		if (!t) return;

		if (is_disconnecting()) return;
		if (index < 0)
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("<== INVALID_SUGGEST_PIECE [ %d ]", index);
#endif
			return;
		}
		
			if (index >= int(m_have_piece.size()))
			{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
				peer_log("<== INVALID_ALLOWED_FAST [ %d | s: %d ]"
					, index, int(m_have_piece.size()));
#endif
				return;
			}

			// if we already have the piece, we can
			// ignore this message
			if (t->have_piece(index))
				return;

		if (int(m_suggested_pieces.size()) > m_ses.m_settings.max_suggest_pieces)
			m_suggested_pieces.erase(m_suggested_pieces.begin());

		m_suggested_pieces.push_back(index);

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("** SUGGEST_PIECE [ piece: %d added to set: %d ]", index, int(m_suggested_pieces.size()));
#endif
	}

	// -----------------------------
	// ---------- UNCHOKE ----------
	// -----------------------------

	void peer_connection::incoming_unchoke()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		NS_LOG_IP_INFO(ip, "<== UNCHOKE");

		m_peer_choked = false;
		m_last_unchoked = time_now();
		if (is_disconnecting())
            return;

        t->get_policy().peer_is_interesting(*this);
		if (is_interesting())
		{
#ifdef TORRENT_STATS
			++m_ses.m_unchoke_piece_picks;
#endif
			request_a_block(*t, *this);
			send_block_requests();
		}
	}

	// -----------------------------
	// -------- INTERESTED ---------
	// -----------------------------

	void peer_connection::incoming_interested()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== INTERESTED");
#endif
		m_peer_interested = true;
		if (is_disconnecting()) return;
	
		// if the peer is ready to download stuff, it must have metadata		
		m_has_metadata = true;

		disconnect_if_redundant();
		if (is_disconnecting()) return;

		if (is_choked())
		{
			if (ignore_unchoke_slots())
			{
				// if this peer is expempted from the choker
				// just unchoke it immediately
				send_unchoke();
			}
			else if ((m_ses.num_uploads() < m_ses.settings().unchoke_slots_limit
					|| m_ses.settings().unchoke_slots_limit < 0)
				&& (t->ratio() == 0
					|| share_diff() >= size_type(-free_upload_amount)
					|| t->is_finished()))
			{
				// if the peer is choked and we have upload slots left,
				// then unchoke it. Another condition that has to be met
				// is that the torrent doesn't keep track of the individual
				// up/down ratio for each peer (ratio == 0) or (if it does
				// keep track) this particular connection isn't a leecher.
				// If the peer was choked because it was leeching, don't
				// unchoke it again.
				// The exception to this last condition is if we're a seed.
				// In that case we don't care if people are leeching, they
				// can't pay for their downloads anyway.
				m_ses.unchoke_peer(*this);
			}
#if defined TORRENT_VERBOSE_LOGGING
			else
			{
				std::string reason;
				if (m_ses.num_uploads() >= m_ses.settings().unchoke_slots_limit
					&& m_ses.settings().unchoke_slots_limit >= 0)
				{
					peer_log("DID NOT UNCHOKE [ the number of uploads (%d)"
						"is more than or equal to the limit (%d) ]"
						, m_ses.num_uploads(), m_ses.settings().unchoke_slots_limit);
				}
				else
				{
					peer_log("DID NOT UNCHOKE [ the share ratio (%d) is <= "
						"free_upload_amount (%d) and we are not seeding and the ratio (%d) is non-zero"
						, share_diff(), int(free_upload_amount), t->ratio());
				}
			}
#endif
		}
	}

	// -----------------------------
	// ------ NOT INTERESTED -------
	// -----------------------------

	void peer_connection::incoming_not_interested()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		m_became_uninterested = time_now();

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== NOT_INTERESTED");
#endif
		m_peer_interested = false;
		if (is_disconnecting()) return;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		if (!is_choked())
		{
			if (ignore_unchoke_slots())
			{
				send_choke();
			}
			else
			{
				if (m_peer_info && m_peer_info->optimistically_unchoked)
				{
					m_peer_info->optimistically_unchoked = false;
					m_ses.m_optimistic_unchoke_time_scaler = 0;
				}
				m_ses.choke_peer(*this);
				m_ses.m_unchoke_time_scaler = 0;
			}
		}

		if (t->ratio() != 0.f)
		{
			TORRENT_ASSERT(share_diff() < (std::numeric_limits<size_type>::max)());
			size_type diff = share_diff();
			if (diff > 0 && is_seed())
			{
				// the peer is a seed and has sent
				// us more than we have sent it back.
				// consider the download as free download
				t->add_free_upload(diff);
				add_free_upload(-diff);
			}
		}

		if (t->super_seeding() && m_superseed_piece != -1)
		{
			// assume the peer has the piece we're superseeding to it
			// and give it another one
		  	if (!m_have_piece[m_superseed_piece]) incoming_have(m_superseed_piece);
		}
	}

	// -----------------------------
	// ----------- HAVE ------------
	// -----------------------------

	void peer_connection::incoming_have(int index)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		if (is_disconnecting()) return;

		// if we haven't received a bitfield, it was
		// probably omitted, which is the same as 'have_none'
		if (!m_bitfield_received) incoming_have_none();

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== HAVE    [ piece: %d ]", index);
#endif

		if (is_disconnecting()) return;

		// if we got an invalid message, abort
		if (index >= int(m_have_piece.size()) || index < 0)
		{
			disconnect(errors::invalid_have, 2);
			return;
		}

		if (t->super_seeding() && !m_ses.settings().strict_super_seeding)
		{
			// if we're superseeding and the peer just told
			// us that it completed the piece we're superseeding
			// to it, change the superseeding piece for this peer
			// if the peer optimizes out redundant have messages
			// this will be handled when the peer sends not-interested
			// instead.
			if (m_superseed_piece == index)
			{
				superseed_piece(t->get_piece_to_super_seed(m_have_piece));
			}
		}

		if (m_have_piece[index])
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("   got redundant HAVE message for index: %d", index);
#endif
			return;
		}

		m_have_piece.set_bit(index);
		++m_num_pieces;

		// if the peer is downloading stuff, it must have metadata		
		m_has_metadata = true;

		t->peer_has(index);

		// this will disregard all have messages we get within
		// the first two seconds. Since some clients implements
		// lazy bitfields, these will not be reliable to use
		// for an estimated peer download rate.
		if (!peer_info_struct()
			|| m_ses.session_time() - peer_info_struct()->last_connected > 2)
		{
			// update bytes downloaded since last timer
			m_remote_bytes_dled += t->torrent_file().piece_size(index);
		}

		// it's important to not disconnect before we have
		// updated the piece picker, otherwise we will incorrectly
		// decrement the piece count without first incrementing it
		if (is_seed())
		{
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("*** THIS IS A SEED [ p: %p ]", m_peer_info);
#endif
			t->seen_complete();
			t->get_policy().set_seed(m_peer_info, true);
			m_upload_only = true;
			disconnect_if_redundant();
			if (is_disconnecting()) return;
		}

		if (!t->have_piece(index)
			&& !t->is_seed()
			&& !is_interesting()
			&& t->picker().piece_priority(index) != 0)
			t->get_policy().peer_is_interesting(*this);

		// if we're super seeding, this might mean that somebody
		// forwarded this piece. In which case we need to give
		// a new piece to that peer
		if (t->super_seeding()
			&& m_ses.settings().strict_super_seeding
			&& (index != m_superseed_piece || t->num_peers() == 1))
		{
			for (torrent::peer_iterator i = t->begin()
				, end(t->end()); i != end; ++i)
			{
				peer_connection* p = *i;
				if (p->superseed_piece() != index) continue;
				if (!p->has_piece(index)) continue;
				p->superseed_piece(t->get_piece_to_super_seed(p->get_bitfield()));
			}
		}
	}

	// -----------------------------
	// -------- DONT HAVE ----------
	// -----------------------------

	void peer_connection::incoming_dont_have(int index)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		if (is_disconnecting()) return;

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== DONT_HAVE [ piece: %d ]", index);
#endif

		if (is_disconnecting()) return;

		// if we got an invalid message, abort
		if (index >= int(m_have_piece.size()) || index < 0)
		{
			disconnect(errors::invalid_dont_have, 2);
			return;
		}

		if (!m_have_piece[index])
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("   got redundant DONT_HAVE message for index: %d", index);
#endif
			return;
		}

		bool was_seed = is_seed();
		m_have_piece.clear_bit(index);
		TORRENT_ASSERT(m_num_pieces > 0);
		--m_num_pieces;

		t->peer_lost(index);

		if (was_seed)
			t->get_policy().set_seed(m_peer_info, false);
	}

	// -----------------------------
	// --------- BITFIELD ----------
	// -----------------------------

	void peer_connection::incoming_bitfield(bitfield const& bits)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		if (is_disconnecting()) return;

#ifdef TORRENT_VERBOSE_LOGGING
		std::string bitfield_str;
		bitfield_str.resize(bits.size());
		for (int i = 0; i < int(bits.size()); ++i)
			bitfield_str[i] = bits[i] ? '1' : '0';
		peer_log("<== BITFIELD [ %s ]", bitfield_str.c_str());
#endif

		// if we don't have the metedata, we cannot
		// verify the bitfield size
		if ((bits.size() + 7) / 8 != (m_have_piece.size() + 7) / 8)
		{
			disconnect(errors::invalid_bitfield_size, 2);
			return;
		}

		m_bitfield_received = true;

		int num_pieces = bits.count();
		if (num_pieces == int(m_have_piece.size()))
		{
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("*** THIS IS A SEED [ p: %p ]", m_peer_info);
#endif
			// if this is a web seed. we don't have a peer_info struct
			t->get_policy().set_seed(m_peer_info, true);
			m_upload_only = true;

			m_have_piece.set_all();
			m_num_pieces = num_pieces;
			t->peer_has_all();
			if (!t->is_upload_only())
				t->get_policy().peer_is_interesting(*this);

			disconnect_if_redundant();

			return;
		}

		// let the torrent know which pieces the
		// peer has
		// if we're a seed, we don't keep track of piece availability
		bool interesting = false;
		if (!t->is_seed())
		{
			t->peer_has(bits);

			for (int i = 0; i < (int)m_have_piece.size(); ++i)
			{
				bool have = bits[i];
				if (have && !m_have_piece[i])
				{
					if (!t->have_piece(i) && t->picker().piece_priority(i) != 0)
						interesting = true;
				}
				else if (!have && m_have_piece[i])
				{
					// this should probably not be allowed
					t->peer_lost(i);
				}
			}
		}

		m_have_piece = bits;
		m_num_pieces = num_pieces;

        init();

		if (interesting) t->get_policy().peer_is_interesting(*this);
		else if (upload_only()) disconnect(errors::upload_upload_connection);
	}

	void peer_connection::disconnect_if_redundant()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		// we cannot disconnect in a constructor
		TORRENT_ASSERT(m_in_constructor == false);
		if (!m_ses.settings().close_redundant_connections) return;

		boost::shared_ptr<torrent> t = m_torrent;
		if (!t)
        {
            return;
        }

		// don't close connections in share mode, we don't know if we need them
		if (t->share_mode()) return;

		if (m_upload_only && t->is_upload_only())
		{
			disconnect(errors::upload_upload_connection);
			return;
		}

		if (m_upload_only
			&& !m_interesting
			&& m_bitfield_received)
			//&& t->are_files_checked())
		{
			disconnect(errors::uninteresting_upload_peer);
			return;
		}
	}

	// -----------------------------
	// ---------- REQUEST ----------
	// -----------------------------

	void peer_connection::incoming_request(peer_request const& r)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

#ifdef TORRENT_STATS
		++m_ses.m_piece_requests;
#endif

		NS_LOG_IP_INFO(ip,"<== REQUEST [ piece: " <<r.piece << " s: "<<r.start << " l: "<<r.length << " ]");

		if (m_superseed_piece != -1
			&& r.piece != m_superseed_piece)
		{
#ifdef TORRENT_STATS
			++m_ses.m_invalid_piece_requests;
#endif
			++m_num_invalid_requests;
			peer_log("*** INVALID_REQUEST [ piece not superseeded "
				"i: %d t: %d n: %d h: %d ss: %d ]"
				, m_peer_interested
				, int(t->torrent_file().piece_size(r.piece))
				, t->torrent_file().num_pieces()
				, t->have_piece(r.piece)
				, m_superseed_piece);

            // TODO: 临时禁用
			/*if (t->alerts().should_post<invalid_request_alert>())
			{
				t->alerts().post_alert(invalid_request_alert(
					t->get_handle(), m_remote, m_peer_id, r));
			}*/
			return;
		}

		// if we haven't received a bitfield, it was
		// probably omitted, which is the same as 'have_none'
		if (!m_bitfield_received) incoming_have_none();
		if (is_disconnecting()) return;

		if (int(m_requests.size()) > m_ses.settings().max_allowed_in_request_queue)
		{
#ifdef TORRENT_STATS
			++m_ses.m_max_piece_requests;
#endif
			// don't allow clients to abuse our
			// memory consumption.
			// ignore requests if the client
			// is making too many of them.
			peer_log("*** INVALID_REQUEST [ incoming request queue full %d ]"
				, int(m_requests.size()));
			peer_log("==> REJECT_PIECE [ piece: %d s: %d l: %d ]"
				, r.piece , r.start , r.length);
			write_reject_request(r);
			return;
		}

		int fast_idx = -1;
		std::vector<int>::iterator fast_iter = std::find(m_accept_fast.begin()
			, m_accept_fast.end(), r.piece);
		if (fast_iter != m_accept_fast.end()) fast_idx = fast_iter - m_accept_fast.begin();

		// make sure this request
		// is legal and that the peer
		// is not choked
		if (r.piece >= 0
			&& r.piece < t->torrent_file().num_pieces()
			&& t->have_piece(r.piece)
			&& r.start >= 0
			&& r.start < t->torrent_file().piece_size(r.piece)
			&& r.length > 0
			&& r.length + r.start <= t->torrent_file().piece_size(r.piece)
			&& m_peer_interested
			&& r.length <= t->block_size())
		{
			// if we have choked the client
			// ignore the request
			const int blocks_per_piece = static_cast<int>(
				(t->torrent_file().piece_length() + t->block_size() - 1) / t->block_size());

			// disconnect peers that downloads more than foo times an allowed
			// fast piece
			if (m_choked && fast_idx != -1 && m_accept_fast_piece_cnt[fast_idx] >= 3 * blocks_per_piece)
			{
				disconnect(errors::too_many_requests_when_choked);
				return;
			}

			if (m_choked && fast_idx == -1)
			{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
				peer_log("*** REJECTING REQUEST [ peer choked and piece not in allowed fast set ]");
				peer_log(" ==> REJECT_PIECE [ piece: %d | s: %d | l: %d ]"
					, r.piece, r.start, r.length);
#endif
#ifdef TORRENT_STATS
				++m_ses.m_choked_piece_requests;
#endif
				write_reject_request(r);
				++m_choke_rejects;

				if (m_choke_rejects > m_ses.settings().max_rejects)
				{
					disconnect(errors::too_many_requests_when_choked, 2);
					return;
				}
				else if ((m_choke_rejects & 0xf) == 0)
				{
					// tell the peer it's choked again
					// every 16 requests in a row
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
					peer_log("==> CHOKE [ peer keeps sending request when choked ]");
#endif
					write_choke();
				}
			}
			else
			{
				// increase the allowed fast set counter
				if (fast_idx != -1)
					++m_accept_fast_piece_cnt[fast_idx];

				m_choke_rejects = 0;
				m_requests.push_back(r);
			peer_log("==> GET PIECE REQUEST[ piece: %d s: %d l: %d ]"
				, r.piece , r.start , r.length);
#ifdef TORRENT_REQUEST_LOGGING
				if (m_ses.m_request_log)
					write_request_log(m_ses.m_request_log, t->info_hash(), this, r);
#endif
				m_last_incoming_request = time_now();
				fill_send_buffer();
			}
		}
		else
		{
#ifdef TORRENT_STATS
			++m_ses.m_invalid_piece_requests;
#endif
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** INVALID_REQUEST [ "
				"i: %d t: %d n: %d h: %d block_limit: %d ]"
				, m_peer_interested
				, int(t->torrent_file().piece_size(r.piece))
				, t->torrent_file().num_pieces()
				, t->have_piece(r.piece)
				, t->block_size());

			peer_log("==> REJECT_PIECE [ piece: %d s: %d l: %d ]"
				, r.piece , r.start , r.length);
#endif

			write_reject_request(r);
			++m_num_invalid_requests;

            // TODO: 待修正
			/*if (t->alerts().should_post<invalid_request_alert>())
			{
				t->alerts().post_alert(invalid_request_alert(
					t->get_handle(), m_remote, m_peer_id, r));
			}*/
		}
	}

	void peer_connection::incoming_piece_fragment(int bytes)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		m_last_piece = time_now();
		TORRENT_ASSERT(m_outstanding_bytes >= bytes);
		m_outstanding_bytes -= bytes;
		if (m_outstanding_bytes < 0) m_outstanding_bytes = 0;
		boost::shared_ptr<torrent> t = associated_torrent();
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		TORRENT_ASSERT(m_received_in_piece + bytes <= t->block_size());
		m_received_in_piece += bytes;
#endif

		// progress of this torrent increased
		t->state_updated();

#if !defined TORRENT_DISABLE_INVARIANT_CHECKS && defined TORRENT_DEBUG
		check_invariant();
#endif
	}

	void peer_connection::start_receive_piece(peer_request const& r)
	{
#if !defined TORRENT_DISABLE_INVARIANT_CHECKS && defined TORRENT_DEBUG
		check_invariant();
#endif
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		buffer::const_interval recv_buffer = receive_buffer();
		int recv_pos = recv_buffer.end - recv_buffer.begin;
		TORRENT_ASSERT(recv_pos >= 9);
#endif

		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);

		// piece_block can't necessarily hold large piece numbers
		// so check that first
		if (r.piece < 0
			|| r.piece >= t->torrent_file().num_pieces()
			|| r.start < 0
			|| r.start > t->torrent_file().piece_length())
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** INVALID_PIECE [ piece: %d s: %d l: %d ]"
				, r.piece, r.start, r.length);
#endif
			disconnect(errors::invalid_piece, 2);
			return;
		}

		piece_block b(r.piece, r.start / t->block_size());
		m_receiving_block = b;

		if (!verify_piece(r))
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** INVALID_PIECE [ piece: %d s: %d l: %d ]"
				, r.piece, r.start, r.length);
#endif
			disconnect(errors::invalid_piece, 2);
			return;
		}

		bool in_req_queue = false;
		for (std::vector<pending_block>::const_iterator i = m_download_queue.begin()
			, end(m_download_queue.end()); i != end; ++i)
		{
			if (i->block != b) continue;
			in_req_queue = true;
			break;
		}

		// if this is not in the request queue, we have to
		// assume our outstanding bytes includes this piece too
		// if we're disconnecting, we shouldn't add pieces
		if (!in_req_queue && !m_disconnecting)
		{
			for (std::vector<pending_block>::iterator i = m_request_queue.begin()
				, end(m_request_queue.end()); i != end; ++i)
			{
				if (i->block != b) continue;
				in_req_queue = true;
				if (i - m_request_queue.begin() < m_queued_time_critical)
					--m_queued_time_critical;
				m_request_queue.erase(i);
				break;
			}

			m_download_queue.insert(m_download_queue.begin(), b);
			if (!in_req_queue)
			{
                // TODO: 待修正
				/*if (t->alerts().should_post<unwanted_block_alert>())
				{
					t->alerts().post_alert(unwanted_block_alert(t->get_handle(), m_remote
						, m_peer_id, b.block_index, b.piece_index));
				}*/
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
				peer_log("*** The block we just got was not in the request queue ***");
#endif
				TORRENT_ASSERT(m_download_queue.front().block == b);
				m_download_queue.front().not_wanted = true;
			}
			m_outstanding_bytes += r.length;
		}
	}

#ifdef TORRENT_DEBUG
	struct check_postcondition
	{
		check_postcondition(boost::shared_ptr<torrent> const& t_
			, bool init_check = true): t(t_) { if (init_check) check(); }
	
		~check_postcondition() { check(); }
		
		void check()
		{
			if (!t->is_seed())
			{
				const int blocks_per_piece = static_cast<int>(
					(t->torrent_file().piece_length() + t->block_size() - 1) / t->block_size());

				std::vector<piece_picker::downloading_piece> const& dl_queue
					= t->picker().get_download_queue();

				for (std::vector<piece_picker::downloading_piece>::const_iterator i =
					dl_queue.begin(); i != dl_queue.end(); ++i)
				{
					TORRENT_ASSERT(i->finished <= blocks_per_piece);
				}
			}
		}
		
		shared_ptr<torrent> t;
	};
#endif


	// -----------------------------
	// ----------- PIECE -----------
	// -----------------------------

	void peer_connection::incoming_piece(peer_request const& p)
	{
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		TORRENT_ASSERT(!m_disk_recv_buffer);
		TORRENT_ASSERT(m_disk_recv_buffer_size == 0);

		// we're not receiving any block right now
		m_receiving_block = piece_block::invalid;

#ifdef TORRENT_CORRUPT_DATA
		// corrupt all pieces from certain peers
	//	if ((m_remote.GetPeerAddress().Get() & 0xf) == 0)
	//	{
	//		data[0] = ~data[0];
	//	}
#endif

		// if we haven't received a bitfield, it was
		// probably omitted, which is the same as 'have_none'
		if (!m_bitfield_received) incoming_have_none();
		if (is_disconnecting()) return;

		update_desired_queue_size();

		if (is_disconnecting()) return;

#ifdef TORRENT_DEBUG
		check_postcondition post_checker_(t);
#if !defined TORRENT_DISABLE_INVARIANT_CHECKS && defined TORRENT_EXPENSIVE_INVARIANT_CHECKS
		t->check_invariant();
#endif
#endif

	//	hasher h;
	//	h.update(data, p.length);
		peer_log("<== PIECE        [ piece: %d | s: %d | l: %d | ds: %d | qs: %d | q: %d ]"
			, p.piece, p.start, p.length, statistics().download_rate()
			, int(m_desired_queue_size), int(m_download_queue.size()));
//			, to_hex(h.final().to_string()).c_str());

		if (p.length == 0)
		{
            // TODO: 禁用alert
			/*if (t->alerts().should_post<peer_error_alert>())
			{
				t->alerts().post_alert(peer_error_alert(t->get_handle(), m_remote
					, m_peer_id, errors::peer_sent_empty_piece));
			}*/
			// This is used as a reject-request by bitcomet
			incoming_reject_request(p);
			return;
		}

		// if we're already seeding, don't bother,
		// just ignore it
		if (t->is_seed())
		{
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			TORRENT_ASSERT(m_received_in_piece == p.length);
			m_received_in_piece = 0;
#endif
			if (!m_download_queue.empty()) m_download_queue.erase(m_download_queue.begin());
			return;
		}

		ptime now = time_now();

		piece_picker& picker = t->picker();
		//piece_manager& fs = t->filesystem();

		std::vector<piece_block> finished_blocks;
		piece_block block_finished(p.piece, p.start / t->block_size());
		TORRENT_ASSERT(verify_piece(p));

		std::vector<pending_block>::iterator b
			= std::find_if(
				m_download_queue.begin()
				, m_download_queue.end()
				, has_block(block_finished));

		if (b == m_download_queue.end())
		{
            // TODO: 禁用alert
			/*if (t->alerts().should_post<unwanted_block_alert>())
			{
				t->alerts().post_alert(unwanted_block_alert(t->get_handle(), m_remote
					, m_peer_id, block_finished.block_index, block_finished.piece_index));
			}*/
			peer_log("*** The block we just got was not in the request queue ***");
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			TORRENT_ASSERT_VAL(m_received_in_piece == p.length, m_received_in_piece);
			m_received_in_piece = 0;
#endif
			return;
		}

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		pending_block pending_b = *b;
#endif

		int block_index = b - m_download_queue.begin();
		TORRENT_ASSERT(m_download_queue[block_index] == pending_b);
		for (int i = 0; i < block_index; ++i)
		{
			pending_block& qe = m_download_queue[i];
			TORRENT_ASSERT(m_download_queue[block_index] == pending_b);
			TORRENT_ASSERT(i < block_index);

			peer_log("*** SKIPPED_PIECE [ piece: %d b: %d dqs: %d ]"
				, qe.block.piece_index, qe.block.block_index, int(m_desired_queue_size));

			++qe.skipped;
			// if the number of times a block is skipped by out of order
			// blocks exceeds the size of the outstanding queue, assume that
			// the other end dropped the request.
			if (m_ses.m_settings.drop_skipped_requests
				&& qe.skipped > m_desired_queue_size)
			{
                // TODO: 禁用alert
				/*if (m_ses.m_alerts.should_post<request_dropped_alert>())
					m_ses.m_alerts.post_alert(request_dropped_alert(t->get_handle()
						, remote(), pid(), qe.block.block_index, qe.block.piece_index));*/

				peer_log("*** DROPPED_PIECE [ piece: %d b: %d dqs: %d skip: %d ]"
					, qe.block.piece_index, qe.block.block_index
					, int(m_desired_queue_size), qe.skipped);

				if (!qe.timed_out && !qe.not_wanted)
					picker.abort_download(qe.block, peer_info_struct());

				TORRENT_ASSERT(m_outstanding_bytes >= t->to_req(qe.block).length);
				m_outstanding_bytes -= t->to_req(qe.block).length;
				if (m_outstanding_bytes < 0) m_outstanding_bytes = 0;
				TORRENT_ASSERT(m_download_queue[block_index] == pending_b);
				m_download_queue.erase(m_download_queue.begin() + i);
				--i;
				--block_index;
				TORRENT_ASSERT(m_download_queue[block_index] == pending_b);
#if !defined TORRENT_DISABLE_INVARIANT_CHECKS && defined TORRENT_DEBUG
				check_invariant();
#endif
			}
		}
		TORRENT_ASSERT(int(m_download_queue.size()) > block_index);
		b = m_download_queue.begin() + block_index;
		TORRENT_ASSERT(*b == pending_b);
		
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		TORRENT_ASSERT_VAL(m_received_in_piece == p.length, m_received_in_piece);
		m_received_in_piece = 0;
#endif
		// if the block we got is already finished, then ignore it
		if (picker.is_downloaded(block_finished))
		{
			m_download_queue.erase(b);
			m_timeout_extend = 0;

			if (!m_download_queue.empty())
				m_requested = now;

#ifdef TORRENT_STATS
			++m_ses.m_incoming_redundant_piece_picks;
#endif
			request_a_block(*t, *this);
			send_block_requests();
			return;
		}

		if (total_seconds(now - m_requested)
			< m_ses.settings().request_timeout
			&& m_snubbed)
		{
			m_snubbed = false;

            // TODO: 禁用alert
            /*
			if (m_ses.m_alerts.should_post<peer_unsnubbed_alert>())
			{
				m_ses.m_alerts.post_alert(peer_unsnubbed_alert(t->get_handle()
					, m_remote, m_peer_id));
			}*/
		}

		//int write_queue_size = fs.async_write(p, data, boost::bind(&peer_connection::on_disk_write_complete
		//	, self(), _1, _2, p, t));
		m_outstanding_writing_bytes += p.length;
		m_download_queue.erase(b);

        // TODO: 禁用alert
		/*if (write_queue_size / 16 / 1024 > m_ses.m_settings.cache_size / 2
			&& m_ses.m_settings.cache_size > 5
			&& (now - m_ses.m_last_disk_queue_performance_warning) > seconds(10)
			&& m_ses.m_alerts.should_post<performance_alert>())
		{
			m_ses.m_last_disk_queue_performance_warning = now;
			t->alerts().post_alert(performance_alert(t->get_handle()
				, performance_alert::too_high_disk_queue_limit));
		}

		if (!m_ses.can_write_to_disk()
			&& m_ses.settings().max_queued_disk_bytes
			&& t->alerts().should_post<performance_alert>()
			&& (now - m_ses.m_last_disk_performance_warning) > seconds(10))
		{
			m_ses.m_last_disk_performance_warning = now;
			t->alerts().post_alert(performance_alert(t->get_handle()
				, performance_alert::outstanding_disk_buffer_limit_reached));
		}*/

		if (!m_download_queue.empty())
		{
			m_timeout_extend = (std::max)(m_timeout_extend
				- m_ses.settings().request_timeout, 0);
			m_requested += seconds(m_ses.settings().request_timeout);
			if (m_requested > now) m_requested = now;
		}
		else
		{
			m_timeout_extend = 0;
		}

		bool was_finished = picker.is_piece_finished(p.piece);
		// did we request this block from any other peers?
		bool multi = picker.num_peers(block_finished) > 1;
		picker.mark_as_writing(block_finished, peer_info_struct());

		TORRENT_ASSERT(picker.num_peers(block_finished) == 0);
		// if we requested this block from other peers, cancel it now
		if (multi) t->cancel_block(block_finished);

		TORRENT_ASSERT(picker.num_peers(block_finished) == 0);

#if defined TORRENT_DEBUG && !defined TORRENT_DISABLE_INVARIANT_CHECKS \
	&& defined TORRENT_EXPENSIVE_INVARIANT_CHECKS
		t->check_invariant();
#endif

//#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
//		piece_picker::downloading_piece pi;
//		picker.piece_info(p.piece, pi);
//		int num_blocks = picker.blocks_in_piece(p.piece);
//		TORRENT_ASSERT(pi.writing + pi.finished + pi.requested <= num_blocks);
//		TORRENT_ASSERT(picker.is_piece_finished(p.piece) == (pi.writing + pi.finished == num_blocks));
//#endif

		// did we just finish the piece?
		// this means all blocks are either written
		// to disk or are in the disk write cache
		if (picker.is_piece_finished(p.piece) && !was_finished)
		{
#ifdef TORRENT_DEBUG
			check_postcondition post_checker2_(t, false);
#endif
            t->piece_finished(p.piece, 0);
			//t->async_verify_piece(p.piece, boost::bind(&torrent::piece_finished, t
			//	, p.piece, _1));
		}

		if (is_disconnecting()) return;

//#ifdef TORRENT_STATS
//		++m_ses.m_incoming_piece_picks;
//#endif
		request_a_block(*t, *this);
		send_block_requests();
	}

//	void peer_connection::on_disk_write_complete(int ret, disk_io_job const& j
//		, peer_request p, boost::shared_ptr<torrent> t)
//	{
//#ifdef TORRENT_STATS
//		++m_ses.m_num_messages[aux::session_impl::on_disk_write_counter];
//#endif
//		TORRENT_ASSERT(m_ses.is_network_thread());
//
//		// flush send buffer at the end of this scope
//		// TODO: peers should really be corked/uncorked outside of
//		// all completed disk operations
//		cork _c(*this);
//
//		INVARIANT_CHECK;
//
//		m_outstanding_writing_bytes -= p.length;
//		TORRENT_ASSERT(m_outstanding_writing_bytes >= 0);
//
//#if defined(TORRENT_VERBOSE_LOGGING) || defined(TORRENT_LOGGING)
////		(*m_ses.m_logger) << time_now_string() << " *** DISK_WRITE_COMPLETE [ p: "
////			<< p.piece << " o: " << p.start << " ]\n";
//#endif
//
//		if (!t)
//		{
//			disconnect(j.error);
//			return;
//		}
//
//		// in case the outstanding bytes just dropped down
//		// to allow to receive more data
//		setup_receive(read_async);
//
//		piece_block block_finished(p.piece, p.start / t->block_size());
//
//		if (ret == -1)
//		{
//			// handle_disk_error may disconnect us
//			t->handle_disk_error(j, this);
//			return;
//		}
//
//		if (t->is_seed()) return;
//
//		piece_picker& picker = t->picker();
//
//		TORRENT_ASSERT(p.piece == j.piece);
//		TORRENT_ASSERT(p.start == j.offset);
//		TORRENT_ASSERT(picker.num_peers(block_finished) == 0);
//		picker.mark_as_finished(block_finished, peer_info_struct());
//
//        // TODO: 禁用alert
//		/*if (t->alerts().should_post<block_finished_alert>())
//		{
//			t->alerts().post_alert(block_finished_alert(t->get_handle(), 
//				remote(), pid(), block_finished.block_index, block_finished.piece_index));
//		}*/
//
//		if (t->is_aborted()) return;
//	}

	// -----------------------------
	// ---------- CANCEL -----------
	// -----------------------------

	void peer_connection::incoming_cancel(peer_request const& r)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		if (is_disconnecting()) return;

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== CANCEL  [ piece: %d | s: %d | l: %d ]", r.piece, r.start, r.length);
#endif

		std::vector<peer_request>::iterator i
			= std::find(m_requests.begin(), m_requests.end(), r);

		if (i != m_requests.end())
		{
#ifdef TORRENT_STATS
			++m_ses.m_cancelled_piece_requests;
#endif
			m_requests.erase(i);
			peer_log("==> REJECT_PIECE [ piece: %d s: %d l: %d ]"
				, r.piece , r.start , r.length);
			write_reject_request(r);
		}
		else
		{
			peer_log("*** GOT CANCEL NOT IN THE QUEUE");
		}
	}

	// -----------------------------
	// --------- DHT PORT ----------
	// -----------------------------

	void peer_connection::incoming_dht_port(int listen_port)
	{
		INVARIANT_CHECK;

		peer_log("<== DHT_PORT [ p: %d ]", listen_port);
	}

	// -----------------------------
	// --------- HAVE ALL ----------
	// -----------------------------

	void peer_connection::incoming_have_all()
	{
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		// we cannot disconnect in a constructor, and
		// this function may end up doing that
		TORRENT_ASSERT(m_in_constructor == false);

		peer_log("<== HAVE_ALL");

		if (is_disconnecting()) return;

		m_have_all = true;

		peer_log("*** THIS IS A SEED [ p: %p ]", m_peer_info);

		t->get_policy().set_seed(m_peer_info, true);
		m_upload_only = true;
		m_bitfield_received = true;

		TORRENT_ASSERT(!m_have_piece.empty());
		m_have_piece.set_all();
		m_num_pieces = m_have_piece.size();
		
		t->peer_has_all();

        init();
		// if we're finished, we're not interested
		//if (t->is_upload_only()) send_not_interested();
		//else t->get_policy().peer_is_interesting(*this);

		disconnect_if_redundant();
	}
	
	// -----------------------------
	// --------- HAVE NONE ---------
	// -----------------------------

	void peer_connection::incoming_have_none()
	{
		INVARIANT_CHECK;

		peer_log("<== HAVE_NONE");

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		if (is_disconnecting()) return;
		t->get_policy().set_seed(m_peer_info, false);
		m_bitfield_received = true;

		// if the peer is ready to download stuff, it must have metadata		
		m_has_metadata = true;

		// we're never interested in a peer that doesn't have anything
		send_not_interested();

		TORRENT_ASSERT(!m_have_piece.empty());
        init();

		disconnect_if_redundant();
	}

	// -----------------------------
	// ------- ALLOWED FAST --------
	// -----------------------------

	void peer_connection::incoming_allowed_fast(int index)
	{
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== ALLOWED_FAST [ %d ]", index);
#endif

		if (is_disconnecting()) return;
		if (index < 0)
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("<== INVALID_ALLOWED_FAST [ %d ]", index);
#endif
			return;
		}

			if (index >= int(m_have_piece.size()))
			{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
				peer_log("<== INVALID_ALLOWED_FAST [ %d | s: %d ]"
					, index, int(m_have_piece.size()));
#endif
				return;
			}

			// if we already have the piece, we can
			// ignore this message
			if (t->have_piece(index))
				return;

		// if we don't have the metadata, we'll verify
		// this piece index later
		m_allowed_fast.push_back(index);

		// if the peer has the piece and we want
		// to download it, request it
		if (int(m_have_piece.size()) > index
			&& m_have_piece[index]
			&& t->has_picker()
			&& t->picker().piece_priority(index) > 0)
		{
			t->get_policy().peer_is_interesting(*this);
		}
	}

	std::vector<int> const& peer_connection::allowed_fast()
	{
		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		// TODO: sort the allowed fast set in priority order
		return m_allowed_fast;
	}

	bool peer_connection::can_request_time_critical() const
	{
		if (has_peer_choked() || !is_interesting()) return false;
		if ((int)m_download_queue.size() + (int)m_request_queue.size()
			> m_desired_queue_size * 2) return false;
		if (on_parole()) return false; 
		if (m_disconnecting) return false;
		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);
		if (t->upload_mode()) return false;

		// ignore snubbed peers, since they're not likely to return pieces in a timely
		// manner anyway
		if (m_snubbed) return false;
		return true;
	}

	void peer_connection::make_time_critical(piece_block const& block)
	{
		std::vector<pending_block>::iterator rit = std::find_if(m_request_queue.begin()
			, m_request_queue.end(), has_block(block));
		if (rit == m_request_queue.end()) return;
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);
		TORRENT_ASSERT(t->has_picker());
		TORRENT_ASSERT(t->picker().is_requested(block));
#endif
		// ignore it if it's already time critical
		if (rit - m_request_queue.begin() < m_queued_time_critical) return;
		pending_block b = *rit;
		m_request_queue.erase(rit);
		m_request_queue.insert(m_request_queue.begin() + m_queued_time_critical, b);
		++m_queued_time_critical;
	}

	bool peer_connection::add_request(piece_block const& block, int flags)
	{
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		TORRENT_ASSERT(!m_disconnecting);
		TORRENT_ASSERT(block.piece_index >= 0);
		TORRENT_ASSERT(int(block.piece_index) < t->torrent_file().num_pieces());
		TORRENT_ASSERT(block.block_index >= 0);
		TORRENT_ASSERT(int(block.block_index) < t->torrent_file().piece_size(block.piece_index));
		TORRENT_ASSERT(!t->picker().is_requested(block) || (t->picker().num_peers(block) > 0));
		TORRENT_ASSERT(!t->have_piece(block.piece_index));
		TORRENT_ASSERT(std::find_if(m_download_queue.begin(), m_download_queue.end()
			, has_block(block)) == m_download_queue.end());
		TORRENT_ASSERT(std::find(m_request_queue.begin(), m_request_queue.end()
			, block) == m_request_queue.end());

		if (t->upload_mode()) return false;
		if (m_disconnecting) return false;

		piece_picker::piece_state_t state;
		peer_speed_t speed = peer_speed();
		//char const* speedmsg = 0;
		if (speed == fast)
		{
		//	speedmsg = "fast";
			state = piece_picker::fast;
		}
		else if (speed == medium)
		{
		//	speedmsg = "medium";
			state = piece_picker::medium;
		}
		else
		{
		//	speedmsg = "slow";
			state = piece_picker::slow;
		}

		if (flags & req_busy)
		{
			// this block is busy (i.e. it has been requested
			// from another peer already). Only allow one busy
			// request in the pipeline at the time
			for (std::vector<pending_block>::const_iterator i = m_download_queue.begin()
				, end(m_download_queue.end()); i != end; ++i)
			{
				if (i->busy) return false;
			}

			for (std::vector<pending_block>::const_iterator i = m_request_queue.begin()
				, end(m_request_queue.end()); i != end; ++i)
			{
				if (i->busy) return false;
			}
		}

		if (!t->picker().mark_as_downloading(block, peer_info_struct(), state))
			return false;

        // TODO: 禁用alert
		/*if (t->alerts().should_post<block_downloading_alert>())
		{
			t->alerts().post_alert(block_downloading_alert(t->get_handle(), 
				remote(), pid(), speedmsg, block.block_index, block.piece_index));
		}*/

		pending_block pb(block);
		pb.busy = (flags & req_busy) ? true : false;
		if (flags & req_time_critical)
		{
			m_request_queue.insert(m_request_queue.begin() + m_queued_time_critical
				, pb);
			++m_queued_time_critical;
		}
		else
		{
			m_request_queue.push_back(pb);
		}
		return true;
	}

	void peer_connection::cancel_all_requests()
	{
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		// this peer might be disconnecting
		if (!t) return;

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("*** CANCEL ALL REQUESTS");
#endif

		while (!m_request_queue.empty())
		{
			t->picker().abort_download(m_request_queue.back().block, peer_info_struct());
			m_request_queue.pop_back();
		}
		m_queued_time_critical = 0;

		// make a local temporary copy of the download queue, since it
		// may be modified when we call write_cancel (for peers that don't
		// support the FAST extensions).
		std::vector<pending_block> temp_copy = m_download_queue;

		for (std::vector<pending_block>::iterator i = temp_copy.begin()
			, end(temp_copy.end()); i != end; ++i)
		{
			piece_block b = i->block;

			int block_offset = b.block_index * t->block_size();
			int block_size
				= (std::min)(t->torrent_file().piece_size(b.piece_index)-block_offset,
					t->block_size());
			TORRENT_ASSERT(block_size > 0);
			TORRENT_ASSERT(block_size <= t->block_size());

			// we can't cancel the piece if we've started receiving it
			if (m_receiving_block == b) continue;

			peer_request r;
			r.piece = b.piece_index;
			r.start = block_offset;
			r.length = block_size;

#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("==> CANCEL  [ piece: %d s: %d l: %d b: %d ]"
				, b.piece_index, block_offset, block_size, b.block_index);
#endif
			write_cancel(r);
		}
	}

	void peer_connection::cancel_request(piece_block const& block, bool force)
	{
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		// this peer might be disconnecting
		if (!t) return;

		TORRENT_ASSERT(block.piece_index >= 0);
		TORRENT_ASSERT(int(block.piece_index) < t->torrent_file().num_pieces());
		TORRENT_ASSERT(block.block_index >= 0);
		TORRENT_ASSERT(int(block.block_index) < t->torrent_file().piece_size(block.piece_index));

		// if all the peers that requested this block has been
		// cancelled, then just ignore the cancel.
		if (!t->picker().is_requested(block)) return;

		std::vector<pending_block>::iterator it
			= std::find_if(m_download_queue.begin(), m_download_queue.end(), has_block(block));
		if (it == m_download_queue.end())
		{
			std::vector<pending_block>::iterator rit = std::find_if(m_request_queue.begin()
				, m_request_queue.end(), has_block(block));

			// when a multi block is received, it is cancelled
			// from all peers, so if this one hasn't requested
			// the block, just ignore to cancel it.
			if (rit == m_request_queue.end()) return;

			if (rit - m_request_queue.begin() < m_queued_time_critical)
				--m_queued_time_critical;

			t->picker().abort_download(block, peer_info_struct());
			m_request_queue.erase(rit);
			// since we found it in the request queue, it means it hasn't been
			// sent yet, so we don't have to send a cancel.
			return;
		}

		int block_offset = block.block_index * t->block_size();
		int block_size
			= (std::min)(t->torrent_file().piece_size(block.piece_index)-block_offset,
			t->block_size());
		TORRENT_ASSERT(block_size > 0);
		TORRENT_ASSERT(block_size <= t->block_size());

		if (force) t->picker().abort_download(block, peer_info_struct());

		if (m_outstanding_bytes < block_size) return;

		peer_request r;
		r.piece = block.piece_index;
		r.start = block_offset;
		r.length = block_size;

#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("==> CANCEL  [ piece: %d s: %d l: %d b: %d ]"
				, block.piece_index, block_offset, block_size, block.block_index);
#endif
		write_cancel(r);
	}

	bool peer_connection::send_choke()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		if (m_peer_info && m_peer_info->optimistically_unchoked)
			m_peer_info->optimistically_unchoked = false;

		if (m_choked) return false;
#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("==> CHOKE");
#endif
		write_choke();
		m_choked = true;

#ifdef TORRENT_DEBUG
		m_last_choke = time_now();
#endif
		m_num_invalid_requests = 0;

		// reject the requests we have in the queue
		// except the allowed fast pieces
		for (std::vector<peer_request>::iterator i = m_requests.begin();
			i != m_requests.end();)
		{
			if (std::find(m_accept_fast.begin(), m_accept_fast.end(), i->piece)
				!= m_accept_fast.end())
			{
				++i;
				continue;
			}
			peer_request const& r = *i;
#ifdef TORRENT_STATS
			++m_ses.m_choked_piece_requests;
#endif
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("==> REJECT_PIECE [ piece: %d s: %d l: %d ]"
				, r.piece , r.start , r.length);
#endif
			write_reject_request(r);
			i = m_requests.erase(i);
		}
		return true;
	}

	bool peer_connection::send_unchoke()
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		if (!m_choked) return false;
		boost::shared_ptr<torrent> t = m_torrent;

		if (!m_sent_suggests)
		{
			std::vector<int> ret;
			t->get_suggested_pieces(ret);
			for (std::vector<int>::iterator i = ret.begin()
				, end(ret.end()); i != end; ++i)
			{
				TORRENT_ASSERT(*i >= 0);
				//send_suggest(*i);
			}

			m_sent_suggests = true;
		}

		m_last_unchoke = time_now();
		write_unchoke();
		m_choked = false;

		m_uploaded_at_last_unchoke = m_statistics.total_payload_upload();

		NS_LOG_IP_INFO(ip, "==> UNCHOKE");

		return true;
	}

	void peer_connection::send_interested()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		if (m_interesting) return;
		boost::shared_ptr<torrent> t = m_torrent;
		m_interesting = true;
		write_interested();

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("==> INTERESTED");
#endif
	}

	void peer_connection::send_not_interested()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		// we cannot disconnect in a constructor, and
		// this function may end up doing that
		TORRENT_ASSERT(m_in_constructor == false);
//
//		if (!m_interesting)
//		{
//			disconnect_if_redundant();
//			return;
//		}

		boost::shared_ptr<torrent> t = m_torrent;
		m_interesting = false;
		write_not_interested();

		m_became_uninteresting = time_now();

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("==> NOT_INTERESTED");
#endif
		disconnect_if_redundant();
	}

	void peer_connection::send_suggest(int piece)
	{
		if (m_connecting) return;
		if (in_handshake()) return;

		// don't suggest a piece that the peer already has
		// don't suggest anything to a peer that isn't interested
		if (has_piece(piece)
			|| !m_peer_interested)
			return;
	
#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("==> SUGGEST [ %d ]", piece);
#endif
		write_suggest(piece);
	}

	void peer_connection::send_block_requests()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;
		
		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		if (m_disconnecting) return;

		if (t->graceful_pause() && m_outstanding_bytes == 0)
		{
			NS_LOG_IP_INFO(ip, "*** GRACEFUL PAUSE [ NO MORE DOWNLOAD ]");
			disconnect(errors::torrent_paused);
			return;
		}

		// we can't download pieces in these states
		if (t->state() == torrent_status::checking_files
			|| t->state() == torrent_status::checking_resume_data
			|| t->state() == torrent_status::downloading_metadata
			|| t->state() == torrent_status::allocating)
        {
            NS_LOG_IP_INFO(ip, "state error, not ready to send block request");
			return;
        }

		if ((int)m_download_queue.size() >= m_desired_queue_size
			|| t->upload_mode())
        {
            NS_LOG_IP_INFO(ip, "can't download ");
            return;
        }

		bool empty_download_queue = m_download_queue.empty();

		while (!m_request_queue.empty()
			&& ((int)m_download_queue.size() < m_desired_queue_size
				|| m_queued_time_critical > 0))
		{
			pending_block block = m_request_queue.front();

			m_request_queue.erase(m_request_queue.begin());
			if (m_queued_time_critical) --m_queued_time_critical;

			// if we're a seed, we don't have a piece picker
			// so we don't have to worry about invariants getting
			// out of sync with it
			if (t->is_seed())
                continue;

			// this can happen if a block times out, is re-requested and
			// then arrives "unexpectedly"
			if (t->picker().is_finished(block.block)
				|| t->picker().is_downloaded(block.block))
			{

				t->picker().abort_download(block.block, peer_info_struct());
				continue;
			}

			int block_offset = block.block.block_index * t->block_size();
			int block_size = (std::min)(t->torrent_file().piece_size(
				block.block.piece_index) - block_offset, t->block_size());
			TORRENT_ASSERT(block_size > 0);
			TORRENT_ASSERT(block_size <= t->block_size());

			peer_request r;
			r.piece = block.block.piece_index;
			r.start = block_offset;
			r.length = block_size;

			TORRENT_ASSERT(verify_piece(t->to_req(block.block)));
			m_download_queue.push_back(block);
			m_outstanding_bytes += block_size;
#if !defined TORRENT_DISABLE_INVARIANT_CHECKS && defined TORRENT_DEBUG
			check_invariant();
#endif

/*
#ifdef TORRENT_VERBOSE_LOGGING
			(*m_logger) << time_now_string()
				<< " *** REQUEST-QUEUE** [ "
				"piece: " << block.piece_index << " | "
				"block: " << block.block_index << " ]\n";
#endif
*/			
			// if we are requesting large blocks, merge the smaller
			// blocks that are in the same piece into larger requests
			if (m_request_large_blocks)
			{
				int blocks_per_piece = t->torrent_file().piece_length() / t->block_size();

				while (!m_request_queue.empty())
				{
					// check to see if this block is connected to the previous one
					// if it is, merge them, otherwise, break this merge loop
					pending_block const& front = m_request_queue.front();
					if (front.block.piece_index * blocks_per_piece + front.block.block_index
						!= block.block.piece_index * blocks_per_piece + block.block.block_index + 1)
						break;
					block = m_request_queue.front();
					m_request_queue.erase(m_request_queue.begin());
					TORRENT_ASSERT(verify_piece(t->to_req(block.block)));
					m_download_queue.push_back(block);
					if (m_queued_time_critical) --m_queued_time_critical;

					peer_log("*** MERGING REQUEST [ piece: %d block: %d ]"
						, block.block.piece_index, block.block.block_index);

					block_offset = block.block.block_index * t->block_size();
					block_size = (std::min)(t->torrent_file().piece_size(
						block.block.piece_index) - block_offset, t->block_size());
					TORRENT_ASSERT(block_size > 0);
					TORRENT_ASSERT(block_size <= t->block_size());

					r.length += block_size;
					m_outstanding_bytes += block_size;
#if !defined TORRENT_DISABLE_INVARIANT_CHECKS && defined TORRENT_DEBUG
					check_invariant();
#endif
				}
			}

			// the verification will fail for coalesced blocks
			TORRENT_ASSERT(verify_piece(r) || m_request_large_blocks);
			
			{
				write_request(r);
				m_last_request = time_now();
			}

			peer_log("==> REQUEST      [ piece: %d | s: %d | l: %d | ds: %d B/s | "
				"dqs: %d rqs: %d blk: %s ]"
				, r.piece, r.start, r.length, statistics().download_rate()
				, int(m_desired_queue_size), int(m_download_queue.size())
				, m_request_large_blocks?"large":"single");
		}
		m_last_piece = time_now();

		if (!m_download_queue.empty()
			&& empty_download_queue)
		{
			// This means we just added a request to this connection
			m_requested = time_now();
		}
	}

	void peer_connection::on_timeout()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());

		connect_failed(errors::timed_out);
	}
	
	void peer_connection::connect_failed(error_code const& e)
	{
		TORRENT_ASSERT(e);

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
		peer_log("CONNECTION FAILED: %s", print_endpoint(m_remote).c_str());
#endif
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
		(*m_ses.m_logger) << time_now_string() << " CONNECTION FAILED: " << print_endpoint(m_remote) << "\n";
#endif

#ifdef TORRENT_STATS
		++m_ses.m_connect_timeouts;
#endif

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(!m_connecting || t);
		if (m_connecting && t)
		{
			t->dec_num_connecting();
			m_connecting = false;
		}

	//	if (m_connection_ticket != -1)
	//	{
	//		m_ses.m_half_open.done(m_connection_ticket);
	//	}

		disconnect(e, 1);
		return;
	}

	// the error argument defaults to 0, which means deliberate disconnect
	// 1 means unexpected disconnect/error
	// 2 protocol error (client sent something invalid)
	void peer_connection::disconnect(error_code const& ec, int error)
	{
        NS_LOG_IP_FUNCTION(ip,this);
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_disconnect_started = true;
#endif

		if (m_disconnecting) return;

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
		switch (error)
		{
		case 0:
			peer_log("*** CONNECTION CLOSED %s", ec.message().c_str());
			break;
		case 1:
			peer_log("*** CONNECTION FAILED %s", ec.message().c_str());
			break;
		case 2:
			peer_log("*** PEER ERROR %s", ec.message().c_str());
			break;
		}
#endif

		// for incoming connections, we get invalid argument errors
		// when asking for the remote endpoint and the socket already
		// closed, which is an edge case, but possible to happen when
		// a peer makes a TCP and uTP connection in parallel.
		// for outgoing connections however, why would we get this?
		TORRENT_ASSERT(ec != error::invalid_argument || !m_outgoing);

#ifdef TORRENT_STATS
		++m_ses.m_disconnected_peers;
		if (error == 2) ++m_ses.m_error_peers;
		if (ec == error::connection_reset) ++m_ses.m_connreset_peers;
		else if (ec == error::eof) ++m_ses.m_eof_peers;
		else if (ec == error::connection_refused) ++m_ses.m_connrefused_peers;
		else if (ec == error::connection_aborted) ++m_ses.m_connaborted_peers;
		else if (ec == error::no_permission) ++m_ses.m_perm_peers;
		else if (ec == error::no_buffer_space) ++m_ses.m_buffer_peers;
		else if (ec == error::host_unreachable) ++m_ses.m_unreachable_peers;
		else if (ec == error::broken_pipe) ++m_ses.m_broken_pipe_peers;
		else if (ec == error::address_in_use) ++m_ses.m_addrinuse_peers;
		else if (ec == error::access_denied) ++m_ses.m_no_access_peers;
		else if (ec == error::invalid_argument) ++m_ses.m_invalid_arg_peers;
		else if (ec == error::operation_aborted) ++m_ses.m_aborted_peers;
		else if (ec == error_code(errors::upload_upload_connection)
			|| ec == error_code(errors::uninteresting_upload_peer)
			|| ec == error_code(errors::torrent_aborted)
			|| ec == error_code(errors::self_connection)
			|| ec == error_code(errors::torrent_paused))
			++m_ses.m_uninteresting_peers;

		if (ec == error_code(errors::timed_out)
			|| ec == error::timed_out)
			++m_ses.m_transport_timeout_peers;
		
		if (ec == error_code(errors::timed_out_inactivity)
			|| ec == error_code(errors::timed_out_no_request)
			|| ec == error_code(errors::timed_out_no_interest))
			++m_ses.m_timeout_peers;

		if (ec == error_code(errors::no_memory))
			++m_ses.m_no_memory_peers;

		if (ec == error_code(errors::too_many_connections))
			++m_ses.m_too_many_peers;

		if (ec == error_code(errors::timed_out_no_handshake))
			++m_ses.m_connect_timeouts;

		if (m_outgoing) ++m_ses.m_error_outgoing_peers;
		else ++m_ses.m_error_incoming_peers;

#endif

		// we cannot do this in a constructor
		TORRENT_ASSERT(m_in_constructor == false);
		if (error > 0) m_failed = true;
		boost::intrusive_ptr<peer_connection> me(this);

		INVARIANT_CHECK;

	//	if (m_channel_state[upload_channel] & peer_info::bw_disk)
	//	{
	//		m_ses.dec_disk_queue(upload_channel);
	//		m_channel_state[upload_channel] &= ~peer_info::bw_disk;
	//	}
	//	if (m_channel_state[download_channel] & peer_info::bw_disk)
	//	{
	//		m_ses.dec_disk_queue(download_channel);
	//		m_channel_state[download_channel] &= ~peer_info::bw_disk;
	//	}

		boost::shared_ptr<torrent> t = m_torrent;
		if (m_connecting)
		{
			t->dec_num_connecting();
			m_connecting = false;
		}
		if (m_connection_ticket >= 0)
		{
	//		m_ses.m_half_open.done(m_connection_ticket);
			m_connection_ticket = -1;
		}

		torrent_handle handle;
		if (t) handle = t->get_handle();

        // TODO: 禁用alert
		/*if (ec == error::address_in_use
			&& m_ses.m_settings.outgoing_ports.first != 0)
		{
			if (m_ses.m_alerts.should_post<performance_alert>())
				m_ses.m_alerts.post_alert(performance_alert(
					handle, performance_alert::too_few_outgoing_ports));
		}

		if (ec)
		{
			if ((error > 1 || ec.category() == socks_category)
				&& m_ses.m_alerts.should_post<peer_error_alert>())
			{
				m_ses.m_alerts.post_alert(
					peer_error_alert(handle, remote(), pid(), ec));
			}
			else if (error <= 1 && m_ses.m_alerts.should_post<peer_disconnected_alert>())
			{
				m_ses.m_alerts.post_alert(
					peer_disconnected_alert(handle, remote(), pid(), ec));
			}
		}*/

		if (t)
		{
			// make sure we keep all the stats!
			if (!m_ignore_stats)
			{
				t->add_stats(statistics());

				// report any partially received payload as redundant
				boost::optional<piece_block_progress> pbp = downloading_piece_progress();
			}

			if (t->has_picker())
			{
				piece_picker& picker = t->picker();

				while (!m_download_queue.empty())
				{
					pending_block& qe = m_download_queue.back();
					if (!qe.timed_out && !qe.not_wanted)
						picker.abort_download(qe.block, peer_info_struct());
					m_outstanding_bytes -= t->to_req(qe.block).length;
					if (m_outstanding_bytes < 0) m_outstanding_bytes = 0;
					m_download_queue.pop_back();
				}
				while (!m_request_queue.empty())
				{
					picker.abort_download(m_request_queue.back().block, peer_info_struct());
					m_request_queue.pop_back();
				}
			}
			else
			{
				m_download_queue.clear();
				m_request_queue.clear();
				m_outstanding_bytes = 0;
			}
			m_queued_time_critical = 0;

#if !defined TORRENT_DISABLE_INVARIANT_CHECKS && defined TORRENT_DEBUG
			check_invariant();
#endif
			t->remove_peer(this);
			m_torrent.reset();
		}
		else
		{
			TORRENT_ASSERT(m_download_queue.empty());
			TORRENT_ASSERT(m_request_queue.empty());
		}

#if defined TORRENT_DEBUG && defined TORRENT_EXPENSIVE_INVARIANT_CHECKS
		// since this connection doesn't have a torrent reference
		// no torrent should have a reference to this connection either
		for (aux::session_impl::torrent_map::const_iterator i = m_ses.m_torrents.begin()
			, end(m_ses.m_torrents.end()); i != end; ++i)
			TORRENT_ASSERT(!i->second->has_peer(this));
#endif

		m_disconnecting = true;
		error_code e;

        m_socket->Close();

		m_ses.close_connection(this, ec);

		// we should only disconnect while we still have
		// at least one reference left to the connection
		TORRENT_ASSERT(refcount() > 0);
	}

	int peer_connection::get_upload_limit() const
	{
		return m_upload_limit;
	}

	int peer_connection::get_download_limit() const
	{
		return m_download_limit;
	}

	void peer_connection::set_upload_limit(int limit)
	{
		TORRENT_ASSERT(limit >= -1);
		if (limit < 0) limit = 0;
		if (limit < 10 && limit > 0) limit = 10;
		m_upload_limit = limit;
		m_bandwidth_channel[upload_channel].throttle(m_upload_limit);
	}

	void peer_connection::set_download_limit(int limit)
	{
		TORRENT_ASSERT(limit >= -1);
		if (limit < 0) limit = 0;
		if (limit < 10 && limit > 0) limit = 10;
		m_download_limit = limit;
		m_bandwidth_channel[download_channel].throttle(m_download_limit);
	}

	size_type peer_connection::share_diff() const
	{
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		float ratio = t->ratio();

		// if we have an infinite ratio, just say we have downloaded
		// much more than we have uploaded. And we'll keep uploading.
		if (ratio == 0.f)
			return (std::numeric_limits<size_type>::max)();

		return m_free_upload
			+ static_cast<size_type>(m_statistics.total_payload_download() * ratio)
			- m_statistics.total_payload_upload();
	}

	bool peer_connection::ignore_unchoke_slots() const
	{
		return m_ignore_unchoke_slots
			|| (m_ses.settings().ignore_limits_on_local_network
			// on_local_network()
			&& m_ses.m_local_upload_channel.throttle() == 0);
	}

    // TODO: 待修正，将相应的代码加紧来
    /*
	// defined in upnp.cpp
	bool is_local(Ipv4Address const& a);

	bool peer_connection::on_local_network() const
	{
		if (libtorrent::is_local(m_remote.GetPeerAddress())
			|| is_loopback(m_remote.GetPeerAddress())) return true;
		return false;
	}*/

	void peer_connection::get_peer_info(peer_info& p) const
	{
		TORRENT_ASSERT(!associated_torrent().expired());

		ptime now = time_now();

		p.download_rate_peak = m_download_rate_peak;
		p.upload_rate_peak = m_upload_rate_peak;
		p.rtt = m_rtt;
		p.down_speed = statistics().download_rate();
		p.up_speed = statistics().upload_rate();
		p.payload_down_speed = statistics().download_payload_rate();
		p.payload_up_speed = statistics().upload_payload_rate();
		p.pid = pid();
		p.ip = remote();
		p.pending_disk_bytes = m_outstanding_writing_bytes;
		p.send_quota = m_quota[upload_channel];
		p.receive_quota = m_quota[download_channel];
		p.num_pieces = m_num_pieces;
		if (m_download_queue.empty()) p.request_timeout = -1;
		else p.request_timeout = total_seconds(m_requested - now) + m_ses.settings().request_timeout
			+ m_timeout_extend;

		p.download_queue_time = download_queue_time();
		p.queue_bytes = m_outstanding_bytes;
		
		p.total_download = statistics().total_payload_download();
		p.total_upload = statistics().total_payload_upload();

		if (m_bandwidth_channel[upload_channel].throttle() == 0)
			p.upload_limit = -1;
		else
			p.upload_limit = m_bandwidth_channel[upload_channel].throttle();

		if (m_bandwidth_channel[download_channel].throttle() == 0)
			p.download_limit = -1;
		else
			p.download_limit = m_bandwidth_channel[download_channel].throttle();

		p.load_balancing = total_free_upload();

		p.download_queue_length = int(download_queue().size() + m_request_queue.size());
		p.requests_in_buffer = int(m_requests_in_buffer.size() + m_request_queue.size());
		p.target_dl_queue_length = int(desired_queue_size());
		p.upload_queue_length = int(upload_queue().size());
		p.timed_out_requests = 0;
		p.busy_requests = 0;
		for (std::vector<pending_block>::const_iterator i = m_download_queue.begin()
			, end(m_download_queue.end()); i != end; ++i)
		{
			if (i->timed_out) ++p.timed_out_requests;
			if (i->busy) ++p.busy_requests;
		}

		if (boost::optional<piece_block_progress> ret = downloading_piece_progress())
		{
			p.downloading_piece_index = ret->piece_index;
			p.downloading_block_index = ret->block_index;
			p.downloading_progress = ret->bytes_downloaded;
			p.downloading_total = ret->full_block_bytes;
		}
		else
		{
			p.downloading_piece_index = -1;
			p.downloading_block_index = -1;
			p.downloading_progress = 0;
			p.downloading_total = 0;
		}

		p.pieces = get_bitfield();
		p.last_request = now - m_last_request;
		p.last_active = now - (std::max)(m_last_sent, m_last_receive);

		// this will set the flags so that we can update them later
		p.flags = 0;
		get_specific_peer_info(p);

		p.flags |= is_seed() ? peer_info::seed : 0;
		p.flags |= m_snubbed ? peer_info::snubbed : 0;
		p.flags |= m_upload_only ? peer_info::upload_only : 0;
		p.flags |= m_endgame_mode ? peer_info::endgame_mode : 0;
		p.flags |= 0;
		if (peer_info_struct())
		{
			policy::peer* pi = peer_info_struct();
			TORRENT_ASSERT(pi->in_use);
			p.source = pi->source;
			p.failcount = pi->failcount;
			p.num_hashfails = pi->hashfails;
			p.flags |= pi->on_parole ? peer_info::on_parole : 0;
			p.flags |= pi->optimistically_unchoked ? peer_info::optimistic_unchoke : 0;
		}
		else
		{
			p.source = 0;
			p.failcount = 0;
			p.num_hashfails = 0;
		}

		p.remote_dl_rate = m_remote_dl_rate;
		p.send_buffer_size = m_send_buffer.capacity();
		p.used_send_buffer = m_send_buffer.size();
		//p.receive_buffer_size = m_recv_buffer.capacity() + m_disk_recv_buffer_size;
		p.used_receive_buffer = m_recv_pos;
		p.write_state = m_channel_state[upload_channel];
		p.read_state = m_channel_state[download_channel];
		
		// pieces may be empty if we don't have metadata yet
		if (p.pieces.size() == 0)
		{
			p.progress = 0.f;
			p.progress_ppm = 0;
		}
		else
		{
#if TORRENT_NO_FPU
			p.progress = 0.f;
#else
			p.progress = (float)p.pieces.count() / (float)p.pieces.size();
#endif
			p.progress_ppm = boost::uint64_t(p.pieces.count()) * 1000000 / p.pieces.size();
		}

		error_code ec;
        // TODO: 禁用boost::asio
		//p.local_endpoint = get_socket()->local_endpoint(ec);
	}

	// allocates a disk buffer of size 'disk_buffer_size' and replaces the
	// end of the current receive buffer with it. i.e. the receive pos
	// must be <= packet_size - disk_buffer_size
	// the disk buffer can be accessed through release_disk_receive_buffer()
	// when it is queried, the responsibility to free it is transferred
	// to the caller
//	bool peer_connection::allocate_disk_receive_buffer(int disk_buffer_size)
//	{
//		INVARIANT_CHECK;
//		
//		TORRENT_ASSERT(m_packet_size > 0);
//		TORRENT_ASSERT(m_recv_pos <= m_packet_size - disk_buffer_size);
//		//TORRENT_ASSERT(!m_disk_recv_buffer);
//		TORRENT_ASSERT(disk_buffer_size <= 16 * 1024);
//
//		if (disk_buffer_size == 0) return true;
//
//		if (disk_buffer_size > 16 * 1024)
//		{
//			disconnect(errors::invalid_piece_size, 2);
//			return false;
//		}
//
//		// first free the old buffer
//		//m_disk_recv_buffer.reset();
//		// then allocate a new one
//
//		//m_disk_recv_buffer.reset(m_ses.allocate_disk_buffer("receive buffer"));
//		/*if (!m_disk_recv_buffer)
//		{
//			disconnect(errors::no_memory);
//			return false;
//		}
//		m_disk_recv_buffer_size = disk_buffer_size;*/
//		return true;
//	}

//	char* peer_connection::release_disk_receive_buffer()
//	{
//		m_disk_recv_buffer_size = 0;
//		return m_disk_recv_buffer.release();
//	}
	
	// size = the packet size to remove from the receive buffer
	// packet_size = the next packet size to receive in the buffer
	void peer_connection::cut_receive_buffer(int size, int packet_size, int offset)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(packet_size > 0);
		TORRENT_ASSERT(int(m_recv_buffer.size()) >= size);
		TORRENT_ASSERT(int(m_recv_buffer.size()) >= m_recv_pos);
		TORRENT_ASSERT(m_recv_pos >= size + offset);
		TORRENT_ASSERT(offset >= 0);

		if (size > 0)		
			std::memmove(&m_recv_buffer[0] + offset, &m_recv_buffer[0] + offset + size, m_recv_pos - size - offset);

		m_recv_pos -= size;

#ifdef TORRENT_DEBUG
		std::fill(m_recv_buffer.begin() + m_recv_pos, m_recv_buffer.end(), 0);
#endif

		m_packet_size = packet_size;
	}

	void peer_connection::superseed_piece(int index)
	{
		if (index == -1)
		{
			if (m_superseed_piece == -1) return;
			m_superseed_piece = -1;
			
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("*** ending super seed mode");
#endif
			boost::shared_ptr<torrent> t = m_torrent;
			assert(t);

			for (int i = 0; i < int(m_have_piece.size()); ++i)
			{
				if (m_have_piece[i] || !t->have_piece(i)) continue;
#ifdef TORRENT_VERBOSE_LOGGING
				peer_log("==> HAVE    [ piece: %d] (ending super seed)", i);
#endif
				write_have(i);
			}
			
			return;
		}

		assert(!has_piece(index));
		
#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("==> HAVE    [ piece: %d ] (super seed)", index);
#endif
		write_have(index);
		m_superseed_piece = index;
	}

	void peer_connection::update_desired_queue_size()
	{
		if (m_snubbed)
		{
			m_desired_queue_size = 1;
			return;
		}
	
		int download_rate = statistics().download_rate();

		// calculate the desired download queue size
		const int queue_time = m_ses.settings().request_queue_time;
		// (if the latency is more than this, the download will stall)
		// so, the queue size is queue_time * down_rate / 16 kiB
		// (16 kB is the size of each request)
		// the minimum number of requests is 2 and the maximum is 48
		// the block size doesn't have to be 16. So we first query the
		// torrent for it
		boost::shared_ptr<torrent> t = m_torrent;
		const int block_size = t->block_size();

		TORRENT_ASSERT(block_size > 0);
		
		m_desired_queue_size = queue_time * download_rate / block_size;

		if (m_desired_queue_size > m_max_out_request_queue)
			m_desired_queue_size = m_max_out_request_queue;
		if (m_desired_queue_size < min_request_queue)
			m_desired_queue_size = min_request_queue;
	}

	void peer_connection::second_tick(int tick_interval_ms)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		ptime now = time_now();
		boost::intrusive_ptr<peer_connection> me(self());

		// the invariant check must be run before me is destructed
		// in case the peer got disconnected
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;

		// drain the IP overhead from the bandwidth limiters
		if (m_ses.m_settings.rate_limit_ip_overhead)
		{
			int download_overhead = m_statistics.download_ip_overhead();
			int upload_overhead = m_statistics.upload_ip_overhead();
			m_bandwidth_channel[download_channel].use_quota(download_overhead);
			m_bandwidth_channel[upload_channel].use_quota(upload_overhead);

			bandwidth_channel* upc = 0;
			bandwidth_channel* downc = 0;
			if (m_ignore_bandwidth_limits)
			{
				upc = &m_ses.m_local_upload_channel;
				downc = &m_ses.m_local_download_channel;
			}
			else
			{
				upc = &m_ses.m_upload_channel;
				downc = &m_ses.m_download_channel;
			}
	
			//int up_limit = m_bandwidth_channel[upload_channel].throttle();
			//int down_limit = m_bandwidth_channel[download_channel].throttle();

			if (t)
			{
				if (!m_ignore_bandwidth_limits)
				{
					t->m_bandwidth_channel[download_channel].use_quota(download_overhead);
					t->m_bandwidth_channel[upload_channel].use_quota(upload_overhead);
				}

                // TODO: 禁用alert
				/*if (down_limit > 0
					&& download_overhead >= down_limit
					&& t->alerts().should_post<performance_alert>())
				{
					t->alerts().post_alert(performance_alert(t->get_handle()
						, performance_alert::download_limit_too_low));
				}

				if (up_limit > 0
					&& upload_overhead >= up_limit
					&& t->alerts().should_post<performance_alert>())
				{
					t->alerts().post_alert(performance_alert(t->get_handle()
						, performance_alert::upload_limit_too_low));
				}*/
			}
			downc->use_quota(download_overhead);
			upc->use_quota(upload_overhead);
		}

		if (!t || m_disconnecting)
		{
			//m_ses.m_half_open.done(m_connection_ticket);
			if (m_connection_ticket >= -1) m_connection_ticket = -1;
			TORRENT_ASSERT(t || !m_connecting);
			if (m_connecting && t)
			{
				t->dec_num_connecting();
				m_connecting = false;
			}
			disconnect(errors::torrent_aborted);
			return;
		}

		if (m_endgame_mode
			&& m_interesting
			&& m_download_queue.empty()
			&& m_request_queue.empty()
			&& total_seconds(now - m_last_request) >= 5)
		{
			// this happens when we're in strict end-game
			// mode and the peer could not request any blocks
			// because they were all taken but there were still
			// unrequested blocks. Now, 5 seconds later, there
			// might not be any unrequested blocks anymore, so
			// we should try to pick another block to see
			// if we can pick a busy one
#ifdef TORRENT_STATS
			++m_ses.m_end_game_piece_picks;
#endif
			m_last_request = now;
			request_a_block(*t, *this);
			if (m_disconnecting) return;
			send_block_requests();
		}

		on_tick();

		// if the peer hasn't said a thing for a certain
		// time, it is considered to have timed out
		time_duration d;
		d = (std::min)(now - m_last_receive, now - m_last_sent);

		// if we can't read, it means we're blocked on the rate-limiter
		// or the disk, not the peer itself. In this case, don't blame
		// the peer and disconnect it
		bool may_timeout = (m_channel_state[download_channel] & peer_info::bw_network);

		if (may_timeout && d > seconds(m_timeout) && !m_connecting)
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** LAST ACTIVITY [ %d seconds ago ] ***", int(total_seconds(d)));
#endif
			disconnect(errors::timed_out_inactivity);
			return;
		}

		// do not stall waiting for a handshake
		if (may_timeout
			&& !m_connecting
			&& in_handshake()
			&& d > seconds(m_ses.settings().handshake_timeout))
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** NO HANDSHAKE [ waited %d seconds ] ***", int(total_seconds(d)));
#endif
			disconnect(errors::timed_out_no_handshake);
			return;
		}

		// disconnect peers that we unchoked, but
		// they didn't send a request within 20 seconds.
		// but only if we're a seed
		d = now - (std::max)(m_last_unchoke, m_last_incoming_request);
		if (may_timeout
			&& !m_connecting
			&& m_requests.empty()
			//&& m_reading_bytes == 0
			&& !m_choked
			&& m_peer_interested
			&& t && t->is_upload_only()
			&& d > seconds(20))
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** NO REQUEST [ waited %d seconds ] ***", int(total_seconds(d)));
#endif
			disconnect(errors::timed_out_no_request);
			return;
		}

		// if the peer hasn't become interested and we haven't
		// become interested in the peer for 10 minutes, it
		// has also timed out.
		time_duration d1;
		time_duration d2;
		d1 = now - m_became_uninterested;
		d2 = now - m_became_uninteresting;
		time_duration time_limit = seconds(
			m_ses.settings().inactivity_timeout);

		// don't bother disconnect peers we haven't been interested
		// in (and that hasn't been interested in us) for a while
		// unless we have used up all our connection slots
		if (may_timeout
			&& !m_interesting
			&& !m_peer_interested
			&& d1 > time_limit
			&& d2 > time_limit
			&& (m_ses.num_connections() >= m_ses.settings().connections_limit
			|| (t && t->num_peers() >= t->max_connections())))
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** MUTUAL NO INTEREST [ t1: %d t2: %d ]"
				, total_seconds(d1), total_seconds(d2));
#endif
			disconnect(errors::timed_out_no_interest);
			return;
		}

		if (may_timeout
			&& !m_download_queue.empty()
			&& m_quota[download_channel] > 0
			&& now > m_requested + seconds(m_ses.settings().request_timeout
			+ m_timeout_extend))
		{
			snub_peer();
		}

		// if we haven't sent something in too long, send a keep-alive
		keep_alive();

		m_ignore_bandwidth_limits = m_ses.settings().ignore_limits_on_local_network;
			//&& on_local_network();

		m_statistics.second_tick(tick_interval_ms);

		if (m_statistics.upload_payload_rate() > m_upload_rate_peak)
		{
			m_upload_rate_peak = m_statistics.upload_payload_rate();
		}
		if (m_statistics.download_payload_rate() > m_download_rate_peak)
		{
			m_download_rate_peak = m_statistics.download_payload_rate();
		}
		if (is_disconnecting()) return;

		update_desired_queue_size();

        // TODO: 禁用alert
		/*if (m_desired_queue_size == m_max_out_request_queue 
				&& t->alerts().should_post<performance_alert>())
		{
			t->alerts().post_alert(performance_alert(t->get_handle()
				, performance_alert::outstanding_request_limit_reached));
		}*/

		int piece_timeout = m_ses.settings().piece_timeout;
		int rate_limit = INT_MAX;
		if (m_bandwidth_channel[download_channel].throttle() > 0)
			rate_limit = (std::min)(m_bandwidth_channel[download_channel].throttle(), rate_limit);
		if (t->bandwidth_throttle(download_channel) > 0)
			rate_limit = (std::min)(t->bandwidth_throttle(download_channel) / t->num_peers(), rate_limit);
		if (m_ses.m_download_channel.throttle() > 0)
			rate_limit = (std::min)(m_ses.m_download_channel.throttle()
				/ m_ses.num_connections(), rate_limit);

		// rate_limit is an approximation of what this connection is
		// allowed to download. If it is impossible to beat the piece
		// timeout at this rate, adjust it to be realistic

		const int block_size = t->block_size();
		int rate_limit_timeout = rate_limit / block_size;
		if (piece_timeout < rate_limit_timeout) piece_timeout = rate_limit_timeout;

		if (!m_download_queue.empty()
			&& m_quota[download_channel] > 0
			&& now - m_last_piece > seconds(piece_timeout + m_timeout_extend))
		{
			// this peer isn't sending the pieces we've
			// requested (this has been observed by BitComet)
			// in this case we'll clear our download queue and
			// re-request the blocks.
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log("*** PIECE_REQUEST TIMED OUT [ %d time: %d to: %d extend: %d ]"
				, (int)m_download_queue.size(), total_seconds(now - m_last_piece)
				, piece_timeout, m_timeout_extend);
#endif

			snub_peer();
		}

		// If the client sends more data
		// we send it data faster, otherwise, slower.
		// It will also depend on how much data the
		// client has sent us. This is the mean to
		// maintain the share ratio given by m_ratio
		// with all peers.

		if (t->is_upload_only() || is_choked() || t->ratio() == 0.0f)
		{
			// if we have downloaded more than one piece more
			// than we have uploaded OR if we are a seed
			// have an unlimited upload rate
			m_bandwidth_channel[upload_channel].throttle(m_upload_limit);
		}
		else
		{
			size_type bias = 0x10000 + 2 * t->block_size() + m_free_upload;

			const int break_even_time = 15; // seconds.
			size_type have_uploaded = m_statistics.total_payload_upload();
			size_type have_downloaded = m_statistics.total_payload_download();
			int download_speed = m_statistics.download_rate();

			size_type soon_downloaded =
				have_downloaded + (size_type)(download_speed * (break_even_time + break_even_time / 2));

			if (t->ratio() != 1.f)
				soon_downloaded = size_type(soon_downloaded * t->ratio());

			TORRENT_ASSERT((soon_downloaded - have_uploaded + bias) / break_even_time < INT_MAX);
			int upload_speed_limit = int((soon_downloaded - have_uploaded
				+ bias) / break_even_time);

			if (m_upload_limit > 0 && m_upload_limit < upload_speed_limit)
				upload_speed_limit = m_upload_limit;

			upload_speed_limit = (std::min)(upload_speed_limit, (std::numeric_limits<int>::max)());

			m_bandwidth_channel[upload_channel].throttle(
				(std::min)((std::max)(upload_speed_limit, 10), m_upload_limit));
		}

		// update once every minute
		if (now - m_remote_dl_update >= seconds(60))
		{
			if (m_remote_dl_rate > 0)
				m_remote_dl_rate = (m_remote_dl_rate * 2 / 3) + 
					((m_remote_bytes_dled / 3) / 60);
			else
				m_remote_dl_rate = m_remote_bytes_dled / 60;
			
			m_remote_bytes_dled = 0;
			m_remote_dl_update = now;
		}

		fill_send_buffer();
	}

	void peer_connection::snub_peer()
	{
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		if (!m_snubbed)
		{
			m_snubbed = true;
            // TODO: 禁用alert
            /*
			if (m_ses.m_alerts.should_post<peer_snubbed_alert>())
			{
				m_ses.m_alerts.post_alert(peer_snubbed_alert(t->get_handle()
					, m_remote, m_peer_id));
			}*/
		}
		m_desired_queue_size = 1;

		if (on_parole())
		{
			m_timeout_extend += m_ses.settings().request_timeout;
			return;
		}
		if (!t->has_picker()) return;
		piece_picker& picker = t->picker();

		// first, if we have any unsent requests, just
		// wipe those out
		while (!m_request_queue.empty())
		{
			t->picker().abort_download(m_request_queue.back().block, peer_info_struct());
			m_request_queue.pop_back();
		}
		m_queued_time_critical = 0;

		TORRENT_ASSERT(!m_download_queue.empty());

		// request a new block before removing the previous
		// one, in order to prevent it from
		// picking the same block again, stalling the
		// same piece indefinitely.
		m_desired_queue_size = 2;
#ifdef TORRENT_STATS
		++m_ses.m_snubbed_piece_picks;
#endif
		request_a_block(*t, *this);

		// the block we just picked (potentially)
		// hasn't been put in m_download_queue yet.
		// it's in m_request_queue and will be sent
		// once send_block_requests() is called.

		m_desired_queue_size = 1;

		// time out the last request eligible
		// block in the queue
		int i = m_download_queue.size() - 1;
		for (; i >= 0; --i)
		{
			if (!m_download_queue[i].timed_out
				&& !m_download_queue[i].not_wanted)
				break;
		}

		if (i >= 0)
		{
			pending_block& qe = m_download_queue[i];
			piece_block r = qe.block;

			// only time out a request if it blocks the piece
			// from being completed (i.e. no free blocks to
			// request from it)
			piece_picker::downloading_piece p;
			picker.piece_info(qe.block.piece_index, p);
			int free_blocks = picker.blocks_in_piece(qe.block.piece_index)
				- p.finished - p.writing - p.requested;
			if (free_blocks > 0)
			{
				m_timeout_extend += m_ses.settings().request_timeout;
				return;
			}

            // TODO: 禁用alert
            /*
			if (m_ses.m_alerts.should_post<block_timeout_alert>())
			{
				m_ses.m_alerts.post_alert(block_timeout_alert(t->get_handle()
					, remote(), pid(), qe.block.block_index, qe.block.piece_index));
			}*/
			qe.timed_out = true;
			picker.abort_download(r, peer_info_struct());
		}

		send_block_requests();
	}

	std::pair<int, int> peer_connection::preferred_caching() const
	{
		int line_size = 0;
		int expiry = 0;
		if (m_ses.m_settings.guided_read_cache)
		{
			boost::shared_ptr<torrent> t = m_torrent;
			int upload_rate = m_statistics.upload_payload_rate();
			if (upload_rate == 0) upload_rate = 1;

			int num_uploads = m_ses.num_uploads();
			if (num_uploads == 0) num_uploads = 1;

			// assume half of the cache is write cache if we're downloading
			// this torrent as well
			int cache_size = m_ses.m_settings.cache_size / num_uploads;
			if (!t->is_upload_only()) cache_size /= 2;
			// cache_size is the amount of cache we have per peer. The
			// cache line should not be greater than this

			// try to avoid locking caches for more than a couple of seconds
			expiry = cache_size * 16 * 1024 / upload_rate;
			if (expiry < 1) expiry = 1;
			else if (expiry > 10) expiry = 10;

			line_size = cache_size;
		}
		return std::make_pair(line_size, expiry);
	}

	void peer_connection::fill_send_buffer()
	{
        NS_LOG_IP_FUNCTION(ip, this);
#ifdef TORRENT_EXPENSIVE_INVARIANT_CHECKS
		INVARIANT_CHECK;
#endif

		boost::shared_ptr<torrent> t = m_torrent;
		if (!t) return;

		// only add new piece-chunks if the send buffer is small enough
		// otherwise there will be no end to how large it will be!
		
		boost::uint64_t upload_rate = int(m_statistics.upload_rate());

		int buffer_size_watermark = upload_rate
			* m_ses.settings().send_buffer_watermark_factor / 100;

		if (buffer_size_watermark < m_ses.settings().send_buffer_low_watermark)
		{
			buffer_size_watermark = m_ses.settings().send_buffer_low_watermark;
		}
		else if (buffer_size_watermark > m_ses.settings().send_buffer_watermark)
		{
			buffer_size_watermark = m_ses.settings().send_buffer_watermark;
		}

        char temp[10000];
        disk_buffer_holder buf(t->session(), temp);
		while (!m_requests.empty())
			//&& (send_buffer_size() + m_reading_bytes < buffer_size_watermark))
		{
			peer_request& r = m_requests.front();
			
			TORRENT_ASSERT(r.piece >= 0);
			TORRENT_ASSERT(r.piece < (int)m_have_piece.size());
			TORRENT_ASSERT(t->have_piece(r.piece));
			TORRENT_ASSERT(r.start + r.length <= t->torrent_file().piece_size(r.piece));
			TORRENT_ASSERT(r.length > 0 && r.start >= 0);

			//std::pair<int, int> cache = preferred_caching();

            // TODO: 禁用磁盘读写
			/*if (!t->seed_mode() || t->verified_piece(r.piece))
			{
				t->filesystem().async_read(r, boost::bind(&peer_connection::on_disk_read_complete
					, self(), _1, _2, r), cache.first, cache.second);
			}
			else
			{
				// this means we're in seed mode and we haven't yet
				// verified this piece (r.piece)
				t->filesystem().async_read_and_hash(r, boost::bind(&peer_connection::on_disk_read_complete
					, self(), _1, _2, r), cache.second);
				t->verified(r.piece);
			}*/

            // TODO: 将来这里应该写入write_piece
            //setup_send();
            write_piece(r, buf);
			//m_reading_bytes += r.length;

			m_requests.erase(m_requests.begin());
		}
	}

	void peer_connection::assign_bandwidth(int channel, int amount)
	{
		NS_LOG_FUNCTION((channel == upload_channel ? ">>>" : "<<<") << " ASSIGN BANDWIDHT \
                [ bytes: " << amount << " ]");

		TORRENT_ASSERT(amount > 0);
		m_quota[channel] += amount;
		TORRENT_ASSERT(m_channel_state[channel] & peer_info::bw_limit);
		m_channel_state[channel] &= ~peer_info::bw_limit;
		if (channel == upload_channel)
		{
			setup_send();
		}
		else if (channel == download_channel)
		{
			setup_receive();
		}
	}

	int peer_connection::request_upload_bandwidth(
		bandwidth_channel* bwc1
		, bandwidth_channel* bwc2
		, bandwidth_channel* bwc3
		, bandwidth_channel* bwc4)
	{
		shared_ptr<torrent> t = m_torrent;
		int priority;
		priority = 1 + is_interesting() * 2 + m_requests_in_buffer.size();
		if (priority > 255) priority = 255;
		priority += t ? t->priority() << 8 : 0;
		TORRENT_ASSERT(priority <= 0xffff);

		// peers that we are not interested in are non-prioritized
		TORRENT_ASSERT((m_channel_state[upload_channel] & peer_info::bw_limit) == 0);
#ifdef TORRENT_VERBOSE_LOGGING
		peer_log(">>> REQUEST_BANDWIDTH [ upload: %d prio: %d "
			"channels: %p %p %p %p limits: %d %d %d %d ignore: %d ]"
			, int(m_send_buffer.size()), priority
			, bwc1, bwc2, bwc3, bwc4
			, (bwc1?bwc1->throttle():0)
			, (bwc2?bwc2->throttle():0)
			, (bwc3?bwc3->throttle():0)
			, (bwc4?bwc4->throttle():0)
			, m_ignore_bandwidth_limits);
#endif
		return m_ses.m_upload_rate.request_bandwidth(self()
			, (std::max)(m_send_buffer.size(), m_statistics.upload_rate() * 2
				* m_ses.m_settings.tick_interval / 1000)
			, priority
			, bwc1, bwc2, bwc3, bwc4);
	}

	int peer_connection::request_download_bandwidth(
		bandwidth_channel* bwc1
		, bandwidth_channel* bwc2
		, bandwidth_channel* bwc3
		, bandwidth_channel* bwc4)
	{
		shared_ptr<torrent> t = m_torrent;

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<<< REQUEST_BANDWIDTH [ download: %d prio: %d "
			"channels: %p %p %p %p limits: %d %d %d %d ignore: %d ]"
			, int(m_download_queue.size() * 16 * 1024 + 30), m_priority
			, bwc1, bwc2, bwc3, bwc4
			, (bwc1?bwc1->throttle():0)
			, (bwc2?bwc2->throttle():0)
			, (bwc3?bwc3->throttle():0)
			, (bwc4?bwc4->throttle():0)
			, m_ignore_bandwidth_limits);
#endif

		TORRENT_ASSERT(m_priority <= 255);
		int priority = m_priority + (t ? (t->priority() << 8) : 0);

		TORRENT_ASSERT(m_outstanding_bytes >= 0);
		TORRENT_ASSERT((m_channel_state[download_channel] & peer_info::bw_limit) == 0);
		return m_ses.m_download_rate.request_bandwidth(self()
			, (std::max)((std::max)(m_outstanding_bytes, m_packet_size - m_recv_pos) + 30
				, m_statistics.download_rate() * 2 * m_ses.m_settings.tick_interval / 1000)
			, priority , bwc1, bwc2, bwc3, bwc4);
	}

//	void peer_connection::uncork_socket()
//	{
//		if (!m_corked) return;
//		m_corked = false;
//		setup_send();
//	}

	void peer_connection::setup_send()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		if (m_disconnecting) return;

		if (m_channel_state[upload_channel] & (peer_info::bw_network | peer_info::bw_limit)) return;
		
		shared_ptr<torrent> t = m_torrent;

		if (m_quota[upload_channel] <= 0
			&& !m_send_buffer.empty()
			&& !m_connecting)
		{
            NS_LOG_INFO("request upload bandwidth");
			int ret = 0;
            // 张惊：去掉utp_stream
			bool utp = false;
			bool ignore_limits = m_ignore_bandwidth_limits
				|| (!m_ses.m_settings.rate_limit_utp && utp);
			if (!ignore_limits)
			{
				// in this case, we have data to send, but no
				// bandwidth. So, we simply request bandwidth
				// from the bandwidth manager
				ret = request_upload_bandwidth(
					&m_ses.m_upload_channel
					, t ? &t->m_bandwidth_channel[upload_channel] : 0
					, &m_bandwidth_channel[upload_channel]
					, !utp ? &m_ses.m_tcp_upload_channel : 0);
			}
			else
			{
				// in this case, we're a local peer, and the settings
				// are set to ignore rate limits for local peers. So,
				// instead we rate limit ourself against the special
				// global bandwidth channel for local peers, which defaults
				// to unthrottled
				ret = request_upload_bandwidth(&m_ses.m_local_upload_channel
					, &m_bandwidth_channel[upload_channel]);
			}
			if (ret == 0)
			{
				m_channel_state[upload_channel] |= peer_info::bw_limit;
                NS_LOG_IP_INFO(ip, "failed to get send bandwidth");
				return;
			}

			// we were just assigned 'ret' quota
			TORRENT_ASSERT(ret > 0);
			m_quota[upload_channel] += ret;

			peer_log("<<< ASSIGN BANDWIDTH [ bytes: %d ]", ret);
		}

		int quota_left = m_quota[upload_channel];

		if (m_send_buffer.empty()
			//&& m_reading_bytes > 0
			&& quota_left > 0)
		{
			if ((m_channel_state[upload_channel] & peer_info::bw_disk) == 0)
				m_ses.inc_disk_queue(upload_channel);
			m_channel_state[upload_channel] |= peer_info::bw_disk;

		//	if (!m_connecting
		//		&& !m_requests.empty()
		//		&& m_reading_bytes > m_ses.settings().send_buffer_watermark - 0x4000)
		//	{
		//		// we're stalled on the disk. We want to write and we can write
		//		// but our send buffer is empty, waiting to be refilled from the disk
		//		// this either means the disk is slower than the network connection
		//		// or that our send buffer watermark is too small, because we can
		//		// send it all before the disk gets back to us. That's why we only
		//		// trigger this if we've also filled the allowed send buffer. The
		//		// first request would not fill it all the way up because of the
		//		// upload rate being virtually 0. If m_requests is empty, it doesn't
		//		// matter anyway, because we don't have any more requests from the
		//		// peer to hang on to the disk
        //        // TODO: 禁用alert
        //        /*
		//		if (m_ses.m_alerts.should_post<performance_alert>())
		//		{
		//			m_ses.m_alerts.post_alert(performance_alert(t->get_handle()
		//				, performance_alert::send_buffer_watermark_too_low));
		//		}*/
		//	}
		}
		else
		{
			if (m_channel_state[upload_channel] & peer_info::bw_disk)
				m_ses.dec_disk_queue(upload_channel);
			m_channel_state[upload_channel] &= ~peer_info::bw_disk;
		}

		if (!can_write())
		{
			if (m_send_buffer.empty())
			{
				NS_LOG_IP_INFO(ip,">>> SEND BUFFER DEPLETED ["<< 
					" quota: "<<m_quota[upload_channel]<<" ignore: " << (m_ignore_bandwidth_limits? "yes":"no")<< 
                    " buf: "<<int(m_send_buffer.size())<<" connecting: "<<(m_connecting?"yes":"no")<<
                    " disconnecting: " << (m_disconnecting?"yes":"no"));// << " pending_disk: " << m_reading_bytes << " ]");
			}
			else
			{
				NS_LOG_IP_INFO(ip,">>> CANNOT WRITE ["<<
					" quota: " << m_quota[upload_channel] << " ignore: "<<(m_ignore_bandwidth_limits?"yes":"no") << 
                    " buf: " << int(m_send_buffer.size()) << " connecting: " << (m_connecting?"yes":"no") << 
                    " disconnecting: " << (m_disconnecting?"yes": "no"));// << " pending_disk: " << m_reading_bytes << " ]");
			}
			return;
		}

		// send the actual buffer
		int amount_to_send = m_send_buffer.size();
		if (amount_to_send > quota_left)
			amount_to_send = quota_left;

		TORRENT_ASSERT(amount_to_send > 0);

	//	if (m_corked)
	//	{
	//		NS_LOG_IP_INFO(ip,">>> CORKED WRITE [ bytes: " << amount_to_send<< " ]");
	//		return;		
	//	}

        int amount_socket_can_send = m_socket->GetTxAvailable();

        amount_to_send = std::min(amount_to_send, amount_socket_can_send);

		TORRENT_ASSERT((m_channel_state[upload_channel] & peer_info::bw_network) == 0);
		NS_LOG_IP_INFO(ip,">>> ASYNC_WRITE [ bytes: "<<amount_to_send<<" ]");
		//std::list<asio::const_buffer> const& vec = m_send_buffer.build_iovec(amount_to_send);
#if defined TORRENT_ASIO_DEBUGGING
		add_outstanding_async("peer_connection::on_send_data");
#endif
        const std::vector<uint8_t>&  buf = m_send_buffer.build_iovec(amount_to_send);

        uint8_t* pBuf = new uint8_t[buf.size()];
        for (uint i = 0;i < buf.size();++i)
        {
            pBuf[i] = buf[i];
        }

        //Ptr<ns3::Packet> p = Create<ns3::Packet> (pBuf, buf.size());
        int bytesSend = m_socket->Send(pBuf, buf.size(), 0);
        NS_LOG_IP_INFO(ip,"data send size is " << bytesSend);
        if (bytesSend <= 0)
        {
            NS_LOG_INFO ("Error while sending");
        }
        delete pBuf;

        error_code ec;

		m_channel_state[upload_channel] |= peer_info::bw_network;
        on_send_data(ec, bytesSend);
	}

//	void peer_connection::on_disk()
//	{
//		if ((m_channel_state[download_channel] & peer_info::bw_disk) == 0) return;
//		boost::intrusive_ptr<peer_connection> me(this);
//	
//		m_ses.dec_disk_queue(download_channel);
//		m_channel_state[download_channel] &= ~peer_info::bw_disk;
//		setup_receive(read_async);
//	}
    
    void peer_connection::setup_packet_receive(Ptr<Socket> socket)
    {
        NS_LOG_IP_FUNCTION(ip,this);
		//try_read();
        setup_receive();
      //  Address from;
      //  Ptr<ns3::Packet> packet = socket->RecvFrom(from);
      //  if (packet == NULL)
      //  {
      //      NS_LOG_IP_INFO(ip,"No Data Received");
      //      return;
      //  }
      //  uint8_t* pBuf = new uint8_t[packet->GetSize()];
      //  int bufSize = packet->GetSize();
      //  packet->CopyData(pBuf, bufSize);
      //  memcpy(&m_recv_buffer[m_recv_pos], pBuf, bufSize);

      //  on_receive(ec, bufSize);
    }

	void peer_connection::setup_receive()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		if (m_disconnecting)
        {
            return;
        }

		if (m_channel_state[download_channel] & (peer_info::bw_network | peer_info::bw_limit)) return;

		shared_ptr<torrent> t = m_torrent;
		
        // 张惊:处理带宽限制相关的代码
		if (m_quota[download_channel] <= 0
			&& !m_connecting)
		{
            NS_LOG_INFO("request download bandwidth");
			int ret = 0;
            // 张惊:去掉utp_stream
			bool utp = false; 
			bool ignore_limits = m_ignore_bandwidth_limits
				|| (!m_ses.m_settings.rate_limit_utp && utp);
			if (!ignore_limits)
			{
				// in this case, we have outstanding data to
				// receive, but no bandwidth quota. So, we simply
				// request bandwidth from the bandwidth manager
				ret = request_download_bandwidth(
					&m_ses.m_download_channel
					, t ? &t->m_bandwidth_channel[download_channel] : 0
					, &m_bandwidth_channel[download_channel]
					, !utp ? &m_ses.m_tcp_download_channel : 0);
			}
			else
			{
				// in this case, we're a local peer, and the settings
				// are set to ignore rate limits for local peers. So,
				// instead we rate limit ourself against the special
				// global bandwidth channel for local peers, which defaults
				// to unthrottled
				ret = request_download_bandwidth(&m_ses.m_local_download_channel
					, &m_bandwidth_channel[download_channel]);
			}
			if (ret == 0)
			{
				m_channel_state[download_channel] |= peer_info::bw_limit;
				return;
			}

			// we were just assigned 'ret' quota
			TORRENT_ASSERT(ret > 0);
			m_quota[download_channel] += ret;

			NS_LOG_IP_INFO(ip, ">>> ASSIGN BANDWIDTH [ bytes: " << ret << " ]");
		}
		
//		if (!can_read(&m_channel_state[download_channel]))
//		{
//#ifdef TORRENT_VERBOSE_LOGGING
//			peer_log("<<< CANNOT READ [ quota: %d ignore: %s "
//				"can-write-to-disk: %s queue-limit: %d disconnecting: %s ]"
//				, m_quota[download_channel]
//				, (m_ignore_bandwidth_limits?"yes":"no")
//				, (m_ses.can_write_to_disk()?"yes":"no")
//				, m_ses.settings().max_queued_disk_bytes
//				, (m_disconnecting?"yes":"no"));
//#endif
//			// if we block reading, waiting for the disk, we will wake up
//			// by the disk_io_thread posting a message every time it drops
//			// from being at or exceeding the limit down to below the limit
//			return;
//		}
        try_read();
	}

	size_t peer_connection::try_read()
	{
        NS_LOG_IP_FUNCTION(ip, this);
        
        error_code ec;
		TORRENT_ASSERT(m_packet_size > 0);
		int max_receive = m_packet_size - m_recv_pos;
		TORRENT_ASSERT(max_receive >= 0);

		if (m_recv_pos >= m_soft_packet_size) m_soft_packet_size = 0;
		if (m_soft_packet_size && max_receive > m_soft_packet_size - m_recv_pos)
			max_receive = m_soft_packet_size - m_recv_pos;
		int quota_left = m_quota[download_channel];

		if (max_receive > quota_left)
			max_receive = quota_left;

		if (max_receive == 0)
		{
			return 0;
		}

		TORRENT_ASSERT(m_recv_pos >= 0);
		TORRENT_ASSERT(m_packet_size > 0);

		if (!can_read())
		{
            NS_LOG_IP_INFO(ip, "unable to read");
			ec = asio::error::would_block;
			return 0;
		}

		int regular_buffer_size = m_packet_size;// - m_disk_recv_buffer_size;

		if (int(m_recv_buffer.size()) < regular_buffer_size)
			m_recv_buffer.resize(round_up8(regular_buffer_size));

            // TODO: 禁用boost::asio
		//boost::array<asio::mutable_buffer, 2> vec;
		//int num_bufs = 0;
		/*if (!m_disk_recv_buffer || regular_buffer_size >= m_recv_pos + max_receive)
		{
			// only receive into regular buffer
			TORRENT_ASSERT(m_recv_pos + max_receive <= int(m_recv_buffer.size()));
			vec[0] = asio::buffer(&m_recv_buffer[m_recv_pos], max_receive);
			num_bufs = 1;
		}*/

        // 张惊：这里将原来的同步异步两种读发改为同步一种，为了保持逻辑的一致性，在要求异步的情况下，加入了对on_receiv_data的调用
		size_t ret = 0;

        ns3::Address addr;
        Ptr<ns3::Packet> packet = m_socket->RecvFrom(addr);//Recv(max_receive, 0);
        if (packet == NULL)
        {
            NS_LOG_IP_INFO(ip,"no data received");
            return 0;
        }

        uint8_t* pBuf = new uint8_t[packet->GetSize()];
        uint bufSize = packet->GetSize();
        packet->CopyData(pBuf, bufSize);
        if (m_recv_buffer.size() < bufSize + m_recv_pos)
        {
            m_recv_buffer.resize(bufSize + m_recv_pos);
        }
        //if (bufSize != 536)
        {
            memcpy(&m_recv_buffer[m_recv_pos], pBuf, bufSize);
        }

		NS_LOG_IP_INFO(ip,"<<< SYNC_READ [ max: " << max_receive << " real:" <<bufSize);
        on_receive_data(ec, bufSize);
        delete pBuf;
        ret = bufSize;

		return ret;
	}

	void peer_connection::reset_recv_buffer(int packet_size)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		TORRENT_ASSERT(packet_size > 0);
		sha1_hash info_hash;

		if (m_recv_pos > m_packet_size)
		{
			cut_receive_buffer(m_packet_size, packet_size);
			return;
		}
		m_recv_pos = 0;
		m_packet_size = packet_size;
	}

	void nop(char*) {}

	void peer_connection::append_const_send_buffer(char const* buffer, int size)
	{
		m_send_buffer.append_buffer((char*)buffer, size, size, &nop);
#if defined TORRENT_STATS && defined TORRENT_DISK_STATS
		m_ses.m_buffer_usage_logger << log_time() << " append_const_send_buffer: " << size << std::endl;
		m_ses.log_buffer_usage();
#endif
	}

	void peer_connection::send_buffer(char const* buf, int size, int flags
		, void (*fun)(char*, int, void*), void* userdata)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		if (flags == message_type_request)
			m_requests_in_buffer.push_back(m_send_buffer.size() + size);

		int free_space = m_send_buffer.space_in_last_buffer();
		if (free_space > size)
            free_space = size;
		if (free_space > 0)
		{
			char* dst = m_send_buffer.append(buf, free_space);
			TORRENT_ASSERT(dst != 0);
			if (fun) fun(dst, free_space, userdata);
			size -= free_space;
			buf += free_space;
#if defined TORRENT_STATS && defined TORRENT_DISK_STATS
			m_ses.m_buffer_usage_logger << log_time() << " send_buffer: "
				<< free_space << std::endl;
			m_ses.log_buffer_usage();
#endif
		}
		if (size <= 0)
        {
            return;
        }

#if defined TORRENT_STATS && defined TORRENT_DISK_STATS
		m_ses.m_buffer_usage_logger << log_time() << " send_buffer_alloc: " << size << std::endl;
		m_ses.log_buffer_usage();
#endif
		int i = 0;
		while (size > 0)
		{
			char* chain_buf = m_ses.allocate_buffer();
			if (chain_buf == 0)
			{
				disconnect(errors::no_memory);
				return;
			}

			int buf_size = (std::min)(int(aux::session_impl::send_buffer_size), size);
			memcpy(chain_buf, buf, buf_size);
			if (fun) fun(chain_buf, buf_size, userdata);
			buf += buf_size;
			size -= buf_size;
			m_send_buffer.append_buffer(chain_buf, aux::session_impl::send_buffer_size, buf_size
				, boost::bind(&session_impl::free_buffer, boost::ref(m_ses), _1));
			++i;
		}
		setup_send();
	}

	template<class T>
	struct set_to_zero
	{
		set_to_zero(T& v, bool cond): m_val(v), m_cond(cond) {}
		void fire() { if (!m_cond) return; m_cond = false; m_val = 0; }
		~set_to_zero() { if (m_cond) m_val = 0; }
	private:
		T& m_val;
		bool m_cond;
	};

	// --------------------------
	// RECEIVE DATA
	// --------------------------

	void peer_connection::on_receive_data(const error_code& error
		, std::size_t bytes_transferred)
	{
        NS_LOG_IP_FUNCTION(ip, this);
#ifdef TORRENT_STATS
		++m_ses.m_num_messages[aux::session_impl::on_read_counter];
		int size = 8;
		int index = 0;
		while (bytes_transferred > size + 13) { size <<= 1; ++index; }
		int num_max = sizeof(m_ses.m_recv_buffer_sizes)/sizeof(m_ses.m_recv_buffer_sizes[0]);
		if (index >= num_max) index = num_max - 1;
		++m_ses.m_recv_buffer_sizes[index];
#endif

		// keep ourselves alive in until this function exits in
		// case we disconnect
		// this needs to be created before the invariant check,
		// to keep the object alive through the exit check
		boost::intrusive_ptr<peer_connection> me(self());

		// flush the send buffer at the end of this function
		//cork _c(*this);

		INVARIANT_CHECK;

        stringstream ss;
        ss<<"<<< ON_RECEIVE_DATA [ bytes: "<<bytes_transferred<<" error: " << error.message().c_str()<<" ]";
        NS_LOG_IP_INFO(ip,ss.str());
			
		// leave this bit set until we're done looping, reading from the socket.
		// that way we don't trigger any async read calls until the end of this
		// function.
		TORRENT_ASSERT(m_channel_state[download_channel] & peer_info::bw_network);

		int bytes_in_loop = bytes_transferred;

		if (m_extension_outstanding_bytes > 0)
			m_extension_outstanding_bytes -= (std::min)(m_extension_outstanding_bytes, int(bytes_transferred));

		if (error)
		{
			peer_log("*** ERROR [ in peer_connection::on_receive_data error: %s ]"
				, error.message().c_str());
			m_statistics.trancieve_ip_packet(bytes_in_loop, false);
			on_receive(error, bytes_transferred);
			disconnect(error);
			return;
		}

		int num_loops = 0;
		do
		{
			TORRENT_ASSERT(int(m_recv_pos + bytes_transferred) <= m_packet_size);
			NS_LOG_IP_INFO(ip, "<<< read " << int(bytes_transferred) << " bytes");
			// correct the dl quota usage, if not all of the buffer was actually read
			TORRENT_ASSERT(int(bytes_transferred) <= m_quota[download_channel]);
			m_quota[download_channel] -= bytes_transferred;

			if (m_disconnecting)
			{
				m_statistics.trancieve_ip_packet(bytes_in_loop, false);
				return;
			}
	
			TORRENT_ASSERT(m_packet_size > 0);
			TORRENT_ASSERT(bytes_transferred > 0);

			m_last_receive = time_now();
			m_recv_pos += bytes_transferred;
			//TORRENT_ASSERT(m_recv_pos <= int(m_recv_buffer.size()
		//		+ m_disk_recv_buffer_size));

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			size_type cur_payload_dl = m_statistics.last_payload_downloaded();
			size_type cur_protocol_dl = m_statistics.last_protocol_downloaded();
#endif
			{
				INVARIANT_CHECK;
				on_receive(error, bytes_transferred);
			}
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			TORRENT_ASSERT(m_statistics.last_payload_downloaded() - cur_payload_dl >= 0);
			TORRENT_ASSERT(m_statistics.last_protocol_downloaded() - cur_protocol_dl >= 0);
			size_type stats_diff = m_statistics.last_payload_downloaded() - cur_payload_dl +
				m_statistics.last_protocol_downloaded() - cur_protocol_dl;
			TORRENT_ASSERT(stats_diff == int(bytes_transferred));
#endif
			if (m_disconnecting)
            {
                NS_LOG_IP_INFO(ip, "disconnecting");
                return;
            }

			TORRENT_ASSERT(m_packet_size > 0);

			if (m_peer_choked
				&& m_recv_pos == 0
				&& (m_recv_buffer.capacity() - m_packet_size) > 128)
			{
				// round up to an even 8 bytes since that's the RC4 blocksize
				buffer(round_up8(m_packet_size)).swap(m_recv_buffer);
			}

			if (m_recv_pos >= m_soft_packet_size) m_soft_packet_size = 0;

			if (num_loops > 20) break;

			bytes_transferred = try_read();
			TORRENT_ASSERT(bytes_transferred > 0 || ec);
            // TODO: 禁用boost::asio
			/*if (ec && ec != asio::error::would_block)
			{
				m_statistics.trancieve_ip_packet(bytes_in_loop, false);
				disconnect(ec);
				return;
			}
			if (ec == asio::error::would_block) break;*/
			bytes_in_loop += bytes_transferred;
			++num_loops;
		}
		while (bytes_transferred > 0);

		if (is_seed())
		{
			boost::shared_ptr<torrent> t = m_torrent;
			if (t) t->seen_complete();
		}

		m_statistics.trancieve_ip_packet(bytes_in_loop, false);

		// allow reading from the socket again
		TORRENT_ASSERT(m_channel_state[download_channel] & peer_info::bw_network);
		m_channel_state[download_channel] &= ~peer_info::bw_network;

		//setup_receive();
	}

	bool peer_connection::can_write() const
	{
		// if we have requests or pending data to be sent or announcements to be made
		// we want to send data
		return !m_send_buffer.empty()
			&& m_quota[upload_channel] > 0
			&& !m_connecting;
	}

	bool peer_connection::can_read(char* state) const
	{
		boost::shared_ptr<torrent> t = m_torrent;

		bool bw_limit = m_quota[download_channel] > 0;

		if (!bw_limit) return false;

		bool disk = m_ses.settings().max_queued_disk_bytes == 0
			/*|| m_ses.can_write_to_disk()*/
			// don't block this peer because of disk saturation
			// if we're not downloading any pieces from it
			|| m_outstanding_bytes == 0;

		if (!disk)
		{
			if (state)
			{
				if ((*state & peer_info::bw_disk) == 0)
					m_ses.inc_disk_queue(download_channel);
				*state |= peer_info::bw_disk;
			}
			return false;
		}

		return !m_connecting && !m_disconnecting;
	}

	void peer_connection::on_connect(int ticket)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		TORRENT_ASSERT(m_ses.is_network_thread());
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		// in case we disconnect here, we need to
		// keep the connection alive until the
		// exit invariant check is run
		boost::intrusive_ptr<peer_connection> me(self());
#endif
		//INV/ARIANT_CHECK;

		error_code ec;
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
		//(*m_ses.m_logger) << time_now_string() << " ON_CONNECT: " << print_endpoint(m_remote) << "\n";
#endif

		if (ticket == -1)
		{
            NS_LOG_ERROR("invalid ticket");
			disconnect(asio::error::operation_aborted);
			return;		
		}

		m_connection_ticket = ticket;
		boost::shared_ptr<torrent> t = m_torrent;

		m_queued = false;

		if (!t)
		{
			TORRENT_ASSERT(!m_connecting);
			disconnect(errors::torrent_aborted);
			return;
		}

		TORRENT_ASSERT(m_connecting);

		//m_socket->open(m_remote.protocol(), ec);
		if (ec)
		{
			disconnect(ec);
			return;
		}

        ns3::InetSocketAddress bind_interface = t->get_interface();
	
		std::pair<int, int> const& out_ports = m_ses.settings().outgoing_ports;
		if (out_ports.first > 0 && out_ports.second >= out_ports.first)
		{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
			peer_log(">>> SET_REUSE_ADDRESS");
#endif
		//	m_socket->set_option(socket_acceptor::reuse_address(true), ec);
			// ignore errors because the underlying socket may not
			// be opened yet. This happens when we're routing through
			// a proxy. In that case, we don't yet know the address of
			// the proxy server, and more importantly, we don't know
			// the address family of its address. This means we can't
			// open the socket yet. The socks abstraction layer defers
			// opening it.
			ec.clear();
			bind_interface.SetPort(m_ses.next_port());
		}

        // TODO: 这里会报错，暂时关闭，等待进一步的调试
		// if we're not binding to a specific interface, bind
		// to the same protocol family as the target endpoint
		//if (is_any(bind_interface.ConvertTo()))
		//{
		//	bind_interface.setIp(Ipv4Address::GetAny()); 
		//}

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING
		//peer_log(">>> BIND [ ep: %s ]", print_endpoint(bind_interface).c_str());
#endif

		//m_socket->Bind(bind_interface);
        m_socket->Bind();
		if (ec)
		{
			disconnect(ec);
			return;
		}
		NS_LOG_IP_INFO(ip,">>> ASYNC_CONNECT [ dst: "<<m_remote.GetLocalAddress() << ", "<< m_remote.GetLocalPort() << " ]");
		
        //m_socket->SetConnectCallback (
        //    MakeCallback (&peer_connection::testRecv, this),
        //    MakeCallback (&peer_connection::onConnectFailed, this));
        m_socket->Connect(ns3::InetSocketAddress(m_remote.GetLocalAddress(), m_remote.GetLocalPort()));
		m_connect = time_now_hires();
		m_statistics.sent_syn(false);

        //on_connection_complete(ec);
        /*
		if (t->alerts().should_post<peer_connect_alert>())
		{
			t->alerts().post_alert(peer_connect_alert(
				t->get_handle(), remote(), pid()));
		}*/
#if defined TORRENT_VERBOSE_LOGGING
		//peer_log("*** LOCAL ENDPOINT[ e: %s ]", print_endpoint(m_socket->local_endpoint(ec)).c_str());
#endif
	}

    void peer_connection::onConnectFailed(ns3::Ptr<ns3::Socket> sock)
    {
        NS_LOG_IP_FUNCTION(ip,this);
    }
	
	void peer_connection::on_connection_complete(ns3::Ptr<ns3::Socket> sock)
	{
        NS_LOG_IP_FUNCTION(ip,this);
#if defined TORRENT_ASIO_DEBUGGING
		complete_async("peer_connection::on_connection_complete");
#endif
		ptime completed = time_now_hires();

		TORRENT_ASSERT(m_ses.is_network_thread());

		INVARIANT_CHECK;

		m_rtt = total_milliseconds(completed - m_connect);

		if (m_disconnecting) return;

		// if t is NULL, we better not be connecting, since
		// we can't decrement the connecting counter
//		m_ses.m_half_open.done(m_connection_ticket);
        if (m_connecting && m_torrent)
        {
            m_torrent->dec_num_connecting();
            m_connecting = false;
        }

		if (m_disconnecting) return;
		m_last_receive = time_now();

		// this means the connection just succeeded

		m_statistics.received_synack(false);

		/*if (m_remote == m_socket->local_endpoint(ec))
		{
			// if the remote endpoint is the same as the local endpoint, we're connected
			// to ourselves
			if (m_peer_info && t) t->get_policy().ban_peer(m_peer_info);
			disconnect(errors::self_connection, 1);
			return;
		}
		*/

		this->on_connected();
		this->setup_send();
        
        m_socket->SetRecvCallback(MakeCallback (&peer_connection::setup_packet_receive, this));
	}
	
	// --------------------------
	// SEND DATA
	// --------------------------

	void peer_connection::on_send_data(error_code const& error
		, std::size_t bytes_transferred)
	{
        NS_LOG_IP_FUNCTION(ip,this);
#ifdef TORRENT_STATS
		++m_ses.m_num_messages[aux::session_impl::on_write_counter];
		int size = 8;
		int index = 0;
		while (bytes_transferred > size + 13) { size <<= 1; ++index; }
		int num_max = sizeof(m_ses.m_send_buffer_sizes)/sizeof(m_ses.m_send_buffer_sizes[0]);
		if (index >= num_max) index = num_max - 1;
		++m_ses.m_send_buffer_sizes[index];
#endif
		TORRENT_ASSERT(m_ses.is_network_thread());

		peer_log("*** ON_SEND_DATA [ bytes: %d error: %s ]"
			, int(bytes_transferred), error.message().c_str());

		INVARIANT_CHECK;

#if defined TORRENT_ASIO_DEBUGGING
		complete_async("peer_connection::on_send_data");
#endif
		// keep ourselves alive in until this function exits in
		// case we disconnect
		boost::intrusive_ptr<peer_connection> me(self());

		TORRENT_ASSERT(m_channel_state[upload_channel] & peer_info::bw_network);

		m_send_buffer.pop_front(bytes_transferred);

		for (std::vector<int>::iterator i = m_requests_in_buffer.begin()
			, end(m_requests_in_buffer.end()); i != end; ++i)
			*i -= bytes_transferred;

		while (!m_requests_in_buffer.empty()
			&& m_requests_in_buffer.front() <= 0)
			m_requests_in_buffer.erase(m_requests_in_buffer.begin());
		
		m_channel_state[upload_channel] &= ~peer_info::bw_network;

		TORRENT_ASSERT(int(bytes_transferred) <= m_quota[upload_channel]);
		m_quota[upload_channel] -= bytes_transferred;

		m_statistics.trancieve_ip_packet(bytes_transferred, false);

		peer_log(">>> wrote %d bytes", int(bytes_transferred));

		if (error)
		{
			peer_log("**ERROR**: %s [in peer_connection::on_send_data]", error.message().c_str());
			disconnect(error);
			return;
		}
		if (m_disconnecting)
        {
            NS_LOG_ERROR("error: disconnecting");
            return;
        }

		TORRENT_ASSERT(!m_connecting);
		TORRENT_ASSERT(bytes_transferred > 0);

		m_last_sent = time_now();

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		size_type cur_payload_ul = m_statistics.last_payload_uploaded();
		size_type cur_protocol_ul = m_statistics.last_protocol_uploaded();
#endif
		on_sent(error, bytes_transferred);
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		TORRENT_ASSERT(m_statistics.last_payload_uploaded() - cur_payload_ul >= 0);
		TORRENT_ASSERT(m_statistics.last_protocol_uploaded() - cur_protocol_ul >= 0);
		size_type stats_diff = m_statistics.last_payload_uploaded() - cur_payload_ul
			+ m_statistics.last_protocol_uploaded() - cur_protocol_ul;
		TORRENT_ASSERT(stats_diff == int(bytes_transferred));
#endif

        if (!m_send_buffer.empty())
        {
	//        fill_send_buffer();

	        setup_send();
        }
	}

#ifdef TORRENT_DEBUG
	struct peer_count_t
	{
		peer_count_t(): num_peers(0), num_peers_with_timeouts(0), num_peers_with_nowant(0), num_not_requested(0) {}
		int num_peers;
		int num_peers_with_timeouts;
		int num_peers_with_nowant;
		int num_not_requested;
//		std::vector<peer_connection const*> peers;
	};

	void peer_connection::check_invariant() const
	{
		TORRENT_ASSERT(m_in_use == 1337);
		TORRENT_ASSERT(m_queued_time_critical <= int(m_request_queue.size()));
		TORRENT_ASSERT(m_accept_fast.size() == m_accept_fast_piece_cnt.size());

		//TORRENT_ASSERT(bool(m_disk_recv_buffer) == (m_disk_recv_buffer_size > 0));

		TORRENT_ASSERT(m_upload_limit >= 0);
		TORRENT_ASSERT(m_download_limit >= 0);

		boost::shared_ptr<torrent> t = m_torrent;

		if (!m_disconnect_started && m_initialized)
		{
			// none of this matters if we're disconnecting anyway
			if (t->is_finished())
				TORRENT_ASSERT(!is_interesting());
			if (is_seed())
				TORRENT_ASSERT(upload_only());
		}

		if (m_disconnecting)
		{
			TORRENT_ASSERT(m_download_queue.empty());
			TORRENT_ASSERT(m_request_queue.empty());
			TORRENT_ASSERT(!t);
			TORRENT_ASSERT(m_disconnect_started);
		}
		else if (!m_in_constructor)
		{
			TORRENT_ASSERT(m_ses.has_peer((peer_connection*)this));
		}

		TORRENT_ASSERT(m_outstanding_bytes >= 0);
		if (t && !m_disconnecting)
		{
			torrent_info const& ti = t->torrent_file();
			// if the piece is fully downloaded, we might have popped it from the
			// download queue already
			int outstanding_bytes = 0;
			bool in_download_queue = false;
			int block_size = t->block_size();
			piece_block last_block(ti.num_pieces()-1
				, (ti.piece_size(ti.num_pieces()-1) + block_size - 1) / block_size);
			for (std::vector<pending_block>::const_iterator i = m_download_queue.begin()
				, end(m_download_queue.end()); i != end; ++i)
			{
				TORRENT_ASSERT(i->block.piece_index <= last_block.piece_index);
				TORRENT_ASSERT(i->block.piece_index < last_block.piece_index
					|| i->block.block_index <= last_block.block_index);
				if (m_received_in_piece && i == m_download_queue.begin())
				{
					in_download_queue = true;
					// this assert is not correct since block may have different sizes
					// and may not be returned in the order they were requested
//					TORRENT_ASSERT(t->to_req(i->block).length >= m_received_in_piece);
					outstanding_bytes += t->to_req(i->block).length - m_received_in_piece;
				}
				else
				{
					outstanding_bytes += t->to_req(i->block).length;
				}
			}
			//if (p && p->bytes_downloaded < p->full_block_bytes) TORRENT_ASSERT(in_download_queue);

			TORRENT_ASSERT(m_outstanding_bytes == outstanding_bytes);
		}
/*
		if (m_channel_state[download_channel] == peer_info::bw_limit)
			TORRENT_ASSERT(m_quota[download_channel] == 0);
		if (m_channel_state[upload_channel] == peer_info::bw_limit)
			TORRENT_ASSERT(m_quota[upload_channel] == 0);
*/
		std::set<piece_block> unique;
		std::transform(m_download_queue.begin(), m_download_queue.end()
			, std::inserter(unique, unique.begin()), boost::bind(&pending_block::block, _1));
		std::transform(m_request_queue.begin(), m_request_queue.end()
			, std::inserter(unique, unique.begin()), boost::bind(&pending_block::block, _1));
		TORRENT_ASSERT(unique.size() == m_download_queue.size() + m_request_queue.size());
		if (m_peer_info)
		{
			TORRENT_ASSERT(m_peer_info->prev_amount_upload == 0);
			TORRENT_ASSERT(m_peer_info->prev_amount_download == 0);
			TORRENT_ASSERT(m_peer_info->connection == this
				|| m_peer_info->connection == 0);

			if (m_peer_info->optimistically_unchoked)
				TORRENT_ASSERT(!is_choked());
		}

		TORRENT_ASSERT(m_have_piece.count() == m_num_pieces);

		if (!t)
		{
#ifdef TORRENT_EXPENSIVE_INVARIANT_CHECKS
			// since this connection doesn't have a torrent reference
			// no torrent should have a reference to this connection either
			for (aux::session_impl::torrent_map::const_iterator i = m_ses.m_torrents.begin()
				, end(m_ses.m_torrents.end()); i != end; ++i)
				TORRENT_ASSERT(!i->second->has_peer((peer_connection*)this));
#endif
			return;
		}

		if (m_initialized)
			TORRENT_ASSERT(t->torrent_file().num_pieces() == int(m_have_piece.size()));

		// in share mode we don't close redundant connections
		if (m_ses.settings().close_redundant_connections && !t->share_mode())
		{
			// make sure upload only peers are disconnected
			if (t->is_upload_only()
				&& m_upload_only
				&& has_metadata())
				TORRENT_ASSERT(m_disconnect_started || t->graceful_pause() || t->has_error());

			if (m_upload_only
				&& !m_interesting
				&& m_bitfield_received
				//&& t->are_files_checked()
				&& has_metadata())
				TORRENT_ASSERT(m_disconnect_started);
		}

		if (!m_disconnect_started && m_initialized && m_ses.settings().close_redundant_connections)
		{
			// none of this matters if we're disconnecting anyway
			if (t->is_upload_only())
				TORRENT_ASSERT(!m_interesting || t->graceful_pause() || t->has_error());
			if (is_seed())
				TORRENT_ASSERT(m_upload_only);
		}

		if (t->has_picker())
		{
			std::map<piece_block, peer_count_t> num_requests;
			for (torrent::const_peer_iterator i = t->begin(); i != t->end(); ++i)
			{
				// make sure this peer is not a dangling pointer
#ifdef TORRENT_EXPENSIVE_INVARIANT_CHECKS
				TORRENT_ASSERT(m_ses.has_peer(*i));
#endif
				peer_connection const& p = *(*i);
				for (std::vector<pending_block>::const_iterator i = p.request_queue().begin()
					, end(p.request_queue().end()); i != end; ++i)
				{
					++num_requests[i->block].num_peers;
					++num_requests[i->block].num_peers_with_timeouts;
					++num_requests[i->block].num_peers_with_nowant;
					++num_requests[i->block].num_not_requested;
//					num_requests[i->block].peers.push_back(&p);
				}
				for (std::vector<pending_block>::const_iterator i = p.download_queue().begin()
					, end(p.download_queue().end()); i != end; ++i)
				{
					if (!i->not_wanted && !i->timed_out) ++num_requests[i->block].num_peers;
					if (i->timed_out) ++num_requests[i->block].num_peers_with_timeouts;
					if (i->not_wanted) ++num_requests[i->block].num_peers_with_nowant;
//					num_requests[i->block].peers.push_back(&p);
				}
			}
			for (std::map<piece_block, peer_count_t>::iterator i = num_requests.begin()
				, end(num_requests.end()); i != end; ++i)
			{
				piece_block b = i->first;
				peer_count_t const& pc = i->second;
				int count = pc.num_peers;
				int count_with_timeouts = pc.num_peers_with_timeouts;
				int count_with_nowant = pc.num_peers_with_nowant;
				(void)count_with_timeouts;
				(void)count_with_nowant;
				int picker_count = t->picker().num_peers(b);
				if (!t->picker().is_downloaded(b))
					TORRENT_ASSERT(picker_count == count);
			}
		}
#ifdef TORRENT_EXPENSIVE_INVARIANT_CHECKS
		if (m_peer_info && type() == bittorrent_connection)
		{
			policy::const_iterator i = t->get_policy().begin_peer();
			policy::const_iterator end = t->get_policy().end_peer();
			for (; i != end; ++i)
			{
				if (*i == m_peer_info) break;
			}
			TORRENT_ASSERT(i != end);
		}
#endif
		if (t->has_picker() && !t->is_aborted())
		{
			// make sure that pieces that have completed the download
			// of all their blocks are in the disk io thread's queue
			// to be checked.
			const std::vector<piece_picker::downloading_piece>& dl_queue
				= t->picker().get_download_queue();
			for (std::vector<piece_picker::downloading_piece>::const_iterator i =
				dl_queue.begin(); i != dl_queue.end(); ++i)
			{
				const int blocks_per_piece = t->picker().blocks_in_piece(i->index);

				bool complete = true;
				for (int j = 0; j < blocks_per_piece; ++j)
				{
					if (i->info[j].state == piece_picker::block_info::state_finished)
						continue;
					complete = false;
					break;
				}
/*
// this invariant is not valid anymore since the completion event
// might be queued in the io service
				if (complete && !piece_failed)
				{
					disk_io_job ret = m_ses.m_disk_thread.find_job(
						&t->filesystem(), -1, i->index);
					TORRENT_ASSERT(ret.action == disk_io_job::hash || ret.action == disk_io_job::write);
					TORRENT_ASSERT(ret.piece == i->index);
				}
*/
			}
		}

// extremely expensive invariant check
/*
		if (!t->is_seed())
		{
			piece_picker& p = t->picker();
			const std::vector<piece_picker::downloading_piece>& dlq = p.get_download_queue();
			const int blocks_per_piece = static_cast<int>(
				t->torrent_file().piece_length() / t->block_size());

			for (std::vector<piece_picker::downloading_piece>::const_iterator i =
				dlq.begin(); i != dlq.end(); ++i)
			{
				for (int j = 0; j < blocks_per_piece; ++j)
				{
					if (std::find(m_request_queue.begin(), m_request_queue.end()
						, piece_block(i->index, j)) != m_request_queue.end()
						||
						std::find(m_download_queue.begin(), m_download_queue.end()
						, piece_block(i->index, j)) != m_download_queue.end())
					{
						TORRENT_ASSERT(i->info[j].peer == m_remote);
					}
					else
					{
						TORRENT_ASSERT(i->info[j].peer != m_remote || i->info[j].finished);
					}
				}
			}
		}
*/
	}
#endif

	peer_connection::peer_speed_t peer_connection::peer_speed()
	{
		shared_ptr<torrent> t = m_torrent;
		TORRENT_ASSERT(t);

		int download_rate = int(statistics().download_payload_rate());
		int torrent_download_rate = int(t->statistics().download_payload_rate());

		if (download_rate > 512 && download_rate > torrent_download_rate / 16)
			m_speed = fast;
		else if (download_rate > 4096 && download_rate > torrent_download_rate / 64)
			m_speed = medium;
		else if (download_rate < torrent_download_rate / 15 && m_speed == fast)
			m_speed = medium;
		else
			m_speed = slow;

		return m_speed;
	}

	void peer_connection::keep_alive()
	{
#ifdef TORRENT_EXPENSIVE_INVARIANT_CHECKS
		INVARIANT_CHECK;
#endif

		time_duration d;
		d = time_now() - m_last_sent;
		if (libtorrent::total_seconds(d) < m_timeout / 2) return;
		
		if (m_connecting) return;
		if (in_handshake()) return;

		// if the last send has not completed yet, do not send a keep
		// alive
		if (m_channel_state[upload_channel] & peer_info::bw_network) return;

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("==> KEEPALIVE");
#endif

		m_last_sent = time_now();
		write_keepalive();
	}

	bool peer_connection::is_seed() const
	{
		// if m_num_pieces == 0, we probably don't have the
		// metadata yet.
		boost::shared_ptr<torrent> t = m_torrent;
		return m_num_pieces == (int)m_have_piece.size() && m_num_pieces > 0 && t;
	}

	void peer_connection::set_share_mode(bool u)
	{
		// if the peer is a seed, ignore share mode messages
		if (is_seed()) return;

		m_share_mode = u;
	}

	void peer_connection::set_upload_only(bool u)
	{
		// if the peer is a seed, don't allow setting
		// upload_only to false
		if (m_upload_only || is_seed()) return;

		m_upload_only = u;
		boost::shared_ptr<torrent> t = associated_torrent();
		t->get_policy().set_seed(m_peer_info, u);
		disconnect_if_redundant();
	}

}
