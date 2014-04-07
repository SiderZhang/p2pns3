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

#ifndef TORRENT_TORRENT_HPP_INCLUDE
#define TORRENT_TORRENT_HPP_INCLUDE

#include <algorithm>
#include <vector>
#include <set>
#include <list>
#include <deque>
#include <map>

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/limits.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/intrusive_ptr.hpp>
#include <boost/version.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "ns3/libtorrent/torrent_handle.hpp"
#include "ns3/libtorrent/socket.hpp"
#include "ns3/libtorrent/policy.hpp"
#include "ns3/libtorrent/tracker_manager.hpp"
#include "ns3/libtorrent/stat.hpp"
#include "ns3/libtorrent/alert.hpp"
#include "ns3/libtorrent/piece_picker.hpp"
#include "ns3/libtorrent/config.hpp"
#include "ns3/libtorrent/escape_string.hpp"
#include "ns3/libtorrent/bandwidth_limit.hpp"
#include "ns3/libtorrent/bandwidth_manager.hpp"
#include "ns3/libtorrent/bandwidth_queue_entry.hpp"
#include "ns3/libtorrent/hasher.hpp"
#include "ns3/libtorrent/assert.hpp"
#include "ns3/libtorrent/bitfield.hpp"
#include "ns3/libtorrent/aux_/session_impl.hpp"

#include "ns3/Video.h"
#include "ns3/callback.h"

#include "ns3/ptr.h"
#include "ns3/node.h"

#if TORRENT_COMPLETE_TYPES_REQUIRED
#include "ns3/libtorrent/peer_connection.hpp"
#endif

#include "ns3/ipv4-end-point.h"
#include "ns3/node.h"

namespace libtorrent
{
	class http_parser;

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
	struct logger;
#endif

	//class piece_manager;
	struct torrent_plugin;
	struct bitfield;
	struct announce_entry;
	struct tracker_request;
	struct add_torrent_params;
	//struct storage_interface;
	class bt_peer_connection;
	struct listen_socket_t;

	namespace aux
	{
		struct session_impl;
		struct piece_checker_data;
	}

	// a torrent is a class that holds information
	// for a specific download. It updates itself against
	// the tracker
	class TORRENT_EXTRA_EXPORT torrent: public request_callback
		, public boost::enable_shared_from_this<torrent>
	{
	public:

		torrent(aux::session_impl& ses, ns3::Ipv4Address addr, ns3::Ipv4EndPoint const& net_interface
			, int block_size, int seq, add_torrent_params const& p
			, sha1_hash const& info_hash, ns3::Ptr<ns3::Node> myNode, bool initSeed = false);
		~torrent();

		sha1_hash const& info_hash() const
		{
			static sha1_hash empty;
			return m_torrent_file ? m_torrent_file->info_hash() : empty;
		}

        ns3::Callback<void, ns3::Time> onFinished;
		// starts the announce timer
		void start();

		void start_download_url();

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		bool has_peer(peer_connection* p) const
		{ return m_connections.find(p) != m_connections.end(); }
#endif

        // 张惊 自定义监听的端口，这个是从session 移动过来的函数
        uint16_t listen_port(){return 6538;}

		// this is called when the torrent has metadata.
		// it will initialize the storage and the piece-picker
		void init();

		// find the peer that introduced us to the given endpoint. This is
		// used when trying to holepunch. We need the introducer so that we
		// can send a rendezvous connect message
		bt_peer_connection* find_introducer(ns3::InetSocketAddress const& ep) const;

		// if we're connected to a peer at ep, return its peer connection
		// only count BitTorrent peers
		bt_peer_connection* find_peer(ns3::InetSocketAddress const& ep) const;

		void start_announcing();
		void stop_announcing();

		void send_share_mode();
		//void send_upload_only();

		void set_share_mode(bool s);
		bool share_mode() const { return m_share_mode; }

		bool graceful_pause() const { return m_graceful_pause_mode; }

		void set_upload_mode(bool b);
		bool upload_mode() const { return m_upload_mode || m_graceful_pause_mode; }
		bool is_upload_only() const { return is_finished() || upload_mode(); }

		int seed_rank(session_settings const& s) const;

		enum flags_t { overwrite_existing = 1 };
        // TODO: 禁用磁盘读写
		//void add_piece(int piece, char const* data, int flags = 0);
		//void on_disk_write_complete(int ret, disk_io_job const& j
		//	, peer_request p);
		//void on_disk_cache_complete(int ret, disk_io_job const& j);

		void set_progress_ppm(int p) { m_progress_ppm = p; }
		struct read_piece_struct
		{
			boost::shared_array<char> piece_data;
			int blocks_left;
			bool fail;
		};
		void read_piece(int piece);
        // TODO: 禁用磁盘读写
		//void on_disk_read_complete(int ret, disk_io_job const& j, peer_request r, read_piece_struct* rp);

		//storage_mode_t storage_mode() const { return (storage_mode_t)m_storage_mode; }
        // TODO: 禁用存储
		/*storage_interface* get_storage()
		{
			if (!m_owning_storage) return 0;
			return m_owning_storage->get_storage_impl();
		}*/

		// this will flag the torrent as aborted. The main
		// loop in session_impl will check for this state
		// on all torrents once every second, and take
		// the necessary actions then.
		void abort();
		bool is_aborted() const { return m_abort; }

		torrent_status::state_t state() const { return (torrent_status::state_t)m_state; }
		void set_state(torrent_status::state_t s);

		session_settings const& settings() const;
		
		aux::session_impl& session() { return m_ses; }
		
		void set_sequential_download(bool sd);
		bool is_sequential_download() const
		{ return m_sequential_download; }
	
		void queue_up();
		void queue_down();
		void set_queue_position(int p);
		int queue_position() const { return m_sequence_number; }

		void second_tick(stat& accumulator, int tick_interval_ms);

		std::string name() const;

		stat statistics() const { return m_stat; }
		void add_stats(stat const& s);
		size_type bytes_left() const;
		int block_bytes_wanted(piece_block const& p) const;
		void bytes_done(torrent_status& st, bool accurate) const;
		size_type quantized_bytes_done() const;

		//void ip_filter_updated() { m_policy.ip_filter_updated(); }

		void handle_disk_error(disk_io_job const& j, peer_connection* c = 0);
		void clear_error();
		void set_error(error_code const& ec, std::string const& file);
		bool has_error() const { return !!m_error; }
		error_code error() const { return m_error; }

		void set_allow_peers(bool b, bool graceful_pause = false);
		//void set_announce_to_dht(bool b) { m_announce_to_dht = b; }
		void set_announce_to_trackers(bool b) { m_announce_to_trackers = b; }

		ptime started() const { return m_started; }

		//bool is_paused() const;
		bool allows_peers() const { return m_allow_peers; }
		bool is_torrent_paused() const { return !m_allow_peers || m_graceful_pause_mode; }
        // TODO: 禁用完整性检测
		//void save_resume_data(int flags);

		bool need_save_resume_data() const
		{
			// save resume data every 15 minutes regardless, just to
			// keep stats up to date
			return m_need_save_resume_data || time(0) - m_last_saved_resume > 15 * 60;
		}

		//bool should_check_files() const;

		//void delete_files();

		// ============ start deprecation =============
		void filter_piece(int index, bool filter);
		void filter_pieces(std::vector<bool> const& bitmask);
		bool is_piece_filtered(int index) const;
		void filtered_pieces(std::vector<bool>& bitmask) const;
		void filter_files(std::vector<bool> const& files);
		// ============ end deprecation =============

		void piece_availability(std::vector<int>& avail) const;
		
		void set_piece_priority(int index, int priority);
		int piece_priority(int index) const;

		void prioritize_pieces(std::vector<int> const& pieces);
		void piece_priorities(std::vector<int>*) const;

		void set_piece_deadline(int piece, int t, int flags);
		void reset_piece_deadline(int piece);

		// this torrent changed state, if the user is subscribing to
		// it, add it to the m_state_updates list in session_impl
		void state_updated();

		void use_interface(std::string net_interface);
		ns3::InetSocketAddress get_interface() const;
		
		bool connect_to_peer(policy::peer* peerinfo, bool ignore_limit = false);

        std::map<ns3::Ptr<ns3::Socket>, boost::intrusive_ptr<peer_connection> > ccmap;

        void onSockReceive(ns3::Ptr<ns3::Socket> sock);

		void set_ratio(float r)
		{ TORRENT_ASSERT(r >= 0.0f); m_ratio = r; }

		float ratio() const
		{ return m_ratio; }

		int priority() const { return m_priority; }
		void set_priority(int prio)
		{
			TORRENT_ASSERT(prio <= 255 && prio >= 0);
			if (prio > 255) prio = 255;
			else if (prio < 0) prio = 0;
			m_priority = prio;
			state_updated();
		}

// --------------------------------------------
		// BANDWIDTH MANAGEMENT

		bandwidth_channel m_bandwidth_channel[2];

		int bandwidth_throttle(int channel) const;

// --------------------------------------------
		// PEER MANAGEMENT
		
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_ERROR_LOGGING || defined TORRENT_LOGGING
		void log_to_all_peers(char const* message);
#endif

		bool free_upload_slots() const
		{ return m_num_uploads < m_max_uploads; }

		bool choke_peer(peer_connection& c);
		bool unchoke_peer(peer_connection& c, bool optimistic = false);

		// used by peer_connection to attach itself to a torrent
		// since incoming connections don't know what torrent
		// they're a part of until they have received an info_hash.
		// false means attach failed
		bool attach_peer(peer_connection* p);

		// this will remove the peer and make sure all
		// the pieces it had have their reference counter
		// decreased in the piece_picker
		void remove_peer(peer_connection* p);

		void cancel_block(piece_block block);

		bool want_more_peers() const;
		bool try_connect_peer();
		void add_peer(ns3::Ipv4EndPoint const& adr, int source);

		// the number of peers that belong to this torrent
		int num_peers() const { return (int)m_connections.size(); }
		int num_seeds() const;

		typedef std::set<peer_connection*>::iterator peer_iterator;
		typedef std::set<peer_connection*>::const_iterator const_peer_iterator;

		const_peer_iterator begin() const { return m_connections.begin(); }
		const_peer_iterator end() const { return m_connections.end(); }

		peer_iterator begin() { return m_connections.begin(); }
		peer_iterator end() { return m_connections.end(); }

		void get_full_peer_list(std::vector<peer_list_entry>& v) const;
		void get_peer_info(std::vector<peer_info>& v);
		void get_download_queue(std::vector<partial_piece_info>* queue);

		void refresh_explicit_cache(int cache_size);

// --------------------------------------------
		// TRACKER MANAGEMENT

		// these are callbacks called by the tracker_connection instance
		// (either http_tracker_connection or udp_tracker_connection)
		// when this torrent got a response from its tracker request
		// or when a failure occured
		virtual void tracker_response(
			tracker_request const& r
			, ns3::Address const& tracker_ip
			, std::list<ns3::Address> const& ip_list
			, std::vector<peer_entry>& e, int interval, int min_interval
			, int complete, int incomplete, ns3::Address const& external_ip
			, std::string const& trackerid);
		virtual void tracker_request_error(tracker_request const& r
			, int response_code, const std::string& msg
			, int retry_interval);
		virtual void tracker_warning(tracker_request const& req
			, std::string const& msg);
		virtual void tracker_scrape_response(tracker_request const& req
			, int complete, int incomplete, int downloaded, int downloaders);

		// if no password and username is set
		// this will return an empty string, otherwise
		// it will concatenate the login and password
		// ready to be sent over http (but without
		// base64 encoding).
		std::string tracker_login() const;

		// generate the tracker key for this torrent.
		// The key is passed to http trackers as ``&key=``.
		boost::uint32_t tracker_key() const;

		// returns the absolute time when the next tracker
		// announce will take place.
		ptime next_announce() const;

		// forcefully sets next_announce to the current time
		void force_tracker_request();
		void force_tracker_request(ptime);
		void scrape_tracker();
		void announce_with_tracker(tracker_request::event_t e
			= tracker_request::none
			, ns3::Address const& bind_interface = ns3::Ipv4Address::GetAny());
		int seconds_since_last_scrape() const { return m_last_scrape; }

		// sets the username and password that will be sent to
		// the tracker
		void set_tracker_login(std::string const& name, std::string const& pw);

		// the ns3::InetSocketAddress of the tracker that we managed to
		// announce ourself at the last time we tried to announce
		ns3::Ipv4EndPoint current_tracker() const;

		announce_entry* find_tracker(tracker_request const& r);

// --------------------------------------------
		// PIECE MANAGEMENT

		void update_sparse_piece_prio(int piece, int cursor, int reverse_cursor);

		void get_suggested_pieces(std::vector<int>& s) const;

		bool super_seeding() const
		{ return m_super_seeding; }
		
		void super_seeding(bool on);
		int get_piece_to_super_seed(bitfield const&);

		// returns true if we have downloaded the given piece
		bool have_piece(int index) const
		{
			if (!has_picker()) return true;
			return m_picker->have_piece(index);
		}

		// called when we learn that we have a piece
		// only once per piece
		void we_have(int index);

		int num_have() const
		{
			return has_picker()
				? m_picker->num_have()
				: m_torrent_file->num_pieces();
		}

		// when we get a have message, this is called for that piece
		void peer_has(int index)
		{
			if (m_picker.get())
			{
				TORRENT_ASSERT(!is_seed());
				m_picker->inc_refcount(index);
			}
#ifdef TORRENT_DEBUG
			else
			{
				TORRENT_ASSERT(is_seed());
			}
#endif
		}
		
		// when we get a bitfield message, this is called for that piece
		void peer_has(bitfield const& bits)
		{
			if (m_picker.get())
			{
				TORRENT_ASSERT(!is_seed());
				m_picker->inc_refcount(bits);
			}
#ifdef TORRENT_DEBUG
			else
			{
				TORRENT_ASSERT(is_seed());
			}
#endif
		}

		void peer_has_all()
		{
			if (m_picker.get())
			{
				TORRENT_ASSERT(!is_seed());
				m_picker->inc_refcount_all();
			}
#ifdef TORRENT_DEBUG
			else
			{
				TORRENT_ASSERT(is_seed());
			}
#endif
		}

		void peer_lost(int index)
		{
			if (m_picker.get())
			{
				TORRENT_ASSERT(!is_seed());
				m_picker->dec_refcount(index);
			}
#ifdef TORRENT_DEBUG
			else
			{
				TORRENT_ASSERT(is_seed());
			}
#endif
		}

		int block_size() const { TORRENT_ASSERT(m_block_size_shift > 0); return 1 << m_block_size_shift; }
		peer_request to_req(piece_block const& p) const;

		void disconnect_all(error_code const& ec);
		int disconnect_peers(int num, error_code const& ec);

		// this is called wheh the torrent has completed
		// the download. It will post an event, disconnect
		// all seeds and let the tracker know we're finished.
		void completed();

		// this is the asio callback that is called when a name
		// lookup for a PEER is completed.
		void on_peer_name_lookup(error_code const& e, tcp::resolver::iterator i
			, peer_id pid);

		// this is called when the torrent has finished. i.e.
		// all the pieces we have not filtered have been downloaded.
		// If no pieces are filtered, this is called first and then
		// completed() is called immediately after it.
		void finished();

		// This is the opposite of finished. It is called if we used
		// to be finished but enabled some files for download so that
		// we wasn't finished anymore.
		void resume_download();

		void async_verify_piece(int piece_index, boost::function<void(int)> const&);

		// this is called from the peer_connection
		// each time a piece has failed the hash
		// test
		void piece_finished(int index, int passed_hash_check);

		// piece_passed is called when a piece passes the hash check
		// this will tell all peers that we just got his piece
		// and also let the piece picker know that we have this piece
		// so it wont pick it for download
		void piece_passed(int index);

		// piece_failed is called when a piece fails the hash check
		void piece_failed(int index);

		// this will restore the piece picker state for a piece
		// by re marking all the requests to blocks in this piece
		// that are still outstanding in peers' download queues.
		// this is done when a piece fails
		void restore_piece_state(int index);

		enum wasted_reason_t
		{
			piece_timed_out, piece_cancelled, piece_unknown, piece_seed, piece_end_game, piece_closing
			, waste_reason_max
		};
		void add_failed_bytes(int b);

		// this is true if we have all the pieces
		bool is_seed() const
		{
			return  (!m_picker
				|| m_state == torrent_status::seeding
				|| m_picker->num_have() == m_picker->num_pieces());
		}

		// this is true if we have all the pieces that we want
		bool is_finished() const
		{
			if (is_seed()) return true;
			return m_torrent_file->num_pieces()
				- m_picker->num_have() - m_picker->num_filtered() == 0;
		}

		std::string save_path() const;
//		alert_manager& alerts() const;
		piece_picker& picker()
		{
			TORRENT_ASSERT(m_picker.get());
			return *m_picker;
		}
		bool has_picker() const
		{
			return m_picker.get() != 0;
		}
		policy& get_policy() { return m_policy; }
		//piece_manager& filesystem();
		torrent_info const& torrent_file() const
		{ return *m_torrent_file; }

		//std::string const& uuid() const { return m_uuid; }
		//void set_uuid(std::string const& s) { m_uuid = s; }
		//std::string const& url() const { return m_url; }
		//void set_url(std::string const& s) { m_url = s; }
		//std::string const& source_feed_url() const { return m_source_feed_url; }
		//void set_source_feed_url(std::string const& s) { m_source_feed_url = s; }

		std::vector<announce_entry> const& trackers() const
		{ return m_trackers; }

		void replace_trackers(std::vector<announce_entry> const& urls);
		void add_tracker(announce_entry const& url);

		torrent_handle get_handle();

        // TODO: 禁用磁盘文件
		//void write_resume_data(entry& rd) const;
		//void read_resume_data(lazy_entry const& rd);

		void seen_complete() { m_last_seen_complete = time(0); }
		int time_since_complete() const { return int(time(0) - m_last_seen_complete); }
		time_t last_seen_complete() const { return m_last_seen_complete; }

		// LOGGING
		virtual void debug_log(const char* fmt, ...) const;

		// DEBUG
#ifdef TORRENT_DEBUG
		void check_invariant() const;
#endif

// --------------------------------------------
		// RESOURCE MANAGEMENT

		void add_free_upload(size_type diff)
		{
			TORRENT_ASSERT(diff >= 0);
			if (UINT_MAX - m_available_free_upload > diff)
				m_available_free_upload += boost::uint32_t(diff);
			else
				m_available_free_upload = UINT_MAX;
		}

		int get_peer_upload_limit(ns3::Ipv4EndPoint ip) const;
		int get_peer_download_limit(ns3::Ipv4EndPoint ip) const;
		void set_peer_upload_limit(ns3::Ipv4EndPoint ip, int limit);
		void set_peer_download_limit(ns3::Ipv4EndPoint ip, int limit);

		void set_upload_limit(int limit);
		int upload_limit() const;
		void set_download_limit(int limit);
		int download_limit() const;

		void set_max_uploads(int limit);
		int max_uploads() const { return m_max_uploads; }
		void set_max_connections(int limit);
		int max_connections() const { return m_max_connections; }

		//void move_storage(std::string const& save_path);

		// renames the file with the given index to the new name
		// the name may include a directory path
		// returns false on failure
		//bool rename_file(int index, std::string const& name);

		// parses the info section from the given
		// bencoded tree and moves the torrent
		// to the checker thread for initial checking
		// of the storage.
		// a return value of false indicates an error
		bool set_metadata(char const* metadata_buf, int metadata_size);

		void on_torrent_download(error_code const& ec, http_parser const& parser
			, char const* data, int size);

		int sequence_number() const { return m_sequence_number; }

		bool seed_mode() const { return m_seed_mode; }
		void leave_seed_mode(bool seed)
		{
			if (!m_seed_mode) return;
			m_seed_mode = false;
			// seed is false if we turned out not
			// to be a seed after all
			m_num_verified = 0;
			m_verified.free();
		}
		bool all_verified() const
		{ return int(m_num_verified) == m_torrent_file->num_pieces(); }
		bool verified_piece(int piece) const
		{
			TORRENT_ASSERT(piece < int(m_verified.size()));
			TORRENT_ASSERT(piece >= 0);
			return m_verified.get_bit(piece);
		}
		void verified(int piece)
		{
			TORRENT_ASSERT(piece < int(m_verified.size()));
			TORRENT_ASSERT(piece >= 0);
			TORRENT_ASSERT(m_verified.get_bit(piece) == false);
			++m_num_verified;
			m_verified.set_bit(piece);
		}

		bool add_merkle_nodes(std::map<int, sha1_hash> const& n, int piece);

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
		static void print_size(logger& l);
#endif

		void update_last_upload() { m_last_upload = 0; }

		//void set_apply_ip_filter(bool b);
		//bool apply_ip_filter() const { return m_apply_ip_filter; }

		//void queue_torrent_check();
		//void dequeue_torrent_check();

		void clear_in_state_update()
		{ m_in_state_updates = false; }

		void inc_num_connecting()
		{ ++m_num_connecting; }
		void dec_num_connecting()
		{
			TORRENT_ASSERT(m_num_connecting > 0);
			--m_num_connecting;
		}

		bool is_ssl_torrent() const { return m_ssl_torrent; } 

	private:

        
        // 禁用VCR操作
		//void on_files_deleted(int ret, disk_io_job const& j);
		//void on_files_released(int ret, disk_io_job const& j);
		//void on_torrent_paused(int ret, disk_io_job const& j);
		//void on_storage_moved(int ret, disk_io_job const& j);
            // TODO: 禁用piece操作
		//void on_save_resume_data(int ret, disk_io_job const& j);
		//void on_file_renamed(int ret, disk_io_job const& j);
		//void on_cache_flushed(int ret, disk_io_job const& j);

		//void on_piece_verified(int ret, disk_io_job const& j
		//	, boost::function<void(int)> f);
	
		int prioritize_tracker(int tracker_index);
		int deprioritize_tracker(int tracker_index);

		void on_country_lookup(error_code const& error, tcp::resolver::iterator i
			, boost::intrusive_ptr<peer_connection> p) const;
		bool request_bandwidth_from_session(int channel) const;

		void update_peer_interest(bool was_finished);
		void prioritize_udp_trackers();

		void parse_response(const entry& e, std::vector<peer_entry>& peer_list);

		void update_tracker_timer(ptime now);

		static void on_tracker_announce_disp(boost::weak_ptr<torrent> p
			, error_code const& e);

		void on_tracker_announce();

        void sendData();

		void remove_time_critical_piece(int piece, bool finished = false);
		void remove_time_critical_pieces(std::vector<int> const& priority);
		void request_time_critical_pieces();

		policy m_policy;

		// all time totals of uploaded and downloaded payload
		// stored in resume data
		size_type m_total_uploaded;
		size_type m_total_downloaded;

		// if this torrent is running, this was the time
		// when it was started. This is used to have a
		// bias towards keeping seeding torrents that
		// recently was started, to avoid oscillation
		ptime m_started;

		boost::intrusive_ptr<torrent_info> m_torrent_file;

		// if this pointer is 0, the torrent is in
		// a state where the metadata hasn't been
		// received yet, or during shutdown.
		// the piece_manager keeps the torrent object
		// alive by holding a shared_ptr to it and
		// the torrent keeps the piece manager alive
		// with this intrusive_ptr. This cycle is
		// broken when torrent::abort() is called
		// Then the torrent releases the piece_manager
		// and when the piece_manager is complete with all
		// outstanding disk io jobs (that keeps
		// the piece_manager alive) it will destruct
		// and release the torrent file. The reason for
		// this is that the torrent_info is used by
		// the piece_manager, and stored in the
		// torrent, so the torrent cannot destruct
		// before the piece_manager.
		//boost::intrusive_ptr<piece_manager> m_owning_storage;

		// this is a weak (non owninig) pointer to
		// the piece_manager. This is used after the torrent
		// has been aborted, and it can no longer own
		// the object.
		//piece_manager* m_storage;

#ifdef TORRENT_DEBUG
	public:
#endif
		std::set<peer_connection*> m_connections;
#ifdef TORRENT_DEBUG
	private:
#endif
        Video video;

		// of all peers in m_connections, this is the number
		// of peers that are outgoing and still waiting to
		// complete the connection. This is used to possibly
		// kick out these connections when we get incoming
		// connections (if we've reached the connection limit)
		int m_num_connecting;

        ns3::Ipv4Address ip;

		// used for tracker announces
		//deadline_timer m_tracker_timer;

		// this is the upload and download statistics for the whole torrent.
		// it's updated from all its peers once every second.
		libtorrent::stat m_stat;

		// -----------------------------

		// a back reference to the session
		// this torrent belongs to.
		aux::session_impl& m_ses;

		std::vector<boost::uint8_t> m_file_priority;

		// this vector contains the number of bytes completely
		// downloaded (as in passed-hash-check) in each file.
		// this lets us trigger on individual files completing
		std::vector<size_type> m_file_progress;

		boost::scoped_ptr<piece_picker> m_picker;

		std::vector<announce_entry> m_trackers;
		// this is an index into m_trackers

		struct time_critical_piece
		{
			// when this piece was first requested
			ptime first_requested;
			// when this piece was last requested
			ptime last_requested;
			// by what time we want this piece
			ptime deadline;
			// 1 = send alert with piece data when available
			int flags;
			// how many peers it's been requested from
			int peers;
			// the piece index
			int piece;
			bool operator<(time_critical_piece const& rhs) const
			{ return deadline < rhs.deadline; }
		};

		// this list is sorted by time_critical_piece::deadline
		std::deque<time_critical_piece> m_time_critical_pieces;

		std::string m_trackerid;
		std::string m_username;
		std::string m_password;

		// the network interfaces outgoing connections
		// are opened through. If there is more then one,
		// they are used in a round-robin fasion
		std::vector<ns3::InetSocketAddress> m_net_interfaces;

		std::string m_save_path;

		// if we don't have the metadata, this is a url to
		// the torrent file
		//std::string m_url;

		// if this was added from an RSS feed, this is the unique
		// identifier in the feed.
		//std::string m_uuid;

		// if this torrent was added by an RSS feed, this is the
		// URL to that feed
		//std::string m_source_feed_url;

		// this is used as temporary storage while downloading
		// the .torrent file from m_url
		std::vector<char> m_torrent_file_buf;

		// each bit represents a piece. a set bit means
		// the piece has had its hash verified. This
		// is only used in seed mode (when m_seed_mode
		// is true)
		bitfield m_verified;

		// set if there's an error on this torrent
		error_code m_error;
		// if the error ocurred on a file, this is the file
		std::string m_error_file;

		// if the torrent is started without metadata, it may
		// still be given a name until the metadata is received
		// once the metadata is received this field will no
		// longer be used and will be reset
		boost::scoped_ptr<std::string> m_name;

		storage_constructor_type m_storage_constructor;

		// the posix time this torrent was added and when
		// it was completed. If the torrent isn't yet
		// completed, m_completed_time is 0
		time_t m_added_time;
		time_t m_completed_time;
		time_t m_last_seen_complete;
		time_t m_last_saved_resume;

		// the upload/download ratio that each peer
		// tries to maintain.
		// 0 is infinite
		float m_ratio;

		// free download we have got that hasn't
		// been distributed yet.
		boost::uint32_t m_available_free_upload;

		// the average time it takes to download one time critical piece
		boost::uint32_t m_average_piece_time;
		// the average piece download time deviation
		boost::uint32_t m_piece_time_deviation;

		// the number of bytes that has been
		// downloaded that failed the hash-test
		boost::uint32_t m_total_failed_bytes;
		boost::uint32_t m_total_redundant_bytes;

		// the sequence number for this torrent, this is a
		// monotonically increasing number for each added torrent
		int m_sequence_number;

		// ==============================
		// The following members are specifically
		// ordered to make the 24 bit members
		// properly 32 bit aligned by inserting
		// 8 bits after each one
		// ==============================

		// the number of seconds we've been in upload mode
		unsigned int m_upload_mode_time:24;

		// the state of this torrent (queued, checking, downloading, etc.)
		unsigned int m_state:3;

		// determines the storage state for this torrent.
		//unsigned int m_storage_mode:2;

		// this is true while tracker announcing is enabled
		// is is disabled while paused and checking files
		bool m_announcing:1;

		// this is true while the tracker deadline timer
		// is in use. i.e. one or more trackers are waiting
		// for a reannounce
		bool m_waiting_tracker:1;

		// this means we haven't verified the file content
		// of the files we're seeding. the m_verified bitfield
		// indicates which pieces have been verified and which
		// haven't
		bool m_seed_mode:1;

		// total time we've been available on this torrent
		// does not count when the torrent is stopped or paused
		// in seconds
		unsigned int m_active_time:24;

		// the index to the last tracker that worked
		boost::int8_t m_last_working_tracker;

		// total time we've been finished with this torrent
		// does not count when the torrent is stopped or paused
		unsigned int m_finished_time:24;

		// in case the piece picker hasn't been constructed
		// when this settings is set, this variable will keep
		// its value until the piece picker is created
		bool m_sequential_download:1;

		// is false by default and set to
		// true when the first tracker reponse
		// is received
		bool m_got_tracker_response:1;

		// if this is true, we're currently super seeding this
		// torrent.
		bool m_super_seeding:1;

		// this is set when we don't want to load seed_mode,
		// paused or auto_managed from the resume data
		bool m_override_resume_data:1;

		unsigned int m_dummy_padding_bits_to_align:2;

		// set to false when saving resume data. Set to true
		// whenever something is downloaded
		bool m_need_save_resume_data:1;

		// total time we've been available as a seed on this torrent
		// does not count when the torrent is stopped or paused
		unsigned int m_seeding_time:24;

		// this is a counter that is decreased every
		// second, and when it reaches 0, the policy::pulse()
		// is called and the time scaler is reset to 10.
		boost::int8_t m_time_scaler;

		// the maximum number of uploads for this torrent
		unsigned int m_max_uploads:24;

		// these are the flags sent in on a call to save_resume_data
		// we need to save them to check them in write_resume_data
		boost::uint8_t m_save_resume_flags;

		// the number of unchoked peers in this torrent
		unsigned int m_num_uploads:24;

		// the size of a request block
		// each piece is divided into these
		// blocks when requested. The block size is
		// 1 << m_block_size_shift
		unsigned int m_block_size_shift:5;

		// is set to true every time there is an incoming
		// connection to this torrent
		bool m_has_incoming:1;

		// this is true if the torrent has been added to
		// checking queue in the session
		bool m_queued_for_checking:1;

		// the maximum number of connections for this torrent
		unsigned int m_max_connections:24;

		// the number of bytes of padding files
		unsigned int m_padding:24;

		// the scrape data from the tracker response, this
		// is optional and may be 0xffffff
		unsigned int m_complete:24;

		// this is the priority of the torrent. The higher
		// the value is, the more bandwidth is assigned to
		// the torrent's peers
		boost::uint8_t m_priority;

		// the scrape data from the tracker response, this
		// is optional and may be 0xffffff
		unsigned int m_incomplete:24;

		// progress parts per million (the number of
		// millionths of completeness)
		unsigned int m_progress_ppm:20;

		// is set to true when the torrent has
		// been aborted.
		bool m_abort:1;

		// true when the torrent should announce to
		// the DHT
		//bool m_announce_to_dht:1;

		// true when this torrent should anncounce to
		// trackers
		bool m_announce_to_trackers:1;

		// is true if this torrent has allows having peers
		bool m_allow_peers:1;

		// set to true when this torrent may not download anything
		bool m_upload_mode:1;

		// this is set when the torrent is in share-mode
		bool m_share_mode:1;

		// m_num_verified = m_verified.count()
		boost::uint32_t m_num_verified;

		// the number of seconds since the last scrape request to
		// one of the trackers in this torrent
		boost::uint32_t m_last_scrape;

		// the number of seconds since the last piece passed for
		// this torrent
		boost::uint32_t m_last_download;

		// the number of seconds since the last byte was uploaded
		// from this torrent
		boost::uint32_t m_last_upload;

		// the scrape data from the tracker response, this
		// is optional and may be 0xffffff
		unsigned int m_downloaders:24;

		// round-robin index into m_interfaces
		mutable boost::uint8_t m_interface_index;

		// set to true when this torrent has been paused but
		// is waiting to finish all current download requests
		// before actually closing all connections
		bool m_graceful_pause_mode:1;

		// this is set to true when the torrent starts up
		// The first tracker response, when this is true,
		// will attempt to connect to a bunch of peers immediately
		// and set this to false. We only do this once to get
		// the torrent kick-started
		bool m_need_connect_boost:1;

		// this is set to true if the torrent was started without
		// metadata. It is used to save metadata in the resume file
		// by default for such torrents. It does not necessarily
		// have to be a magnet link.
		bool m_magnet_link:1;

		// if set to true, add tracker URLs loaded from resume
		// data into this torrent instead of replacing them
		bool m_merge_resume_trackers:1;
		
		// state subscription. If set, a pointer to this torrent
		// will be added to the m_state_updates set in session_impl
		// whenever this torrent's state changes (any state).
		bool m_state_subscription:1;

		// in state_updates list. When adding a torrent to the
		// session_impl's m_state_update list, this bit is set
		// to never add the same torrent twice
		bool m_in_state_updates:1;

		// even if we're not built to support SSL torrents,
		// remember that this is an SSL torrent, so that we don't
		// accidentally start seeding it without any authentication.
		bool m_ssl_torrent:1;

        // 张惊
        // 这个是代替连接队列的用于计数的功能
        uint32_t m_ticket_count;

        // 这个节点是否是种子节点
        bool initSeed;

//        ns3::Ptr<ns3::Socket> m_socket;

//        void ConnectionSucceeded(ns3::Ptr<ns3::Socket> socket);
//        void ConnectionFailed(ns3::Ptr<ns3::Socket> socket);
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
	public:
		// set to false until we've loaded resume data
		bool m_resume_data_loaded;
#endif

        // 张惊
        // 这个是所属的节点
        ns3::Ptr<ns3::Node> m_node;

        //////////////////  bandwidth_manager //////////////////////////////
        // 从session那边搬来的
			// the bandwidth manager is responsible for
			// handing out bandwidth to connections that
			// asks for it, it can also throttle the
			// rate.
			bandwidth_manager m_download_rate;
			bandwidth_manager m_upload_rate;

			// the global rate limiter bandwidth channels
			bandwidth_channel m_download_channel;
			bandwidth_channel m_upload_channel;

			// bandwidth channels for local peers when
			// rate limits are ignored. They are only
			// throttled by these global rate limiters
			// and they don't have a rate limit set by
			// default
			bandwidth_channel m_local_download_channel;
			bandwidth_channel m_local_upload_channel;

			// all tcp peer connections are subject to these
			// bandwidth limits. Local peers are excempted
			// from this limit. The purpose is to be able to
			// throttle TCP that passes over the internet
			// bottleneck (i.e. modem) to avoid starving out
			// uTP connections.
			bandwidth_channel m_tcp_download_channel;
			bandwidth_channel m_tcp_upload_channel;
        //////////////////  bandwidth_manager //////////////////////////////
	};
}

#endif // TORRENT_TORRENT_HPP_INCLUDED

