/*

Copyright (c) 2003 - 2006, Arvid Norberg
Copyright (c) 2007, Arvid Norberg, Un Shyam
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

#ifndef TORRENT_BT_PEER_CONNECTION_HPP_INCLUDED
#define TORRENT_BT_PEER_CONNECTION_HPP_INCLUDED

#include <ctime>
#include <algorithm>
#include <vector>
#include <string>

#include "debug.hpp"

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/smart_ptr.hpp>
#include <boost/noncopyable.hpp>
#include <boost/array.hpp>
#include <boost/optional.hpp>
#include <boost/cstdint.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "ns3/libtorrent/buffer.hpp"
#include "ns3/libtorrent/peer_connection.hpp"
#include "ns3/libtorrent/socket.hpp"
#include "ns3/libtorrent/peer_id.hpp"
#include "ns3/libtorrent/torrent.hpp"
#include "ns3/libtorrent/peer_request.hpp"
#include "ns3/libtorrent/piece_block_progress.hpp"
#include "ns3/libtorrent/config.hpp"
#include "ns3/libtorrent/disk_buffer_holder.hpp"

namespace libtorrent
{
	class torrent;

	namespace detail
	{
		struct session_impl;
	}

	class bt_peer_connection
		: public peer_connection
	{
	friend class invariant_access;
	public:

		// this is the constructor where the we are the active part.
		// The peer_conenction should handshake and verify that the
		// other end has the correct id
		bt_peer_connection(
			aux::session_impl& ses
            , ns3::Ipv4Address& ip
			, boost::shared_ptr<torrent> t
            , ns3::Ptr<ns3::Socket> s
            , ns3::Ipv4EndPoint const& remote
			, policy::peer* peerinfo
			, bool outgoing = true);

		// with this constructor we have been contacted and we still don't
		// know which torrent the connection belongs to
		bt_peer_connection(
			aux::session_impl& ses
            , ns3::Ipv4Address& ip
            , ns3::Ptr<ns3::Socket> s
            , ns3::Ipv4EndPoint const& remote
			, policy::peer* peerinfo);

		void start();

		~bt_peer_connection();
		
		virtual int type() const { return peer_connection::bittorrent_connection; }

		enum message_type
		{
	// standard messages
			msg_choke = 0,
			msg_unchoke,
			msg_interested,
			msg_not_interested,
			msg_have,
			msg_bitfield,
			msg_request,
			msg_piece,
			msg_cancel,
			// FAST extension
			msg_suggest_piece = 0xc,
			msg_have_all,
			msg_have_none,
			msg_reject_request,
			msg_allowed_fast,

			// extension protocol message
			msg_extended = 20,

			num_supported_messages
		};

		enum hp_message_t
		{
			// msg_types
			hp_rendezvous = 0,
			hp_connect = 1,
			hp_failed = 2,

			// error codes
			hp_no_such_peer = 1,
			hp_not_connected = 2,
			hp_no_support = 3,
			hp_no_self = 4
		};

		// called from the main loop when this connection has any
		// work to do.

		void on_sent(error_code const& error
			, std::size_t bytes_transferred);
		void on_receive(error_code const& error
			, std::size_t bytes_transferred);
		
		virtual void get_specific_peer_info(peer_info& p) const;
		virtual bool in_handshake() const;

		bool support_extensions() const { return m_supports_extensions; }

		// the message handlers are called
		// each time a recv() returns some new
		// data, the last time it will be called
		// is when the entire packet has been
		// received, then it will no longer
		// be called. i.e. most handlers need
		// to check how much of the packet they
		// have received before any processing
		void on_keepalive();
		void on_choke(int received);
		void on_unchoke(int received);
		void on_interested(int received);
		void on_not_interested(int received);
		void on_have(int received);
		void on_bitfield(int received);
		void on_request(int received);
		void on_piece(int received);
		void on_cancel(int received);

		// FAST extension
		void on_suggest_piece(int received);
		void on_have_all(int received);
		void on_have_none(int received);
		void on_reject_request(int received);
		void on_allowed_fast(int received);

		void on_extended(int received);

		void on_extended_handshake();

		typedef void (bt_peer_connection::*message_handler)(int received);

		// the following functions appends messages
		// to the send buffer
		void write_choke();
		void write_unchoke();
		void write_interested();
		void write_not_interested();
		void write_request(peer_request const& r);
		void write_cancel(peer_request const& r);
		void write_bitfield();
		void write_have(int index);
		void write_piece(peer_request const& r, disk_buffer_holder& buffer);
		void write_handshake();
		void write_metadata(std::pair<int, int> req);
		void write_metadata_request(std::pair<int, int> req);
		void write_keepalive();

		// FAST extension
		void write_have_all();
		void write_have_none();
		void write_reject_request(peer_request const&);
		void write_allow_fast(int piece);
		void write_suggest(int piece);
		
		void on_connected();
		void on_metadata();

#ifdef TORRENT_DEBUG
		void check_invariant() const;
		ptime m_last_choke;
#endif

	private:

		bool dispatch_message(int received);
		// returns the block currently being
		// downloaded. And the progress of that
		// block. If the peer isn't downloading
		// a piece for the moment, the boost::optional
		// will be invalid.
		boost::optional<piece_block_progress> downloading_piece_progress() const;

		enum state
		{
			read_protocol_identifier = 0,
			read_info_hash,
			read_peer_id,

			// handshake complete
			read_packet_size,
			read_packet
		};
		
		std::string m_client_version;

		// state of on_receive
		state m_state;

		static const message_handler m_message_handler[num_supported_messages];

		// this is a queue of ranges that describes
		// where in the send buffer actual payload
		// data is located. This is currently
		// only used to be able to gather statistics
		// seperately on payload and protocol data.
		struct range
		{
			range(int s, int l)
				: start(s)
				, length(l)
			{
				TORRENT_ASSERT(s >= 0);
				TORRENT_ASSERT(l > 0);
			}
			int start;
			int length;
		};
		static bool range_below_zero(const range& r)
		{ return r.start < 0; }
		std::vector<range> m_payloads;

		// we have suggested these pieces to the peer
		// don't suggest it again
		bitfield m_sent_suggested_pieces;

		// this is set to true if the handshake from
		// the peer indicated that it supports the
		// extension protocol
		bool m_supports_extensions:1;
		bool m_supports_dht_port:1;
		bool m_supports_fast:1;

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		// this is set to true when the client's
		// bitfield is sent to this peer
		bool m_sent_bitfield;

		bool m_in_constructor;
		
		bool m_sent_handshake;
#endif

	};
}

#endif // TORRENT_BT_PEER_CONNECTION_HPP_INCLUDED

