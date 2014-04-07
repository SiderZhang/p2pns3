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

#include "libtorrent/pch.hpp"

#include <vector>
#include <boost/limits.hpp>
#include <boost/bind.hpp>

#include "libtorrent/bt_peer_connection.hpp"
#include "libtorrent/session.hpp"
#include "libtorrent/identify_client.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/alert_types.hpp"
#include "libtorrent/invariant_check.hpp"
#include "libtorrent/io.hpp"
#include "libtorrent/socket_io.hpp"
#include "libtorrent/version.hpp"
#include "libtorrent/extensions.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/escape_string.hpp"
#include "libtorrent/peer_info.hpp"
#include "libtorrent/random.hpp"
#include "libtorrent/alloca.hpp"
#include "ns3/log.h"

NS_LOG_COMPONENT_DEFINE ("BT_PEER_CONNECTION");

using boost::shared_ptr;
using libtorrent::aux::session_impl;

namespace libtorrent
{
	const bt_peer_connection::message_handler
	bt_peer_connection::m_message_handler[] =
	{
		&bt_peer_connection::on_choke,
		&bt_peer_connection::on_unchoke,
		&bt_peer_connection::on_interested,
		&bt_peer_connection::on_not_interested,
		&bt_peer_connection::on_have,
		&bt_peer_connection::on_bitfield,
		&bt_peer_connection::on_request,
		&bt_peer_connection::on_piece,
		&bt_peer_connection::on_cancel,
		0, 0, 0,
		// FAST extension messages
		&bt_peer_connection::on_suggest_piece,
		&bt_peer_connection::on_have_all,
		&bt_peer_connection::on_have_none,
		&bt_peer_connection::on_reject_request,
		&bt_peer_connection::on_allowed_fast,
		0, 0
		//&bt_peer_connection::on_extended
	};


	bt_peer_connection::bt_peer_connection(
		session_impl& ses
        , ns3::Ipv4Address& ip
		, boost::shared_ptr<torrent> tor
        , ns3::Ptr<ns3::Socket> s
        , ns3::Ipv4EndPoint const& remote
		, policy::peer* peerinfo
		, bool outgoing)
		: peer_connection(ses, ip, tor, s, remote
			, peerinfo, outgoing)
		, m_state(read_protocol_identifier)
		, m_supports_dht_port(false)
		, m_supports_fast(false)
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		, m_sent_bitfield(false)
		, m_in_constructor(true)
		, m_sent_handshake(false)
#endif
	{
        NS_LOG_IP_FUNCTION(ip,this);
#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("*** bt_peer_connection");
#endif

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_in_constructor = false;
#endif
	}

	bt_peer_connection::bt_peer_connection(
		session_impl& ses
        , ns3::Ipv4Address& ip
        , ns3::Ptr<ns3::Socket> s
        , ns3::Ipv4EndPoint const& remote
		, policy::peer* peerinfo)
		: peer_connection(ses, ip, s, remote, peerinfo)
		, m_state(read_protocol_identifier)
		, m_supports_dht_port(false)
		, m_supports_fast(false)
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		, m_sent_bitfield(false)
		, m_in_constructor(true)
		, m_sent_handshake(false)
#endif
	{
        NS_LOG_IP_FUNCTION(ip,this);

		// we are not attached to any torrent yet.
		// we have to wait for the handshake to see
		// which torrent the connector want's to connect to


		// upload bandwidth will only be given to connections
		// that are part of a torrent. Since this is an incoming
		// connection, we have to give it some initial bandwidth
		// to send the handshake.
		m_quota[download_channel] = 80;
		m_quota[upload_channel] = 80;

#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_in_constructor = false;
#endif
	}

	void bt_peer_connection::start()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		peer_connection::start();
		
		// start in the state where we are trying to read the
		// handshake from the other side
		reset_recv_buffer(20);
	}

	bt_peer_connection::~bt_peer_connection()
	{
		TORRENT_ASSERT(m_ses.is_network_thread());
	}

	void bt_peer_connection::on_connected()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		{
            write_handshake();
			
			// start in the state where we are trying to read the
			// handshake from the other side
			reset_recv_buffer(20);
            m_socket->SetRecvCallback(MakeCallback (&peer_connection::setup_packet_receive, this));
		}
	}
	
	void bt_peer_connection::on_metadata()
	{
		// connections that are still in the handshake
		// will send their bitfield when the handshake
		// is done
		if (m_state < read_packet_size) return;
		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);
		write_bitfield();
	}


	void bt_peer_connection::write_have_all()
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;
		TORRENT_ASSERT(m_sent_handshake && !m_sent_bitfield);
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_sent_bitfield = true;
#endif
		NS_LOG_IP_INFO(ip , "==> HAVE_ALL");
		char msg[] = {0,0,0,1, msg_have_all};
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_have_none()
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;
		TORRENT_ASSERT(m_sent_handshake && !m_sent_bitfield);
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_sent_bitfield = true;
#endif
#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("==> HAVE_NONE");
#endif
		char msg[] = {0,0,0,1, msg_have_none};
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_reject_request(peer_request const& r)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

#ifdef TORRENT_STATS
		++m_ses.m_piece_rejects;
#endif

		if (!m_supports_fast) return;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		char msg[] = {0,0,0,13, msg_reject_request,0,0,0,0, 0,0,0,0, 0,0,0,0};
		char* ptr = msg + 5;
		detail::write_int32(r.piece, ptr); // index
		detail::write_int32(r.start, ptr); // begin
		detail::write_int32(r.length, ptr); // length
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_allow_fast(int piece)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		if (!m_supports_fast) return;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		char msg[] = {0,0,0,5, msg_allowed_fast, 0, 0, 0, 0};
		char* ptr = msg + 5;
		detail::write_int32(piece, ptr);
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_suggest(int piece)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		if (!m_supports_fast) return;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);

		if (m_sent_suggested_pieces.empty())
			m_sent_suggested_pieces.resize(t->torrent_file().num_pieces(), false);

		if (m_sent_suggested_pieces[piece]) return;
		m_sent_suggested_pieces.set_bit(piece);

		char msg[] = {0,0,0,5, msg_suggest_piece, 0, 0, 0, 0};
		char* ptr = msg + 5;
		detail::write_int32(piece, ptr);
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::get_specific_peer_info(peer_info& p) const
	{
        NS_LOG_IP_FUNCTION(ip, this);
		TORRENT_ASSERT(!associated_torrent().expired());

		if (is_interesting()) p.flags |= peer_info::interesting;
		if (is_choked()) p.flags |= peer_info::choked;
		if (is_peer_interested()) p.flags |= peer_info::remote_interested;
		if (has_peer_choked()) p.flags |= peer_info::remote_choked;
		if (support_extensions()) p.flags |= peer_info::supports_extensions;
		if (is_outgoing()) p.flags |= peer_info::local_connection;

		if (!is_connecting() && in_handshake())
			p.flags |= peer_info::handshake;
		if (is_connecting() && !is_queued()) p.flags |= peer_info::connecting;
		if (is_queued()) p.flags |= peer_info::queued;

		p.client = m_client_version;
		p.connection_type = peer_info::standard_bittorrent;
	}
	
	bool bt_peer_connection::in_handshake() const
	{
		return m_state < read_packet_size;
	}

	void bt_peer_connection::write_handshake()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(!m_sent_handshake);
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_sent_handshake = true;
#endif

		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);

		// add handshake to the send buffer
		const char version_string[] = "BitTorrent protocol";
		const int string_len = sizeof(version_string)-1;

		char handshake[1 + string_len + 8 + 20 + 20];
		char* ptr = handshake;
		// length of version string
		detail::write_uint8(string_len, ptr);
		// protocol identifier
		memcpy(ptr, version_string, string_len);
		ptr += string_len;
		// 8 zeroes
		memset(ptr, 0, 8);


		// we support merkle torrents
		*(ptr + 5) |= 0x08;

		// we support FAST extension
		*(ptr + 7) |= 0x04;

#ifdef TORRENT_VERBOSE_LOGGING	
		std::string bitmask;
		for (int k = 0; k < 8; ++k)
		{
			for (int j = 0; j < 8; ++j)
			{
				if (ptr[k] & (0x80 >> j)) bitmask += '1';
				else bitmask += '0';
			}
		}
		peer_log(">>> EXTENSION_BITS [ %s ]", bitmask.c_str());
#endif
		ptr += 8;

		// info hash
		sha1_hash const& ih = t->torrent_file().info_hash();
		memcpy(ptr, &ih[0], 20);
		ptr += 20;

		// peer id
		if (m_ses.m_settings.anonymous_mode)
		{
			// in anonymous mode, every peer connection
			// has a unique peer-id
			for (int i = 0; i < 20; ++i)
				*ptr++ = rand();
		}
		else
		{
			memcpy(ptr, &m_ses.get_peer_id()[0], 20);
//			ptr += 20;
		}

		NS_LOG_IP_INFO(ip,"==> HANDSHAKE [ length " << string_len << " ih: "<<to_hex(ih.to_string()).c_str() << " ]");
		send_buffer(handshake, sizeof(handshake));
	}

	boost::optional<piece_block_progress> bt_peer_connection::downloading_piece_progress() const
	{
		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);

		buffer::const_interval recv_buffer = receive_buffer();
		// are we currently receiving a 'piece' message?
		if (m_state != read_packet
			|| recv_buffer.left() <= 9
			|| recv_buffer[0] != msg_piece)
			return boost::optional<piece_block_progress>();

		const char* ptr = recv_buffer.begin + 1;
		peer_request r;
		r.piece = detail::read_int32(ptr);
		r.start = detail::read_int32(ptr);
		r.length = packet_size() - 9;

		// is any of the piece message header data invalid?
		if (!verify_piece(r))
			return boost::optional<piece_block_progress>();

		piece_block_progress p;

		p.piece_index = r.piece;
		p.block_index = r.start / t->block_size();
		p.bytes_downloaded = recv_buffer.left() - 9;
		p.full_block_bytes = r.length;

		return boost::optional<piece_block_progress>(p);
	}


	// message handlers

	// -----------------------------
	// --------- KEEPALIVE ---------
	// -----------------------------

	void bt_peer_connection::on_keepalive()
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== KEEPALIVE");
#endif
		incoming_keepalive();
	}

	// -----------------------------
	// ----------- CHOKE -----------
	// -----------------------------

	void bt_peer_connection::on_choke(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);
		m_statistics.received_bytes(0, received);
		if (packet_size() != 1)
		{
			disconnect(errors::invalid_choke, 2);
			return;
		}
		if (!packet_finished()) return;

		incoming_choke();
		if (is_disconnecting()) return;
		if (!m_supports_fast)
		{
			// we just got choked, and the peer that choked use
			// doesn't support fast extensions, so we have to
			// assume that the choke message implies that all
			// of our requests are rejected. Go through them and
			// pretend that we received reject request messages
			boost::shared_ptr<torrent> t = associated_torrent();
			TORRENT_ASSERT(t);
			while (!download_queue().empty())
			{
				piece_block const& b = download_queue().front().block;
				peer_request r;
				r.piece = b.piece_index;
				r.start = b.block_index * t->block_size();
				r.length = t->block_size();
				// if it's the last piece, make sure to
				// set the length of the request to not
				// exceed the end of the torrent. This is
				// necessary in order to maintain a correct
				// m_outsanding_bytes
				if (r.piece == t->torrent_file().num_pieces() - 1)
				{
					r.length = (std::min)(t->torrent_file().piece_size(
						r.piece) - r.start, r.length);
				}
				incoming_reject_request(r);
			}
		}
	}

	// -----------------------------
	// ---------- UNCHOKE ----------
	// -----------------------------

	void bt_peer_connection::on_unchoke(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);
		m_statistics.received_bytes(0, received);
		if (packet_size() != 1)
		{
			disconnect(errors::invalid_unchoke, 2);
			return;
		}
		if (!packet_finished()) return;

		incoming_unchoke();
	}

	// -----------------------------
	// -------- INTERESTED ---------
	// -----------------------------

	void bt_peer_connection::on_interested(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);
		m_statistics.received_bytes(0, received);
		if (packet_size() != 1)
		{
			disconnect(errors::invalid_interested, 2);
			return;
		}
		if (!packet_finished()) return;

		incoming_interested();
	}

	// -----------------------------
	// ------ NOT INTERESTED -------
	// -----------------------------

	void bt_peer_connection::on_not_interested(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);
		m_statistics.received_bytes(0, received);
		if (packet_size() != 1)
		{
			disconnect(errors::invalid_not_interested, 2);
			return;
		}
		if (!packet_finished()) return;

		incoming_not_interested();
	}

	// -----------------------------
	// ----------- HAVE ------------
	// -----------------------------

	void bt_peer_connection::on_have(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);
		m_statistics.received_bytes(0, received);
		if (packet_size() != 5)
		{
			disconnect(errors::invalid_have, 2);
			return;
		}
		if (!packet_finished()) return;

		buffer::const_interval recv_buffer = receive_buffer();

		const char* ptr = recv_buffer.begin + 1;
		int index = detail::read_int32(ptr);

		incoming_have(index);
	}

	// -----------------------------
	// --------- BITFIELD ----------
	// -----------------------------

	void bt_peer_connection::on_bitfield(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);

		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);

		m_statistics.received_bytes(0, received);
		// if we don't have the metedata, we cannot
		// verify the bitfield size
		if (packet_size() - 1 != (t->torrent_file().num_pieces() + 7) / 8)
		{
			disconnect(errors::invalid_bitfield_size, 2);
			return;
		}

		if (!packet_finished()) return;

		buffer::const_interval recv_buffer = receive_buffer();

		bitfield bits;
		bits.borrow_bytes((char*)recv_buffer.begin + 1
			, get_bitfield().size());
		
		incoming_bitfield(bits);
	}

	// -----------------------------
	// ---------- REQUEST ----------
	// -----------------------------

	void bt_peer_connection::on_request(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);
		m_statistics.received_bytes(0, received);
		if (packet_size() != 13)
		{
			disconnect(errors::invalid_request, 2);
			return;
		}
		if (!packet_finished()) return;

		buffer::const_interval recv_buffer = receive_buffer();

		peer_request r;
		const char* ptr = recv_buffer.begin + 1;
		r.piece = detail::read_int32(ptr);
		r.start = detail::read_int32(ptr);
		r.length = detail::read_int32(ptr);

		incoming_request(r);
	}

	// -----------------------------
	// ----------- PIECE -----------
	// -----------------------------

	void bt_peer_connection::on_piece(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);
		
		buffer::const_interval recv_buffer = receive_buffer();
		int recv_pos = receive_pos(); // recv_buffer.end - recv_buffer.begin;

		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);
		bool merkle = (unsigned char)recv_buffer.begin[0] == 250;
		if (merkle)
		{
			if (recv_pos == 1)
			{
				set_soft_packet_size(13);
				m_statistics.received_bytes(0, received);
				return;
			}
			if (recv_pos < 13)
			{
				m_statistics.received_bytes(0, received);
				return;
			}
			if (recv_pos == 13)
			{
				const char* ptr = recv_buffer.begin + 9;
				int list_size = detail::read_int32(ptr);
				// now we know how long the bencoded hash list is
				// and we can allocate the disk buffer and receive
				// into it

				if (list_size > packet_size() - 13)
				{
					disconnect(errors::invalid_hash_list, 2);
					return;
				}

				if (packet_size() - 13 - list_size > t->block_size())
				{
					disconnect(errors::packet_too_large, 2);
					return;
				}

				TORRENT_ASSERT(!has_disk_receive_buffer());
			//	if (!allocate_disk_receive_buffer(packet_size() - 13 - list_size))
			//	{
			//		m_statistics.received_bytes(0, received);
			//		return;
			//	}
			}
		}
		else
		{
			if (recv_pos == 1)
			{
				TORRENT_ASSERT(!has_disk_receive_buffer());

				if (packet_size() - 9 > t->block_size())
				{
					disconnect(errors::packet_too_large, 2);
					return;
				}

			//	if (!allocate_disk_receive_buffer(packet_size() - 9))
			//	{
			//		m_statistics.received_bytes(0, received);
			//		return;
			//	}
			}
		}
		TORRENT_ASSERT(has_disk_receive_buffer() || packet_size() == 9);
		// classify the received data as protocol chatter
		// or data payload for the statistics
		int piece_bytes = 0;

		int header_size = merkle?13:9;

		peer_request p;
		int list_size = 0;

		if (recv_pos >= header_size)
		{
			const char* ptr = recv_buffer.begin + 1;
			p.piece = detail::read_int32(ptr);
			p.start = detail::read_int32(ptr);

			if (merkle)
			{
				list_size = detail::read_int32(ptr);
				p.length = packet_size() - list_size - header_size;
				header_size += list_size;
			}
			else
			{
				p.length = packet_size() - header_size;
			}
		}

		if (recv_pos <= header_size)
		{
			// only received protocol data
			m_statistics.received_bytes(0, received);
		}
		else if (recv_pos - received >= header_size)
		{
			// only received payload data
			m_statistics.received_bytes(received, 0);
			piece_bytes = received;
		}
		else
		{
			// received a bit of both
			TORRENT_ASSERT(recv_pos - received < header_size);
			TORRENT_ASSERT(recv_pos > header_size);
			TORRENT_ASSERT(header_size - (recv_pos - received) <= header_size);
			m_statistics.received_bytes(
				recv_pos - header_size
				, header_size - (recv_pos - received));
			piece_bytes = recv_pos - header_size;
		}

		if (recv_pos < header_size) return;

			peer_log("<== PIECE_FRAGMENT p: %d start: %d length: %d"
				, p.piece, p.start, p.length);

		if (recv_pos - received < header_size && recv_pos >= header_size)
		{
			// call this once, the first time the entire header
			// has been received
			start_receive_piece(p);
			if (is_disconnecting()) return;
		}

		TORRENT_ASSERT(has_disk_receive_buffer() || packet_size() == header_size);

		incoming_piece_fragment(piece_bytes);
		if (!packet_finished()) return;

		if (merkle && list_size > 0)
		{
			peer_log("<== HASHPIECE [ piece: %d list: %d ]", p.piece, list_size);
			lazy_entry hash_list;
			error_code ec;
			if (lazy_bdecode(recv_buffer.begin + 13, recv_buffer.begin+ 13 + list_size
				, hash_list, ec) != 0)
			{
				disconnect(errors::invalid_hash_piece, 2);
				return;
			}

			// the list has this format:
			// [ [node-index, hash], [node-index, hash], ... ]
			if (hash_list.type() != lazy_entry::list_t)
			{
				disconnect(errors::invalid_hash_list, 2);
				return;
			}

			std::map<int, sha1_hash> nodes;
			for (uint32_t i = 0; i < hash_list.list_size(); ++i)
			{
				lazy_entry const* e = hash_list.list_at((int)i);
				if (e->type() != lazy_entry::list_t
					|| e->list_size() != 2
					|| e->list_at(0)->type() != lazy_entry::int_t
					|| e->list_at(1)->type() != lazy_entry::string_t
					|| e->list_at(1)->string_length() != 20) continue;

				nodes.insert(std::make_pair(int(e->list_int_value_at(0))
					, sha1_hash(e->list_at(1)->string_ptr())));
			}
			if (!nodes.empty() && !t->add_merkle_nodes(nodes, p.piece))
			{
				disconnect(errors::invalid_hash_piece, 2);
				return;
			}
		}

        // TODO: 禁用磁盘缓存
		//disk_buffer_holder holder(m_ses, release_disk_receive_buffer());
		incoming_piece(p);
	}

	// -----------------------------
	// ---------- CANCEL -----------
	// -----------------------------

	void bt_peer_connection::on_cancel(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);
		m_statistics.received_bytes(0, received);
		if (packet_size() != 13)
		{
			disconnect(errors::invalid_cancel, 2);
			return;
		}
		if (!packet_finished()) return;

		buffer::const_interval recv_buffer = receive_buffer();

		peer_request r;
		const char* ptr = recv_buffer.begin + 1;
		r.piece = detail::read_int32(ptr);
		r.start = detail::read_int32(ptr);
		r.length = detail::read_int32(ptr);

		incoming_cancel(r);
	}

	void bt_peer_connection::on_suggest_piece(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		m_statistics.received_bytes(0, received);
		if (!m_supports_fast)
		{
			disconnect(errors::invalid_suggest, 2);
			return;
		}

		if (!packet_finished()) return;

		buffer::const_interval recv_buffer = receive_buffer();

		const char* ptr = recv_buffer.begin + 1;
		int piece = detail::read_uint32(ptr);
		incoming_suggest(piece);
	}

	void bt_peer_connection::on_have_all(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		m_statistics.received_bytes(0, received);
		if (!m_supports_fast)
		{
			disconnect(errors::invalid_have_all, 2);
			return;
		}
		incoming_have_all();
	}

	void bt_peer_connection::on_have_none(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		m_statistics.received_bytes(0, received);
		if (!m_supports_fast)
		{
			disconnect(errors::invalid_have_none, 2);
			return;
		}
		incoming_have_none();
	}

	void bt_peer_connection::on_reject_request(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		m_statistics.received_bytes(0, received);
		if (!m_supports_fast)
		{
			disconnect(errors::invalid_reject, 2);
			return;
		}

		if (!packet_finished()) return;

		buffer::const_interval recv_buffer = receive_buffer();

		peer_request r;
		const char* ptr = recv_buffer.begin + 1;
		r.piece = detail::read_int32(ptr);
		r.start = detail::read_int32(ptr);
		r.length = detail::read_int32(ptr);
		
		incoming_reject_request(r);
	}

	void bt_peer_connection::on_allowed_fast(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		m_statistics.received_bytes(0, received);
		if (!m_supports_fast)
		{
			disconnect(errors::invalid_allow_fast, 2);
			return;
		}

		if (!packet_finished()) return;
		buffer::const_interval recv_buffer = receive_buffer();
		const char* ptr = recv_buffer.begin + 1;
		int index = detail::read_int32(ptr);
		
		incoming_allowed_fast(index);
	}

	// -----------------------------
	// --------- EXTENDED ----------
	// -----------------------------

	/*void bt_peer_connection::on_extended(int received)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);
		m_statistics.received_bytes(0, received);
		if (packet_size() < 2)
		{
			disconnect(errors::invalid_extended, 2);
			return;
		}

		if (associated_torrent().expired())
		{
			disconnect(errors::invalid_extended, 2);
			return;
		}

		buffer::const_interval recv_buffer = receive_buffer();
		if (recv_buffer.left() < 2) return;

		TORRENT_ASSERT(*recv_buffer.begin == msg_extended);
		++recv_buffer.begin;

		int extended_id = detail::read_uint8(recv_buffer.begin);

		if (extended_id == 0)
		{
			on_extended_handshake();
			disconnect_if_redundant();
			return;
		}

		if (extended_id == upload_only_msg)
		{
			if (!packet_finished()) return;
			if (packet_size() != 3)
			{
#ifdef TORRENT_VERBOSE_LOGGING
				peer_log("<== UPLOAD_ONLY [ ERROR: unexpected packet size: %d ]", packet_size());
#endif
				return;
			}
			bool ul = detail::read_uint8(recv_buffer.begin) != 0;
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("<== UPLOAD_ONLY [ %s ]", (ul?"true":"false"));
#endif
			set_upload_only(ul);
			return;
		}

		if (extended_id == share_mode_msg)
		{
			if (!packet_finished()) return;
			if (packet_size() != 3)
			{
#ifdef TORRENT_VERBOSE_LOGGING
				peer_log("<== SHARE_MODE [ ERROR: unexpected packet size: %d ]", packet_size());
#endif
				return;
			}
			bool sm = detail::read_uint8(recv_buffer.begin) != 0;
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("<== SHARE_MODE [ %s ]", (sm?"true":"false"));
#endif
			set_share_mode(sm);
			return;
		}

		if (extended_id == holepunch_msg)
		{
			if (!packet_finished()) return;
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("<== HOLEPUNCH");
#endif
			on_holepunch();
			return;
		}

		if (extended_id == dont_have_msg)
		{
			if (!packet_finished()) return;
			if (packet_size() != 6)
			{
#ifdef TORRENT_VERBOSE_LOGGING
				peer_log("<== DONT_HAVE [ ERROR: unexpected packet size: %d ]", packet_size());
#endif
				return;
			}
			int piece = detail::read_uint32(recv_buffer.begin) != 0;
			incoming_dont_have(piece);
			return;
		}

#ifdef TORRENT_VERBOSE_LOGGING
		if (packet_finished())
			peer_log("<== EXTENSION MESSAGE [ msg: %d size: %d ]"
				, extended_id, packet_size());
#endif

		disconnect(errors::invalid_message, 2);
		return;
	}*/

	void bt_peer_connection::on_extended_handshake()
	{
        NS_LOG_IP_FUNCTION(ip, this);
		if (!packet_finished()) return;

		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);

		buffer::const_interval recv_buffer = receive_buffer();

		lazy_entry root;
		error_code ec;
		int pos;
		int ret = lazy_bdecode(recv_buffer.begin + 2, recv_buffer.end, root, ec, &pos);
		if (ret != 0 || ec || root.type() != lazy_entry::dict_t)
		{
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log("*** invalid extended handshake: %s pos: %d"
				, ec.message().c_str(), pos);
#endif
			return;
		}

#ifdef TORRENT_VERBOSE_LOGGING
		peer_log("<== EXTENDED HANDSHAKE: %s", print_entry(root).c_str());
#endif

		// there is supposed to be a remote listen port
		int listen_port = int(root.dict_find_int_value("p"));
		if (listen_port > 0 && peer_info_struct() != 0)
		{
			t->get_policy().update_peer_port(listen_port
				, peer_info_struct(), peer_info::incoming);
			received_listen_port();
			if (is_disconnecting()) return;
		}

		// there should be a version too
		// but where do we put that info?

		int last_seen_complete = boost::uint8_t(root.dict_find_int_value("complete_ago", -1));
		if (last_seen_complete >= 0) set_last_seen_complete(last_seen_complete);
		
		std::string client_info = root.dict_find_string_value("v");
		if (!client_info.empty()) m_client_version = client_info;

		int reqq = int(root.dict_find_int_value("reqq"));
		if (reqq > 0) m_max_out_request_queue = reqq;

		if (root.dict_find_int_value("upload_only", 0))
			set_upload_only(true);

		if (root.dict_find_int_value("share_mode", 0))
			set_share_mode(true);

		std::string myip = root.dict_find_string_value("yourip");
		if (!myip.empty())
		{
			// TODO: don't trust this blindly
            // TODO: 禁用boost::asio
			/*if (myip.size() == address_v4::bytes_type().size())
			{
				address_v4::bytes_type bytes;
				std::copy(myip.begin(), myip.end(), bytes.begin());
				m_ses.set_external_address(address_v4(bytes)
					, aux::session_impl::source_peer, remote().address());
			}*/
		}

		// if we're finished and this peer is uploading only
		// disconnect it
		if (t->is_finished() && upload_only()
			&& t->settings().close_redundant_connections
			&& !t->share_mode())
			disconnect(errors::upload_upload_connection);
	}

	bool bt_peer_connection::dispatch_message(int received)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(received > 0);

		// this means the connection has been closed already
		if (associated_torrent().use_count() == 0)
		{
			m_statistics.received_bytes(0, received);
			return false;
		}

        // 张惊：获得接受的数据
        buffer::const_interval recv_buffer = receive_buffer();

		TORRENT_ASSERT(recv_buffer.left() >= 1);
		int packet_type = (unsigned char)recv_buffer[0];
		if (packet_type == 250) packet_type = msg_piece;
		if (packet_type < 0
			|| packet_type >= num_supported_messages
			|| m_message_handler[packet_type] == 0)
		{
			m_statistics.received_bytes(0, received);
			// What's going on here?!
			// break in debug builds to allow investigation
//			TORRENT_ASSERT(false);
			disconnect(errors::invalid_message);
			return packet_finished();
		}

		TORRENT_ASSERT(m_message_handler[packet_type] != 0);

#ifdef TORRENT_DEBUG
		size_type cur_payload_dl = m_statistics.last_payload_downloaded();
		size_type cur_protocol_dl = m_statistics.last_protocol_downloaded();
#endif
		// call the correct handler for this packet type
		(this->*m_message_handler[packet_type])(received);
#ifdef TORRENT_DEBUG
		TORRENT_ASSERT(m_statistics.last_payload_downloaded() - cur_payload_dl >= 0);
		TORRENT_ASSERT(m_statistics.last_protocol_downloaded() - cur_protocol_dl >= 0);
		size_type stats_diff = m_statistics.last_payload_downloaded() - cur_payload_dl +
			m_statistics.last_protocol_downloaded() - cur_protocol_dl;
		TORRENT_ASSERT(stats_diff == received);
#endif

		return packet_finished();
	}

	void bt_peer_connection::write_keepalive()
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		// Don't require the bitfield to have been sent at this point
		// the case where m_sent_bitfield may not be true is if the
		// torrent doesn't have any metadata, and a peer is timimg out.
		// then the keep-alive message will be sent before the bitfield
		// this is a violation to the original protocol, but necessary
		// for the metadata extension.
		TORRENT_ASSERT(m_sent_handshake);

		char msg[] = {0,0,0,0};
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_cancel(peer_request const& r)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		char msg[17] = {0,0,0,13, msg_cancel};
		char* ptr = msg + 5;
		detail::write_int32(r.piece, ptr); // index
		detail::write_int32(r.start, ptr); // begin
		detail::write_int32(r.length, ptr); // length
		send_buffer(msg, sizeof(msg));

		if (!m_supports_fast)
			incoming_reject_request(r);
	}

	void bt_peer_connection::write_request(peer_request const& r)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		char msg[17] = {0,0,0,13, msg_request};
		char* ptr = msg + 5;

		detail::write_int32(r.piece, ptr); // index
		detail::write_int32(r.start, ptr); // begin
		detail::write_int32(r.length, ptr); // length
		send_buffer(msg, sizeof(msg), message_type_request);
	}

	void bt_peer_connection::write_bitfield()
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);
		TORRENT_ASSERT(m_sent_handshake && !m_sent_bitfield);

		// in this case, have_all or have_none should be sent instead
		TORRENT_ASSERT(!m_supports_fast || !t->is_seed() || t->num_have() != 0);

		if (t->super_seeding())
		{
			if (m_supports_fast) write_have_none();

			// if we are super seeding, pretend to not have any piece
			// and don't send a bitfield
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			m_sent_bitfield = true;
#endif

			// bootstrap superseeding by sending one have message
			superseed_piece(t->get_piece_to_super_seed(
				get_bitfield()));
			return;
		}
		else if (m_supports_fast && t->is_seed())
		{
			write_have_all();
			//send_allowed_set();
			return;
		}
		else if (m_supports_fast && t->num_have() == 0)
		{
			write_have_none();
			//send_allowed_set();
			return;
		}
		else if (t->num_have() == 0)
		{
			// don't send a bitfield if we don't have any pieces
#ifdef TORRENT_VERBOSE_LOGGING
			peer_log(" *** NOT SENDING BITFIELD");
#endif
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
			m_sent_bitfield = true;
#endif
			return;
		}
	
		int num_pieces = t->torrent_file().num_pieces();

		int lazy_pieces[50];
		int num_lazy_pieces = 0;
		int lazy_piece = 0;

		if (t->is_seed() && m_ses.settings().lazy_bitfields
			)
		{
			num_lazy_pieces = (std::min)(50, num_pieces / 10);
			if (num_lazy_pieces < 1) num_lazy_pieces = 1;
			for (int i = 0; i < num_pieces; ++i)
			{
				if (int(random() % (num_pieces - i)) >= num_lazy_pieces - lazy_piece) continue;
				lazy_pieces[lazy_piece++] = i;
			}
			TORRENT_ASSERT(lazy_piece == num_lazy_pieces);
		}

		const int packet_size = (num_pieces + 7) / 8 + 5;
	
		char* msg = TORRENT_ALLOCA(char, packet_size);
		if (msg == 0) return; // out of memory
		unsigned char* ptr = (unsigned char*)msg;

		detail::write_int32(packet_size - 4, ptr);
		detail::write_uint8(msg_bitfield, ptr);

		if (t->is_seed())
		{
			memset(ptr, 0xff, packet_size - 6);

			// Clear trailing bits
			unsigned char *p = ((unsigned char *)msg) + packet_size - 1;
			*p = (0xff << ((8 - (num_pieces & 7)) & 7)) & 0xff;
		}
		else
		{
			memset(ptr, 0, packet_size - 5);
			piece_picker const& p = t->picker();
			int mask = 0x80;
			for (int i = 0; i < num_pieces; ++i)
			{
				if (p.have_piece(i)) *ptr |= mask;
				mask >>= 1;
				if (mask == 0)
				{
					mask = 0x80;
					++ptr;
				}
			}
		}
		for (int c = 0; c < num_lazy_pieces; ++c)
			msg[5 + lazy_pieces[c] / 8] &= ~(0x80 >> (lazy_pieces[c] & 7));

#ifdef TORRENT_VERBOSE_LOGGING

		std::string bitfield_string;
		bitfield_string.resize(num_pieces);
		for (int k = 0; k < num_pieces; ++k)
		{
			if (msg[5 + k / 8] & (0x80 >> (k % 8))) bitfield_string[k] = '1';
			else bitfield_string[k] = '0';
		}
		peer_log("==> BITFIELD [ %s ]", bitfield_string.c_str());
#endif
#if defined TORRENT_DEBUG || TORRENT_RELEASE_ASSERTS
		m_sent_bitfield = true;
#endif

		send_buffer(msg, packet_size);

		if (num_lazy_pieces > 0)
		{
			for (int i = 0; i < num_lazy_pieces; ++i)
			{
#ifdef TORRENT_VERBOSE_LOGGING
				peer_log("==> HAVE    [ piece: %d ]", lazy_pieces[i]);
#endif
				write_have(lazy_pieces[i]);
			}
			// TODO: if we're finished, send upload_only message
		}

		if (m_supports_fast)
			send_allowed_set();
	}

	void bt_peer_connection::write_choke()
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		if (is_choked()) return;
		char msg[] = {0,0,0,1,msg_choke};
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_unchoke()
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		char msg[] = {0,0,0,1,msg_unchoke};
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_interested()
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		char msg[] = {0,0,0,1,msg_interested};
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_not_interested()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		char msg[] = {0,0,0,1,msg_not_interested};
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_have(int index)
	{
		INVARIANT_CHECK;
		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < associated_torrent()->torrent_file().num_pieces());
		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		char msg[] = {0,0,0,5,msg_have,0,0,0,0};
		char* ptr = msg + 5;
		detail::write_int32(index, ptr);
		send_buffer(msg, sizeof(msg));
	}

	void bt_peer_connection::write_piece(peer_request const& r, disk_buffer_holder& buffer)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		TORRENT_ASSERT(m_sent_handshake && m_sent_bitfield);

		boost::shared_ptr<torrent> t = associated_torrent();
		TORRENT_ASSERT(t);

		bool merkle = t->torrent_file().is_merkle_torrent() && r.start == 0;
	// the hash piece looks like this:
	// uint8_t  msg
	// uint32_t piece index
	// uint32_t start
	// uint32_t list len
	// var      bencoded list
	// var      piece data
		char msg[4 + 1 + 4 + 4 + 4];
		char* ptr = msg;
		TORRENT_ASSERT(r.length <= 16 * 1024);
		detail::write_int32(r.length + 1 + 4 + 4, ptr);
		if (merkle)
			detail::write_uint8(250, ptr);
		else
			detail::write_uint8(msg_piece, ptr);
		detail::write_int32(r.piece, ptr);
		detail::write_int32(r.start, ptr);

		// if this is a merkle torrent and the start offset
		// is 0, we need to include the merkle node hashes
		if (merkle)
		{
			std::vector<char>	piece_list_buf;
			entry piece_list;
			entry::list_type& l = piece_list.list();
			std::map<int, sha1_hash> merkle_node_list = t->torrent_file().build_merkle_list(r.piece);
			for (std::map<int, sha1_hash>::iterator i = merkle_node_list.begin()
				, end(merkle_node_list.end()); i != end; ++i)
			{
				l.push_back(entry(entry::list_t));
				l.back().list().push_back(i->first);
				l.back().list().push_back(i->second.to_string());
			}
			bencode(std::back_inserter(piece_list_buf), piece_list);
			detail::write_int32(piece_list_buf.size(), ptr);

			char* ptr = msg;
			detail::write_int32(r.length + 1 + 4 + 4 + 4 + piece_list_buf.size(), ptr);

			send_buffer(msg, 17);
			send_buffer(&piece_list_buf[0], piece_list_buf.size());
		}
		else
		{
			send_buffer(msg, 13);
		}

		append_send_buffer(buffer.get(), r.length
			, boost::bind(&session_impl::free_disk_buffer
			, boost::ref(m_ses), _1));

		m_payloads.push_back(range(send_buffer_size() - r.length, r.length));
        NS_LOG_IP_INFO(ip, "send content buffer");
		setup_send();
	}

	namespace
	{
		struct match_peer_id
		{
			match_peer_id(peer_id const& id, peer_connection const* pc)
				: m_id(id), m_pc(pc)
			{ TORRENT_ASSERT(pc); }

			bool operator()(policy::peer const* p) const
			{
				return p->connection != m_pc
					&& p->connection
					&& p->connection->pid() == m_id
					&& !p->connection->pid().is_all_zeros()
					&& p->address() == m_pc->remote().GetPeerAddress();
			}

			peer_id const& m_id;
			peer_connection const* m_pc;
		};
	}

	// --------------------------
	// RECEIVE DATA
	// --------------------------

	void bt_peer_connection::on_receive(error_code const& error
		, std::size_t bytes_transferred)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		INVARIANT_CHECK;

		if (error)
		{
			m_statistics.received_bytes(0, bytes_transferred);
			return;
		}

		boost::shared_ptr<torrent> t = associated_torrent();
	
		buffer::const_interval recv_buffer = receive_buffer();

		if (m_state == read_protocol_identifier)
		{
			m_statistics.received_bytes(0, bytes_transferred);
			bytes_transferred = 0;
			TORRENT_ASSERT(packet_size() == 20);

			if (!packet_finished()) return;
			recv_buffer = receive_buffer();

			int packet_size = recv_buffer[0];
			const char protocol_string[] = "\x13" "BitTorrent protocol";


			if (packet_size != 19 ||
				memcmp(recv_buffer.begin, protocol_string, 20) != 0)
			{
                NS_LOG_IP_INFO(ip, "length "<< packet_size << " unrecognized protocol header");
			}
			else
			{
				NS_LOG_IP_INFO(ip,"<== BitTorrent protocol");
			}

				sha1_hash info_hash;
				std::copy(recv_buffer.begin , recv_buffer.begin + 20
					, (char*)info_hash.begin());

            m_state = read_info_hash;
			reset_recv_buffer(28);
		}

		// fall through
		if (m_state == read_info_hash)
		{
			m_statistics.received_bytes(0, bytes_transferred);
			bytes_transferred = 0;
			TORRENT_ASSERT(packet_size() == 28);

			if (!packet_finished()) return;
			recv_buffer = receive_buffer();

#ifdef TORRENT_VERBOSE_LOGGING	
			std::string extensions;
			extensions.resize(8 * 8);
			for (int i=0; i < 8; ++i)
			{
				for (int j=0; j < 8; ++j)
				{
					if (recv_buffer[i] & (0x80 >> j)) extensions[i*8+j] = '1';
					else extensions[i*8+j] = '0';
				}
			}
			peer_log("<== EXTENSIONS [ %s ext: %s%s%s]"
				, extensions.c_str()
				, (recv_buffer[7] & 0x01) ? "DHT " : ""
				, (recv_buffer[7] & 0x04) ? "FAST " : ""
				, (recv_buffer[5] & 0x10) ? "extension " : "");
#endif

			if (recv_buffer[7] & 0x01)
				m_supports_dht_port = true;

			if (recv_buffer[7] & 0x04)
				m_supports_fast = true;

			// ok, now we have got enough of the handshake. Is this connection
			// attached to a torrent?
			if (!t)
			{
				// now, we have to see if there's a torrent with the
				// info_hash we got from the peer
				sha1_hash info_hash;
				std::copy(recv_buffer.begin + 8, recv_buffer.begin + 28
					, (char*)info_hash.begin());

				bool allow_encrypted = true;

				attach_to_torrent(info_hash, allow_encrypted);
				if (is_disconnecting()) return;
			}
			else
			{
				// verify info hash
				if (!std::equal(recv_buffer.begin + 8, recv_buffer.begin + 28
					, (const char*)t->torrent_file().info_hash().begin()))
				{
					NS_LOG_IP_INFO(ip,"*** received invalid info_hash");
					disconnect(errors::invalid_info_hash, 1);
					return;
				}

				NS_LOG_IP_INFO(ip,"<<< info_hash received");
			}

			t = associated_torrent();
			TORRENT_ASSERT(t);
			
			// if this is a local connection, we have already
			// sent the handshake
			if (!is_outgoing()) write_handshake();
			TORRENT_ASSERT(m_sent_handshake);

			if (is_disconnecting()) return;

			TORRENT_ASSERT(t->get_policy().has_connection(this));

			m_state = read_peer_id;
 			reset_recv_buffer(20);
		}

		// fall through
		if (m_state == read_peer_id)
		{
			TORRENT_ASSERT(m_sent_handshake);
			m_statistics.received_bytes(0, bytes_transferred);
//			bytes_transferred = 0;
  			if (!t)
			{
				TORRENT_ASSERT(!packet_finished()); // TODO
				return;
			}
			TORRENT_ASSERT(packet_size() == 20);
			
 			if (!packet_finished()) return;
			recv_buffer = receive_buffer();

			{
				char hex_pid[41];
				to_hex(recv_buffer.begin, 20, hex_pid);
				hex_pid[40] = 0;
				char ascii_pid[21];
				ascii_pid[20] = 0;
				for (int i = 0; i != 20; ++i)
				{
					if (is_print(recv_buffer.begin[i])) ascii_pid[i] = recv_buffer.begin[i];
					else ascii_pid[i] = '.';
				}
				NS_LOG_IP_INFO(ip,"<<< received peer_id: " << hex_pid<< " client: " << identify_client(peer_id(recv_buffer.begin)).c_str()<<" nas ascii: "<<ascii_pid);
			}
			peer_id pid;
			std::copy(recv_buffer.begin, recv_buffer.begin + 20, (char*)pid.begin());
			set_pid(pid);
 
			if (t->settings().allow_multiple_connections_per_ip)
			{
				// now, let's see if this connection should be closed
				policy& p = t->get_policy();
				policy::iterator i = std::find_if(p.begin_peer(), p.end_peer()
					, match_peer_id(pid, this));
				if (i != p.end_peer())
				{
					TORRENT_ASSERT((*i)->connection->pid() == pid);
					// we found another connection with the same peer-id
					// which connection should be closed in order to be
					// sure that the other end closes the same connection?
					// the peer with greatest peer-id is the one allowed to
					// initiate connections. So, if our peer-id is greater than
					// the others, we should close the incoming connection,
					// if not, we should close the outgoing one.
					if (pid < m_ses.get_peer_id() && is_outgoing())
					{
						(*i)->connection->disconnect(errors::duplicate_peer_id);
					}
					else
					{
						disconnect(errors::duplicate_peer_id);
						return;
					}
				}
			}

			// disconnect if the peer has the same peer-id as ourself
			// since it most likely is ourself then
			if (pid == m_ses.get_peer_id())
			{
				if (peer_info_struct()) t->get_policy().ban_peer(peer_info_struct());
				disconnect(errors::self_connection, 1);
				return;
			}
 
			m_client_version = identify_client(pid);
			boost::optional<fingerprint> f = client_fingerprint(pid);
			if (f && std::equal(f->name, f->name + 2, "BC"))
			{
				// if this is a bitcomet client, lower the request queue size limit
				if (m_max_out_request_queue > 50) m_max_out_request_queue = 50;
			}

			NS_LOG_IP_INFO(ip,"<== ANDSHAKE");

			// consider this a successful connection, reset the failcount
			if (peer_info_struct()) t->get_policy().set_failcount(peer_info_struct(), 0);
			
			m_state = read_packet_size;
			reset_recv_buffer(5);
    		write_bitfield();

			TORRENT_ASSERT(!packet_finished());
			return;
		}

		// cannot fall through into
		if (m_state == read_packet_size)
		{
            //NS_LOG_IP_INFO("")
			// Make sure this is not fallen though into
			TORRENT_ASSERT(recv_buffer == receive_buffer());
			TORRENT_ASSERT(packet_size() == 5);

			if (!t) return;

			if (recv_buffer.left() < 4)
			{
				m_statistics.received_bytes(0, bytes_transferred);
				return;
			}
			int transferred_used = 4 - recv_buffer.left() + bytes_transferred;
			TORRENT_ASSERT(transferred_used <= int(bytes_transferred));
			m_statistics.received_bytes(0, transferred_used);
			bytes_transferred -= transferred_used;

			const char* ptr = recv_buffer.begin;
			int packet_size = detail::read_int32(ptr);

			// don't accept packets larger than 1 MB
			if (packet_size > 1024*1024 || packet_size < 0)
			{
				m_statistics.received_bytes(0, bytes_transferred);
				// packet too large
				disconnect(errors::packet_too_large, 2);
				return;
			}
					
			if (packet_size == 0)
			{
				m_statistics.received_bytes(0, bytes_transferred);
				incoming_keepalive();
				if (is_disconnecting()) return;
				// keepalive message
				m_state = read_packet_size;
				cut_receive_buffer(4, 5);
				return;
			}
			else
			{
				if (recv_buffer.left() < 5) return;

				m_state = read_packet;
				cut_receive_buffer(4, packet_size);
				TORRENT_ASSERT(bytes_transferred == 1);
				recv_buffer = receive_buffer();
				TORRENT_ASSERT(recv_buffer.left() == 1);
			}
		}

		if (m_state == read_packet)
		{
			TORRENT_ASSERT(recv_buffer == receive_buffer());
			if (!t)
			{
				m_statistics.received_bytes(0, bytes_transferred);
				disconnect(errors::torrent_removed, 1);
				return;
			}
#ifdef TORRENT_DEBUG
			size_type cur_payload_dl = m_statistics.last_payload_downloaded();
			size_type cur_protocol_dl = m_statistics.last_protocol_downloaded();
#endif
			if (dispatch_message(bytes_transferred))
			{
				m_state = read_packet_size;
				reset_recv_buffer(5);
			}
#ifdef TORRENT_DEBUG
			TORRENT_ASSERT(m_statistics.last_payload_downloaded() - cur_payload_dl >= 0);
			TORRENT_ASSERT(m_statistics.last_protocol_downloaded() - cur_protocol_dl >= 0);
			size_type stats_diff = m_statistics.last_payload_downloaded() - cur_payload_dl +
				m_statistics.last_protocol_downloaded() - cur_protocol_dl;
			TORRENT_ASSERT(stats_diff == size_type(bytes_transferred));
#endif
			TORRENT_ASSERT(!packet_finished());
			return;
		}
		
		TORRENT_ASSERT(!packet_finished());
	}	

	// --------------------------
	// SEND DATA
	// --------------------------

	void bt_peer_connection::on_sent(error_code const& error
		, std::size_t bytes_transferred)
	{
        NS_LOG_IP_FUNCTION(ip, this);
		INVARIANT_CHECK;

		if (error)
		{
			m_statistics.sent_bytes(0, bytes_transferred);
			return;
		}

		// manage the payload markers
		int amount_payload = 0;
		if (!m_payloads.empty())
		{
			for (std::vector<range>::iterator i = m_payloads.begin();
				i != m_payloads.end(); ++i)
			{
				i->start -= bytes_transferred;
				if (i->start < 0)
				{
					if (i->start + i->length <= 0)
					{
						amount_payload += i->length;
					}
					else
					{
						amount_payload += -i->start;
						i->length -= -i->start;
						i->start = 0;
					}
				}
			}
		}

		// TODO: move the erasing into the loop above
		// remove all payload ranges that has been sent
		m_payloads.erase(
			std::remove_if(m_payloads.begin(), m_payloads.end(), range_below_zero)
			, m_payloads.end());

		TORRENT_ASSERT(amount_payload <= (int)bytes_transferred);
		m_statistics.sent_bytes(amount_payload, bytes_transferred - amount_payload);
		
		if (amount_payload > 0)
		{
			boost::shared_ptr<torrent> t = associated_torrent();
			TORRENT_ASSERT(t);
			if (t) t->update_last_upload();
		}
	}

#ifdef TORRENT_DEBUG
	void bt_peer_connection::check_invariant() const
	{
		boost::shared_ptr<torrent> t = associated_torrent();

		if (!in_handshake())
		{
			TORRENT_ASSERT(m_sent_handshake);
		}

		if (!m_payloads.empty())
		{
			for (std::vector<range>::const_iterator i = m_payloads.begin();
				i != m_payloads.end() - 1; ++i)
			{
				TORRENT_ASSERT(i->start + i->length <= (i+1)->start);
			}
		}
	}
#endif

}

