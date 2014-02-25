/*

Copyright (c) 2007, Arvid Norberg
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

#ifndef TORRENT_BROADCAST_SOCKET_HPP_INCLUDED
#define TORRENT_BROADCAST_SOCKET_HPP_INCLUDED

#include "ns3/libtorrent/config.hpp"
#include "ns3/libtorrent/io_service_fwd.hpp"
#include "ns3/libtorrent/socket.hpp"
#include "ns3/libtorrent/error_code.hpp"
#include <boost/shared_ptr.hpp>
#include <boost/function/function3.hpp>
#include <list>

#include "ns3/inet-socket-address.h"
#include "ns3/address.h"
#include "ns3/ipv4-end-point.h"

namespace libtorrent
{

	TORRENT_EXPORT bool is_local(ns3::Address const& a);
	TORRENT_EXPORT bool is_loopback(ns3::Address const& addr);
	TORRENT_EXPORT bool is_multicast(ns3::Address const& addr);
	TORRENT_EXPORT bool is_any(ns3::Address const& addr);
	TORRENT_EXPORT bool is_teredo(ns3::Address const& addr);
	TORRENT_EXTRA_EXPORT int cidr_distance(ns3::Address const& a1, ns3::Address const& a2);

	// determines if the operating system supports IPv6
	TORRENT_EXPORT bool supports_ipv6();

	TORRENT_EXTRA_EXPORT int common_bits(unsigned char const* b1
		, unsigned char const* b2, int n);

	TORRENT_EXPORT ns3::Address guess_local_address(io_service&);

	typedef boost::function<void(ns3::Ipv4EndPoint const& from
		, char* buffer, int size)> receive_handler_t;

	class TORRENT_EXTRA_EXPORT broadcast_socket
	{
	public:
		broadcast_socket(ns3::Ipv4EndPoint const& multicast_endpoint
			, receive_handler_t const& handler);
		~broadcast_socket() { close(); }

		void open(io_service& ios, error_code& ec, bool loopback = true);

		enum flags_t { broadcast = 1 };
		void send(char const* buffer, int size, error_code& ec, int flags = 0);

		void close();
		int num_send_sockets() const { return m_unicast_sockets.size(); }
		void enable_ip_broadcast(bool e);

	private:

		struct socket_entry
		{
			socket_entry(boost::shared_ptr<datagram_socket> const& s)
				: socket(s), broadcast(false) {}
			socket_entry(boost::shared_ptr<datagram_socket> const& s
				, ns3::Ipv4Address const& mask): socket(s), netmask(mask), broadcast(false) {}
			boost::shared_ptr<datagram_socket> socket;
			char buffer[1500];
            ns3::InetSocketAddress remote;
            ns3::Ipv4Address netmask;
			bool broadcast;
			void close()
			{
				if (!socket) return;
				error_code ec;
				socket->close(ec);
			}
			bool can_broadcast() const
			{
				error_code ec;
				return broadcast
					&& netmask != ns3::Ipv4Address()
					&& socket->local_endpoint(ec).address().is_v4();
			}
		};
	
		void on_receive(socket_entry* s, error_code const& ec
			, std::size_t bytes_transferred);
		void open_unicast_socket(io_service& ios, ns3::Address const& addr
			, ns3::Ipv4Address const& mask);
		void open_multicast_socket(io_service& ios, ns3::Address const& addr
			, bool loopback, error_code& ec);

		// if we're aborting, destruct the handler and return true
		bool maybe_abort();

		// these sockets are used to
		// join the multicast group (on each interface)
		// and receive multicast messages
		std::list<socket_entry> m_sockets;
		// these sockets are not bound to any
		// specific port and are used to
		// send messages to the multicast group
		// and receive unicast responses
		std::list<socket_entry> m_unicast_sockets;
		ns3::Ipv4EndPoint m_multicast_endpoint;
		receive_handler_t m_on_receive;

		// the number of outstanding async operations
		// we have on these sockets. The m_on_receive
		// handler may not be destructed until this reaches
		// 0, since it may be holding references to
		// the broadcast_socket itself.
		int m_outstanding_operations;
		// when set to true, we're trying to shut down
		// don't initiate new operations and once the
		// outstanding counter reaches 0, destruct
		// the handler object
		bool m_abort;
	};
}
	
#endif

