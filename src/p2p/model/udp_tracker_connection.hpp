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

#ifndef TORRENT_UDP_TRACKER_CONNECTION_HPP_INCLUDED
#define TORRENT_UDP_TRACKER_CONNECTION_HPP_INCLUDED

#include <vector>
#include <string>
#include <utility>
#include <ctime>

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include "ns3/traced-callback.h"
#include "ns3/attribute.h"
#include "ns3/allocator.hpp"
#include <string>
#include <map>
#include "ns3/peer_id.hpp"
#include "ns3/tracker_req.hpp"
#include "udp-p2p-header.h"
#include "action.h"

// TODO
//#include "udp_socket.hpp"
/*#include "entry.hpp"
#include "session_settings.hpp"
#include "peer_id.hpp"
#include "peer.hpp"
#include "tracker_manager.hpp"
#include "config.hpp"*/

namespace ns3{
    class Socket;
}

namespace libtorrent
{
	class udp_tracker_connection: public tracker_connection
	{
	//friend class tracker_manager;
	public:

		udp_tracker_connection(tracker_manager& man
                , tracker_request const& req
                , boost::weak_ptr<request_callback> c);

		void start();
		void close();

        void SetRemote(ns3::Ipv4Address ip, uint16_t port);
	private:

//		boost::intrusive_ptr<udp_tracker_connection> self()
//		{ return boost::intrusive_ptr<udp_tracker_connection>(this); }

		void on_receive(ns3::Ptr<ns3::Packet> p);
		void on_connect_response(ns3::UdpP2PHeader &header);
		void on_announce_response(ns3::UdpP2PHeader &header);
		void on_scrape_response(ns3::UdpP2PHeader &header);

		void send_udp_connect();
		void send_udp_announce();
		void send_udp_scrape();

		//virtual void on_timeout();

        ns3::Ptr<ns3::Socket> m_socket;

		int m_transaction_id;
		int m_attempts;

		struct connection_cache_entry
		{
			boost::int64_t connection_id;
		};

		static std::map<ns3::Ipv4Address, connection_cache_entry> m_connection_cache;

        ns3::action_t m_state;

        ns3::Ipv4Address remoteAddress;
	};

}

#endif // TORRENT_UDP_TRACKER_CONNECTION_HPP_INCLUDED

