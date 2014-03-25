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
#include <list>

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
#include "ns3/inet-socket-address.h"
#include "ns3/traced-callback.h"
#include "ns3/attribute.h"
#include "ns3/allocator.hpp"
#include <string>
#include <map>
#include "libtorrent/peer_id.hpp"
#include "libtorrent/tracker_manager.hpp"
#include "udp-p2p-header.h"
#include "action.h"
#include "ns3/ipv4-end-point.h"
#include "ns3/ptr.h"
#include "ns3/node.h"

// TODO
//#include "udp_socket.hpp"
/*#include "entry.hpp"
#include "session_settings.hpp"
#include "peer_id.hpp"
#include "peer.hpp"
#include "tracker_manager.hpp"
#include "config.hpp"*/

/*
 * 修改说明：
 * 这个代码我更改了start与close方法。这两个方法是原库中建立与取消与一个trakcer连接的功能。
 * 我移除了fail与timeout函数。由于模拟的时候，不考虑与trakcer突然断开连接，因此不使用这两个函数。
 * 我移除了tracker_manager这个类。由于暂时不考虑多个tracker的问题，因此不需要tracker_manager。
 * 我移除了Boost的所有网络连接的代码
 * 这里我加入了一个SetRemote的方法，用于设置trakcer在NS3模拟网络中的坐标。
 * 在构造函数中，我移除了io_service类型的参数，这个参数是提供Boost中连接的类型。
 */

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
                , boost::shared_ptr<request_callback> c
                , ns3::Ptr<ns3::Node> node
                , ns3::Ipv4Address addr);

        // 这个函数开启与一个远程trakcer的连接
		void start();
        // 这个函数关闭与一个远程tracker的连接
		void close();

        //void SetRemote(ns3::Ipv4Address ip, uint16_t port);
	    void start_announce();
    protected:
        ns3::Ipv4Address GetAddress()
        {
//            ns3::Ptr<ns3::NetDevice> netdev = m_node->GetDevice(0);
//            return ns3::Ipv4InterfaceAddress::ConvertFrom(netdev->GetAddress());
            return ns3::Ipv4Address();        
        }
	private:

		boost::intrusive_ptr<udp_tracker_connection> self()
		{ return boost::intrusive_ptr<udp_tracker_connection>(this); }

		void on_receive(ns3::Ptr<ns3::Packet> p);
		void on_connect_response(uint8_t* buf, uint32_t size);
		void on_announce_response(uint8_t* buf, uint32_t size);
		void on_scrape_response(uint8_t* buf, uint32_t size);

        void handleRecv(ns3::Ptr<ns3::Socket> sock);
		void send_udp_connect();
		void send_udp_announce();
		void send_udp_scrape();

		//virtual void on_timeout();
		
        bool m_abort;
		std::string m_hostname;
		ns3::Ipv4EndPoint m_target;
		std::list<ns3::Ipv4EndPoint> m_endpoints;

        ns3::Ptr<ns3::Socket> m_socket;

		int m_transaction_id;
		int m_attempts;

		struct connection_cache_entry
		{
			boost::int64_t connection_id;
		};

		static std::map<ns3::Ipv4Address, connection_cache_entry> m_connection_cache;

        ns3::action_t m_state;

        ns3::Ptr<ns3::Node> m_node;
        ns3::Ipv4Address ip;
	};

}

#endif // TORRENT_UDP_TRACKER_CONNECTION_HPP_INCLUDED

