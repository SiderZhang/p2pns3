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

#include <vector>
#include <cctype>
#include <map>
#include <list>

#include "zlib.h"
#include "ns3/log.h"
#include "ns3/socket.h"
#include "ns3/packet.h"
#include "ns3/node.hpp"

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/bind.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "udp_tracker_connection.hpp"
#include "udp-p2p-header.h"
#include "libtorrent/peer.hpp"

using boost::bind;
using namespace std;
using namespace ns3;

namespace libtorrent
{
    using namespace ns3;
    NS_LOG_COMPONENT_DEFINE ("UdpP2PClient");

	std::map<Ipv4Address, udp_tracker_connection::connection_cache_entry>
		udp_tracker_connection::m_connection_cache;

	udp_tracker_connection::udp_tracker_connection(tracker_manager& man
                , tracker_request const& req
                , boost::weak_ptr<request_callback> c)
		: tracker_connection(man, req, c)
        , m_transaction_id(0)
		, m_attempts(0)
	{
	}

	void udp_tracker_connection::start()
	{
		std::string hostname;

        // build the socket from ns3 instead the ones from boost
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        m_socket = ns3::Socket::CreateSocket(GetNode(), tid);
        m_socket->Bind();
        
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		boost::shared_ptr<request_callback> cb = requester();
		if (cb) cb->debug_log(("*** UDP_TRACKER [ initiating name lookup: " + hostname + " ]").c_str());
#endif
	}

    void udp_tracker_connection::SetRemote(Ipv4Address ip, uint16_t port)
    {
        m_socket->Connect(InetSocketAddress (ip, port));
        remoteAddress = ip;
    }

    // TODO: wait to add callback of this method
	void udp_tracker_connection::on_receive(Ptr<Packet> p)
            /*error_code const& e
		, udp::endpoint const& ep, char const* buf, int size)*/
    {
		// ignore resposes before we've sent any requests
		if (m_state == action_error)
        {
            NS_LOG_INFO("unknown action type!");
            return;
        }

		//if (!m_socket.is_open())
        //{
         //   NS_LOG_INFO("socket is closed!");
        //    return; // the operation was aborted
       // }

		// ignore packet not sent from the tracker
		//if (m_target != ep) return;
		
/*
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		boost::shared_ptr<request_callback> cb = requester();
		if (cb)
		{
			char msg[200];
			snprintf(msg, 200, "<== UDP_TRACKER_PACKET [ size: %d ]", size);
			cb->debug_log(msg);
		}
#endif*/

        // 重置超时
	//	restart_read_timeout();

        UdpP2PHeader header;
        p->PeekHeader(header);

		int action = header.getAction();
		int transaction = header.getTransactionId();

/*#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		if (cb)
		{
			char msg[200];
			snprintf(msg, 200, "*** UDP_TRACKER_PACKET [ action: %d ]", action);
			cb->debug_log(msg);
		}
#endif*/

		// ignore packets with incorrect transaction id
		if (m_transaction_id != transaction) return;

		if (action == action_error)
		{
		//	fail(-1, std::string(ptr, size - 8).c_str());
			return;
		}

		// ignore packets that's not a response to our message
		if (action != m_state) return;

/*#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		if (cb)
		{
			char msg[200];
			snprintf(msg, 200, "*** UDP_TRACKER_RESPONSE [ tid: %x ]"
				, int(transaction));
			cb->debug_log(msg);
		}
#endif*/

        // 回复数据
		switch (m_state)
		{
			case action_connect:
				on_connect_response(header);
				break;
			case action_announce:
				on_announce_response(header);
				break;
			case action_scrape:
				on_scrape_response(header);
				break;
			default: break;
		}
	}

	void udp_tracker_connection::close()
	{
		m_socket->Close();
	}

	void udp_tracker_connection::on_connect_response(UdpP2PHeader &header)
	{
		// ignore packets smaller than 16 bytes
		//if (size < 16) return;

		//restart_read_timeout();
		// reset transaction
		m_transaction_id = 0;
		m_attempts = 0;
		uint64_t connection_id = header.getConnectionID();

		connection_cache_entry& cce = m_connection_cache[remoteAddress];
		cce.connection_id = connection_id;

		if (tracker_req().kind == tracker_request::announce_request)
			send_udp_announce();
		else if (tracker_req().kind == tracker_request::scrape_request)
			send_udp_scrape();
	}

    // 发送连接请求
	void udp_tracker_connection::send_udp_connect()
	{
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		boost::shared_ptr<request_callback> cb = requester();
		if (cb)
		{
			char hex_ih[41];
			to_hex((char const*)&tracker_req().info_hash[0], 20, hex_ih);
			char msg[200];
			snprintf(msg, 200, "==> UDP_TRACKER_CONNECT [%s]", hex_ih);
			cb->debug_log(msg);
		}
#endif

		if (m_transaction_id == 0)
			m_transaction_id = std::rand() ^ (std::rand() << 16);

        UdpP2PHeader header;
        header.setAction((int32_t)action_connect);
        header.setTransactionId(m_transaction_id);

        Ptr<Packet> p = Create<Packet>(128);
        p->AddHeader (header);

        m_socket->Send(p);
		m_state = action_connect;
		++m_attempts;
	}

    // 发送刮请求
	void udp_tracker_connection::send_udp_scrape()
	{
		if (m_transaction_id == 0)
			m_transaction_id = std::rand() ^ (std::rand() << 16);

        UdpP2PHeader header;
        header.setAction((int32_t) action_scrape);
        header.setTransactionId(m_transaction_id);
        header.setAnnounceIp(this->remoteAddress.Get());
        header.setTrackerReq(this->tracker_req());

        Ptr<Packet> p = Create<Packet>(128);
        p->AddHeader (header);

        m_socket->Send(p);
		m_state = action_scrape;
		++m_attempts;
	}

	void udp_tracker_connection::on_announce_response(UdpP2PHeader &header)
	{
		//restart_read_timeout();
        
        // TODO: 待完成BOOST的更换后，使用这四个变量
		//int interval = header.getInterval();
		//int min_interval = 60;
		//int leechers = header.getLeechersList().size();
		//int seeders = header.getSeedersList().size();

		boost::shared_ptr<request_callback> cb = requester();
//#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
//		if (cb)
//		{
//			boost::shared_ptr<request_callback> cb = requester();
//			char msg[200];
//			snprintf(msg, 200, "<== UDP_TRACKER_RESPONSE [ url: %s ]", tracker_req().url.c_str());
//			cb->debug_log(msg);
//		}
//#endif

		if (!cb)
		{
			m_man.remove_request(this);
			return;
		}

        // TODO: 待处理
		std::vector<peer_entry> peer_list;
        std::list<uint32_t>::iterator iter;
        std::list<uint16_t>::iterator portIter;
        portIter = header.getLeecherPortList().begin();

        std::list<uint32_t>& leechersList = header.getLeechersList();
		for (iter = leechersList.begin();iter != leechersList.end();++iter)
		{
			peer_entry e;
			char ip_string[100];
			
            uint32_t ip = *iter;
            unsigned int a = ip >> 24 & 0xff; 
			unsigned int b = ip >> 16 & 0xff;
			unsigned int c = ip >> 8 & 0xff;
			unsigned int d = ip >> 0 & 0xff;
			snprintf(ip_string, 100, "%u.%u.%u.%u", a, b, c, d);
			e.ip = ip_string;
            
			e.port = *portIter;
			e.pid.clear();
			peer_list.push_back(e);
            portIter++;
		}

        std::list<uint32_t>& seedersList = header.getSeedersList();
        portIter = header.getSeederPortList().begin();
        for (iter = seedersList.begin();iter != seedersList.end();++iter)
        {
			peer_entry e;
			char ip_string[100];
			
            uint32_t ip = *iter;
            unsigned int a = ip >> 24 & 0xff; 
			unsigned int b = ip >> 16 & 0xff;
			unsigned int c = ip >> 8 & 0xff;
			unsigned int d = ip >> 0 & 0xff;
			snprintf(ip_string, 100, "%u.%u.%u.%u", a, b, c, d);
			e.ip = ip_string;
            
			e.port = *portIter;
			e.pid.clear();
			peer_list.push_back(e);
            portIter++;
        }

        //TODO: Boost的网络管理待更换
		//std::list<address> ip_list;
		//for (std::list<udp::endpoint>::const_iterator i = m_endpoints.begin()
		//	, end(m_endpoints.end()); i != end; ++i)
		//{
		//	ip_list.push_back(i->address());
		//}

		//cb->tracker_response(tracker_req(), m_target.address(), ip_list
		//	, peer_list, interval, min_interval, seeders leechers, address());

		m_man.remove_request(this);
		close();
	}

	void udp_tracker_connection::on_scrape_response(UdpP2PHeader &header)
	{
		//restart_read_timeout();
        // TODO: 修改解析代码
		int action = -1;//detail::read_int32(buf);
		int transaction = -1;//detail::read_int32(buf);

		if (transaction != m_transaction_id)
		{
			fail(-1, "incorrect transaction id");
			return;
		}

		if (action == action_error)
		{
			//fail(-1, std::string(buf, size - 8).c_str());
			return;
		}

		if (action != action_scrape)
		{
			fail(-1, "invalid action in announce response");
			return;
		}

        list<uint32_t>& seedersList = header.getSeedersList();
        list<uint32_t>& completedList = header.getCompletedList();
        list<uint32_t>& leechersList = header.getLeechersList();

        int count = seedersList.size();
        list<uint32_t>::iterator seederIter = seedersList.begin();
        list<uint32_t>::iterator completedIter = completedList.begin();
        list<uint32_t>::iterator leechersIter = leechersList.begin();
        
        for (int i = 0;i < count;++i)
        {
		    int complete = *seederIter;
    		int downloaded = *completedIter;
	    	int incomplete = *leechersIter;

		    boost::shared_ptr<request_callback> cb = requester();
    		if (!cb)
	    	{
		    	close();
			    return;
    		}
		
	    	cb->tracker_scrape_response(tracker_req()
		    	, complete, incomplete, downloaded);

            seederIter++;
            completedIter++;
            leechersIter++;
        }
		m_man.remove_request(this);
		close();
	}

    // 发送声明请求
	void udp_tracker_connection::send_udp_announce()
	{
		if (m_transaction_id == 0)
			m_transaction_id = std::rand() ^ (std::rand() << 16);

        UdpP2PHeader header;
        header.setAction((int32_t) action_announce);
        header.setTransactionId(m_transaction_id);
        header.setAnnounceIp(this->remoteAddress.Get());
        header.setTrackerReq(this->tracker_req());

        Ptr<Packet> p = Create<Packet>(128);
        p->AddHeader (header);


#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		boost::shared_ptr<request_callback> cb = requester();
		if (cb)
		{
			char hex_ih[41];
			to_hex((char const*)&req.info_hash[0], 20, hex_ih);
			char msg[200];
			snprintf(msg, 200, "==> UDP_TRACKER_ANNOUNCE [%s]", hex_ih);
			cb->debug_log(msg);
		}
#endif

		error_code ec;
        m_socket->Send(p);
		m_state = action_announce;
		++m_attempts;
		if (ec)
		{
			fail(-1, ec.message().c_str());
			return;
		}
	}

}

