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
#include "ns3/libtorrent/io.hpp"

#include "ns3/libtorrent/parse_url.hpp"

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
#include "ns3/ipv4.h"

using boost::bind;
using namespace std;
using namespace ns3;

namespace libtorrent
{
    using namespace ns3;
    NS_LOG_COMPONENT_DEFINE ("UdpTrackerConnection");

	std::map<Ipv4Address, udp_tracker_connection::connection_cache_entry>
		udp_tracker_connection::m_connection_cache;

	udp_tracker_connection::udp_tracker_connection(tracker_manager& man
                , tracker_request const& req
                , boost::shared_ptr<request_callback> c, ns3::Ptr<ns3::Node> node
                , ns3::Ipv4Address addr)
		: tracker_connection(man, req, c)
        , m_transaction_id(0)
		, m_attempts(0)
        , m_node(node)
	{
        ip = addr;
        NS_LOG_IP_FUNCTION(ip,this);
	}

    

	void udp_tracker_connection::start()
	{
        NS_LOG_IP_FUNCTION(ip,this);

        // build the socket from ns3 instead the ones from boost
        NS_LOG_INFO(m_node->GetObject<Ipv4>()->GetAddress(1,0).GetLocal());
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        m_socket = ns3::Socket::CreateSocket(m_node, tid);
        m_socket->Bind();
        
        error_code ec;
        int port;
        std::string hostname;

		using boost::tuples::ignore;
		boost::tie(ignore, ignore, hostname, port, ignore)
			= parse_url_components(tracker_req().url, ec);

        NS_LOG_INFO("connect info ip "<< hostname <<", port"<<port);

		m_target.SetLocalPort(port);
        m_target.SetLocalAddress(Ipv4Address(hostname.c_str()));
        m_socket->SetRecvCallback(MakeCallback(&udp_tracker_connection::handleRecv, this));
        m_socket->Connect(InetSocketAddress (Ipv4Address(hostname.c_str()), port));

        Simulator::Schedule(Time::FromInteger(1, Time::S), &udp_tracker_connection::start_announce, this);
	//	start_announce();

#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		boost::shared_ptr<request_callback> cb = requester();
		if (cb) cb->debug_log(("*** UDP_TRACKER [ initiating name lookup: " + hostname + " ]").c_str());
#endif
	}
//
//    void udp_tracker_connection::SetRemote(Ipv4Address ip, uint16_t port)
//    {
//        m_socket->Connect(InetSocketAddress (ip, port));
//        remoteAddress = ip;
//    }
//
	void udp_tracker_connection::start_announce()
    {
        NS_LOG_IP_FUNCTION(ip,this);
//		std::map<Ipv4Address, connection_cache_entry>::iterator cc
//			= m_connection_cache.find(m_target.GetLocalAddress());
//		if (cc != m_connection_cache.end())
//		{
//			// we found a cached entry! Now, we can only
//			// use if if it hasn't expired
//			if (time_now() < cc->second.expires)
//			{
//				if (tracker_req().kind == tracker_request::announce_request)
//					send_udp_announce();
//				else if (tracker_req().kind == tracker_request::scrape_request)
//					send_udp_scrape();
//				return;
//			}
//			// if it expired, remove it from the cache
//			m_connection_cache.erase(cc);
//		}

		send_udp_connect();
	}

    void udp_tracker_connection::handleRecv(Ptr<Socket> sock)
    {
        NS_LOG_IP_FUNCTION(ip,this);
        Ptr<Packet> packet;
        Address from;
        // TODO: 与解析代码结合起来！！
        while ((packet = sock->RecvFrom (from)))
        {
            //uint32_t size = packet->GetSize();
            
            if (InetSocketAddress::IsMatchingType (from))
            {
                NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s peer received " << packet->GetSize () << " bytes from " <<
                       InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                       InetSocketAddress::ConvertFrom (from).GetPort ());

                on_receive(packet);
            //UdpP2PHeader header;
            //packet->RemoveHeader (header);
            }
        }
    }

    // TODO: wait to add callback of this method
	void udp_tracker_connection::on_receive(Ptr<Packet> p)
            /*error_code const& e
		, ns3::Ipv4EndPoint const& ep, char const* buf, int size)*/
    {
        NS_LOG_IP_FUNCTION(ip,this);
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

        //UdpP2PHeader header;
        //p->PeekHeader(header);


        uint8_t* buffer = new uint8_t[p->GetSize()];
        uint8_t* ptr = buffer;
        p->CopyData(ptr, p->GetSize());

		int action = detail::read_uint32(ptr);
		int transaction = detail::read_uint32(ptr);

/*#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING
		if (cb)
		{
			char msg[200];
			snprintf(msg, 200, "*** UDP_TRACKER_PACKET [ action: %d ]", action);
			cb->debug_log(msg);
		}
#endif*/

		// ignore packets with incorrect transaction id
		if (m_transaction_id != transaction) 
        {
            NS_LOG_ERROR("transaction id error");
            delete ptr;
            return;
        }

		if (action == action_error)
		{
            NS_LOG_ERROR("action is error");
		//	fail(-1, std::string(ptr, size - 8).c_str());
            delete ptr;
			return;
		}

		// ignore packets that's not a response to our message
		if (action != m_state)
        {
            NS_LOG_ERROR("state error");
            delete ptr;
            return;
        }

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
            {
                NS_LOG_INFO(this << " receive connection response");
				on_connect_response(buffer, p->GetSize());
				break;
            }
			case action_announce:
                NS_LOG_INFO(this << " receive announce response");
				on_announce_response(buffer, p->GetSize());
				break;
			case action_scrape:
                NS_LOG_INFO(this << " receive scrape response");
				on_scrape_response(buffer, p->GetSize());
				break;
			default: 
                NS_LOG_ERROR("action state error");
                break;
		}

        delete buffer;
	}

	void udp_tracker_connection::close()
	{
        tracker_connection::close();
		m_socket->Close();
	}

	void udp_tracker_connection::on_connect_response(uint8_t* buf, uint32_t size)
	{
        NS_LOG_IP_FUNCTION(ip,this);
		// ignore packets smaller than 16 bytes
		//if (size < 16) return;

		//restart_read_timeout();
		// reset transaction
        buf += 8;
		m_transaction_id = 0;
		m_attempts = 0;
		uint64_t connection_id = detail::read_uint64(buf);

		connection_cache_entry& cce = m_connection_cache[m_target.GetLocalAddress()];
		cce.connection_id = connection_id;

        NS_LOG_INFO("receive connection id is "<< connection_id);

		if (tracker_req().kind == tracker_request::announce_request)
			send_udp_announce();
		else if (tracker_req().kind == tracker_request::scrape_request)
			send_udp_scrape();
	}

    // 发送连接请求
	void udp_tracker_connection::send_udp_connect()
	{
        NS_LOG_IP_FUNCTION(ip,this);

		boost::shared_ptr<request_callback> cb = requester();
		if (cb)
		{
			char hex_ih[41];
			to_hex((char const*)&tracker_req().info_hash[0], 20, hex_ih);
			char msg[200];
			snprintf(msg, 200, "==> UDP_TRACKER_CONNECT [%s]", hex_ih);
			cb->debug_log(msg);
		}

		char buf[16];
		char* ptr = buf;

		if (m_transaction_id == 0)
			m_transaction_id = std::rand() ^ (std::rand() << 16);

		detail::write_uint32(0x417, ptr);
		detail::write_uint32(0x27101980, ptr); // connection_id
		detail::write_uint32(action_connect, ptr); // action (connect)
		detail::write_uint32(m_transaction_id, ptr); // transaction_id
		TORRENT_ASSERT(ptr - buf == sizeof(buf));

        Ptr<Packet> p = Create<Packet>((uint8_t*)&buf, 16);

        m_socket->Send(p);
		m_state = action_connect;
		++m_attempts;
	}

    // 发送刮请求
	void udp_tracker_connection::send_udp_scrape()
	{
        NS_LOG_IP_FUNCTION(ip,this);

		if (m_transaction_id == 0)
			m_transaction_id = std::rand() ^ (std::rand() << 16);

        UdpP2PHeader header;
        header.setAction((int32_t) action_scrape);
        header.setTransactionId(m_transaction_id);
        header.setAnnounceIp(this->m_target.GetLocalAddress().Get());
        header.setTrackerReq(this->tracker_req());

        Ptr<Packet> p = Create<Packet>(128);
        p->AddHeader (header);

        m_socket->Send(p);
		m_state = action_scrape;
		++m_attempts;
	}

	void udp_tracker_connection::on_announce_response(uint8_t* buf, uint32_t size)
	{
        NS_LOG_IP_FUNCTION(ip,GetAddress() << this);
		//restart_read_timeout();
        
        buf += 8;
        // TODO: 待完成BOOST的更换后，使用这四个变量
		int interval = detail::read_int32(buf);
		int min_interval = 60;
		int leechers = detail::read_int32(buf);
		int seeders = detail::read_int32(buf);
        int num_peers = (size - 20) / 6;

        if ((size - 20) % 6 != 0)
        {
            NS_LOG_ERROR("invalid tracker response length");
            return;
        }

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
            NS_LOG_ERROR("no callback");
			m_man.remove_request(this);
            //close();
			return;
		}

		std::vector<peer_entry> peer_list;

		for (int i = 0;i < num_peers; ++i)
		{
			peer_entry e;
			char ip_string[100];
			
            unsigned int a = detail::read_uint8(buf);//ip >> 24 & 0xff; 
			unsigned int b = detail::read_uint8(buf);//ip >> 16 & 0xff;
			unsigned int c = detail::read_uint8(buf);//ip >> 8 & 0xff;
			unsigned int d = detail::read_uint8(buf);//ip >> 0 & 0xff;
			snprintf(ip_string, 100, "%u.%u.%u.%u", a, b, c, d);
			e.ip = ip_string;
			e.port = detail::read_uint16(buf);
			e.pid.clear();
            NS_LOG_INFO("peer list " << i << " is "<< ip_string);
			peer_list.push_back(e);
		}

		std::list<Address> ip_list;
		for (std::list<ns3::Ipv4EndPoint>::const_iterator i = m_endpoints.begin()
			, end(m_endpoints.end()); i != end; ++i)
		{
			ip_list.push_back((Address)i->GetLocalAddress());
		}

		cb->tracker_response(tracker_req(), (Address)m_target.GetLocalAddress(), ip_list
			, peer_list, interval, min_interval, seeders, leechers, Address(), "");

		//m_man.remove_request(this);
		//close();
	}

	void udp_tracker_connection::on_scrape_response(uint8_t* buf, uint32_t size)
	{
        NS_LOG_IP_FUNCTION(ip,this);
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

		int complete = detail::read_int32(buf);
		int downloaded = detail::read_int32(buf);
		int incomplete = detail::read_int32(buf);
		boost::shared_ptr<request_callback> cb = requester();

		if (!cb)
		{
			close();
			return;
		}

		cb->tracker_scrape_response(tracker_req()
			, complete, incomplete, downloaded);

		close();
	}

    // 发送声明请求
	void udp_tracker_connection::send_udp_announce()
	{
        NS_LOG_IP_FUNCTION(ip,this);
		if (m_transaction_id == 0)
			m_transaction_id = std::rand() ^ (std::rand() << 16);

        std::map<Ipv4Address, connection_cache_entry>::iterator i = m_connection_cache.find(m_target.GetLocalAddress());
        if (i == m_connection_cache.end())
        {
            NS_LOG_ERROR("failed to find the connection of the target");
            return;
        }

        uint8_t buffer[800];
        uint8_t* out = buffer;
		detail::write_int64(i->second.connection_id, out); // connection_id
		detail::write_int32(action_announce, out); // action (announce)
		detail::write_int32(m_transaction_id, out); // transaction_id

        tracker_request const& req = tracker_req();
		std::copy(req.info_hash.begin(), req.info_hash.end(), out); // info_hash
		out += 20;
		std::copy(req.pid.begin(), req.pid.end(), out); // peer_id
		out += 20;
		const bool stats = req.send_stats;
		detail::write_int64(stats ? req.downloaded : 0, out); // downloaded
		detail::write_int64(stats ? req.left : 0, out); // left
		detail::write_int64(stats ? req.uploaded : 0, out); // uploaded
		detail::write_int32(req.event, out); // event

        uint32_t ipv432 = this->m_target.GetLocalAddress().Get();
        detail::write_uint32(ipv432, out);
		detail::write_int32(req.key, out); // key
		detail::write_int32(req.num_want, out); // num_want
		detail::write_uint16(req.listen_port, out); // port

		std::string request_string;
		error_code ec;
		using boost::tuples::ignore;
		boost::tie(ignore, ignore, ignore, ignore, request_string) = parse_url_components(req.url, ec);

		if (ec)
        {
            NS_LOG_ERROR("failed to parse url!");
            request_string.clear();
        }

		if (!request_string.empty())
        {
			int str_len = (std::min)(int(request_string.size()), 255);
			request_string.resize(str_len);

			detail::write_uint8(2, out);
			detail::write_uint8(str_len, out);
			detail::write_string(request_string, out);
        }

        uint32_t size = out - buffer;
        Ptr<Packet> p = Create<Packet>(buffer, size);

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

