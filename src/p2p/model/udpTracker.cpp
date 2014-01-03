/*
 *	Copyright © 2012,2013 Naim A.
 *
 *	This file is part of UDPT.
 *
 *		UDPT is free software: you can redistribute it and/or modify
 *		it under the terms of the GNU General Public License as published by
 *		the Free Software Foundation, either version 3 of the License, or
 *		(at your option) any later version.
 *
 *		UDPT is distributed in the hope that it will be useful,
 *		but WITHOUT ANY WARRANTY; without even the implied warranty of
 *		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *		GNU General Public License for more details.
 *
 *		You should have received a copy of the GNU General Public License
 *		along with UDPT.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/socket.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "udpTracker.hpp"
#include "tools.h"
#include <cstdlib> // atoi
#include <cstring>
#include <ctime>
#include <iostream>
#include <sstream>
#include "multiplatform.h"
#include "logging.h"

UDPT::Logger *logger;

using namespace std;
using namespace UDPT::Data;
using namespace ns3;

#define UDP_BUFFER_SIZE		2048

namespace UDPT
{
using namespace ns3;
    NS_LOG_COMPONENT_DEFINE("UDPTracker");
    NS_OBJECT_ENSURE_REGISTERED (UDPTracker);

    TypeId UDPTracker::GetTypeId(void)
    {
        static TypeId tid = TypeId("UDPT::UDPTracker").SetParent<Application>()
            .AddConstructor<UDPTracker>();
        return tid;
    }

    UDPTracker::UDPTracker()
    {
        NS_LOG_FUNCTION (this);
        Settings* settings = new Settings("");
		const char strDATABASE[] = "database";
		const char strTRACKER[] = "tracker";
		const char strAPISRV [] = "apiserver";
		// set default settings:

		settings->set (strDATABASE, "driver", "sqlite3");
		settings->set (strDATABASE, "file", "tracker.db");

		settings->set (strTRACKER, "is_dynamic", "0");
		settings->set (strTRACKER, "port", "6969");		// UDP PORT

        // TODO: 线程的处理
		//settings->set (strTRACKER, "threads", "5");
		settings->set (strTRACKER, "allow_remotes", "1");
		settings->set (strTRACKER, "allow_iana_ips", "1");
		settings->set (strTRACKER, "announce_interval", "1800");
		settings->set (strTRACKER, "cleanup_interval", "120");

		settings->set (strAPISRV, "enable", "1");
		//settings->set (strAPISRV, "threads", "1");
		settings->set (strAPISRV, "port", "6969");	// TCP PORT

        init(settings);
    }

	UDPTracker::UDPTracker (Settings *settings)
	{
        init(settings);
    }

    void UDPTracker::init(Settings* settings)
    {
        NS_LOG_FUNCTION (this);
		Settings::SettingClass *sc_tracker;

		sc_tracker = settings->getClass("tracker");

		this->allowRemotes = sc_tracker->getBool("allow_remotes", true);
		this->allowIANA_IPs = sc_tracker->getBool("allow_iana_ips", false);
		this->isDynamic = sc_tracker->getBool("is_dynamic", true);

		this->announce_interval = sc_tracker->getInt("announce_interval", 1800);
		this->cleanup_interval = sc_tracker->getInt("cleanup_interval", 120);
		this->port = sc_tracker->getInt("port", 6969);

        // TODO: 线程
		//this->thread_count = abs (sc_tracker->getInt("threads", 5)) + 1;

	//	list<SOCKADDR_IN> addrs;
	//	sc_tracker->getIPs("bind", addrs);

	//	if (addrs.empty())
	//	{
	//		SOCKADDR_IN sa;
	//		sa.sin_port = m_hton16(port);
	//		sa.sin_addr.s_addr = 0L;
	//		addrs.push_back(sa);
	//	}

	//	this->localEndpoint = addrs.front();

        // TODO: 线程
		//this->threads = new HANDLE[this->thread_count];

		this->isRunning = false;
		this->conn = NULL;
		this->o_settings = settings;

        if (logger != NULL)
        {
            logger = new Logger(settings);
        }
	}

	UDPTracker::~UDPTracker ()
	{
        NS_LOG_FUNCTION (this);
		int i; // loop index

		this->isRunning = false;

        if (logger != NULL)
        {
            delete logger;
            logger = NULL;
        }

		// drop listener connection to continue thread loops.
		// wait for request to finish (1 second max; allot of time for a computer!).

/*	#ifdef linux
		close (this->sock);

		sleep (1);
	#elif defined (WIN32)
		closesocket (this->sock);

		Sleep (1000);
	#endif*/

		for (i = 0;i < this->thread_count;i++)
		{
            // TODO: 线程
            /*
	#ifdef WIN32
		TerminateThread (this->threads[i], 0x00);
	#elif defined (linux)
			pthread_detach (this->threads[i]);
			pthread_cancel (this->threads[i]);
	#endif*/
			stringstream str;
			str << "Thread (" << (i + 1) << "/" << ((int)this->thread_count) << ") terminated.";
		//	logger->log(Logger::LL_INFO, str.str());
		}
		if (this->conn != NULL)
			delete this->conn;
        // TODO: 线程
		// delete[] this->threads;
	}

	void UDPTracker::wait()
	{
        NS_LOG_FUNCTION (this);
/*#ifdef WIN32
		WaitForMultipleObjects(this->thread_count, this->threads, TRUE, INFINITE);
#else
		int i;
		for (i = 0;i < this->thread_count; i++)
		{
			pthread_join (this->threads[i], NULL);
		}
#endif*/
	}

    enum UDPTracker::StartStatus UDPTracker::buildSocket()
    {
        NS_LOG_FUNCTION (this);
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        // TODO: 等待添加端口号
        uint16_t m_port = 6969;
        m_socket = Socket::CreateSocket(GetNode(), tid);
        ns3::InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_port);
        m_socket->SetRecvCallback(MakeCallback (&UDPTracker::HandleRead, this));
        m_socket->Bind(local);

		return START_OK;
    }

	enum UDPTracker::StartStatus UDPTracker::start ()
	{
        NS_LOG_FUNCTION (this);
        StartStatus result = buildSocket();
        if (result != START_OK)
            return result;

		this->conn = new Data::SQLite3Driver (this->o_settings->getClass("database"),
				this->isDynamic);

		this->isRunning = true;

		stringstream ss;
		ss.str("");
		ss << "Starting maintenance thread (1/" << ((int)this->thread_count) << ")";

        // TODO: 后期将日志功能补上
		//logger->log(Logger::LL_INFO, ss.str());

        // TODO: 增加维护线程
		// create maintainer thread.
/*	#ifdef WIN32
		this->threads[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_maintainance_start, (LPVOID)this, 0, NULL);
	#elif defined (linux)
		pthread_create (&this->threads[0], NULL, _maintainance_start, (void*)this);
	#endif
*/
		return START_OK;
	}

	int UDPTracker::sendError (UDPTracker *usi, Address *remote, uint32_t transactionID, const string &msg)
	{
		struct udp_error_response error;
		int msg_sz,	// message size to send.
			i;		// copy loop
		char buff [1024];	// more than reasonable message size...

		error.action = m_hton32 (3);
		error.transaction_id = transactionID;
		error.message = (char*)msg.c_str();

		msg_sz = 4 + 4 + 1 + msg.length();

		// test against overflow message. resolves issue 4.
		if (msg_sz > 1024)
			return -1;

		memcpy(buff, &error, 8);
		for (i = 8;i <= msg_sz;i++)
		{
			buff[i] = msg[i - 8];
		}

        //TODO: 等待添加传输错误信息的功能
        NS_LOG_INFO("error info from tracker");
	    //usi->sendto((uint8_t*)buff, (size_t)msg_sz, 0, remote);

		return 0;
	}

	int UDPTracker::handleConnection (UDPTracker *usi, Address *remote, UdpP2PHeader& reqHeader)
	{
        //NS_LOG_FUNCTION (this);
        InetSocketAddress transport = InetSocketAddress::ConvertFrom (*remote);
        Ipv4Address addressv4 = transport.GetIpv4();
        uint16_t port = transport.GetPort();

        UdpP2PHeader respHeader;
		respHeader.setAction(m_hton32(0));
		respHeader.setTransactionId(reqHeader.getTransactionId());

        uint64_t connectionID = respHeader.getConnectionID();
		if (!usi->conn->genConnectionId(&connectionID,
				addressv4.Get(),
				port))
		{
			return 1;
		}

		usi->sendto(respHeader, 0, remote);

		return 0;
	}

	int UDPTracker::handleAnnounce (UDPTracker *usi, Address *remote, UdpP2PHeader& reqHeader)
	{
        //NS_LOG_FUNCTION (this);
		uint32_t q;		// peer counts
		int bSize;	// message size
		uint32_t i;		// loop index
		DatabaseDriver::PeerEntry *peers;
		DatabaseDriver::TorrentEntry tE;

		//uint8_t buff [1028];	// Reasonable buffer size. (header+168 peers)

        InetSocketAddress transport = InetSocketAddress::ConvertFrom (*remote);
        Ipv4Address addressv4 = transport.GetIpv4();
        uint16_t port = transport.GetPort();

		if (!usi->conn->verifyConnectionId(reqHeader.getConnectionID(),
				addressv4.Get(),
				port))
		{
			return 1;
		}

        
		if (!usi->allowRemotes && reqHeader.getIpAddress() != 0)
		{
			UDPTracker::sendError (usi, remote, reqHeader.getTransactionId(), "Tracker doesn't allow remote IP's; Request ignored.");
			return 0;
		}

		if (!usi->conn->isTorrentAllowed(reqHeader.getInfo_hash()))
		{
			UDPTracker::sendError(usi, remote, reqHeader.getTransactionId(), "info_hash not registered.");
			return 0;
		}

		// load peers
		q = 30;
		if (reqHeader.getNum_want() >= 1)
			q = min (q, reqHeader.getNum_want());

		peers = new DatabaseDriver::PeerEntry [q];

		DatabaseDriver::TrackerEvents event;
		switch (reqHeader.getEvent())
		{
		case 1:
			event = DatabaseDriver::EVENT_COMPLETE;
			break;
		case 2:
			event = DatabaseDriver::EVENT_START;
			break;
		case 3:
			event = DatabaseDriver::EVENT_STOP;
			break;
		default:
			event = DatabaseDriver::EVENT_UNSPEC;
			break;
		}

		if (event == DatabaseDriver::EVENT_STOP)
			q = 0;	// no need for peers when stopping.

        uint8_t* info_hash = reqHeader.getInfo_hash();
		if (q > 0)
			usi->conn->getPeers(info_hash, &q, peers);

		bSize = 20; // header is 20 bytes
		bSize += (6 * q); // + 6 bytes per peer.

		tE.info_hash = info_hash;
		usi->conn->getTorrentInfo(&tE);

		UdpP2PHeader respHeader;
		respHeader.setAction (1);
		respHeader.setInterval ( usi->announce_interval );
		respHeader.setLeechers (tE.leechers);
		respHeader.setSeeders (tE.seeders);
		respHeader.setTransactionId (reqHeader.getTransactionId());

        std::list<uint32_t>& ipList = respHeader.getLeechersList();
        std::list<uint16_t>& portList = respHeader.getLeecherPortList();
		for (i = 0;i < q;i++)
		{
			// IP
            ipList.push_back(peers[i].ip);

			// port
            portList.push_back(peers[i].port);
		}
		delete[] peers;
    	usi->sendto(respHeader, 0, remote);

		// update DB.
		uint32_t ip;
		if (reqHeader.getIpAddress() == 0) // default
			ip = addressv4.Get();
		else
			ip = reqHeader.getIpAddress();

		usi->conn->updatePeer(reqHeader.getPeerId(), reqHeader.getInfo_hash(), ip, reqHeader.getPort(),
				reqHeader.getDownloaded(), reqHeader.getLeft(), reqHeader.getUploaded(), event);

		return 0;
	}

	int UDPTracker::handleScrape (UDPTracker *usi, Address *remote, UdpP2PHeader& reqHeader)
	{
        //NS_LOG_FUNCTION (this);
		uint8_t hash [20];
		//uint8_t buffer [1024];	// up to 74 torrents can be scraped at once (17*74+8) < 1024

		// validate request length:
		/*if (v < 0 || v % 20 != 0)
		{
			UDPTracker::sendError (usi, remote, reqHeader.getTransactionId(), "Bad scrape request.");
			return 0;
		}*/

        InetSocketAddress transport = InetSocketAddress::ConvertFrom (*remote);
        Ipv4Address addressv4 = transport.GetIpv4();
        uint16_t port = transport.GetPort();

		if (!usi->conn->verifyConnectionId(reqHeader.getConnectionID(),
    	        addressv4.Get(), port))
		{
			return 1;
		}

		// get torrent count.

		UdpP2PHeader respHeader;
		respHeader.setAction(2);
		respHeader.setTransactionId (reqHeader.getTransactionId());

        std::list<uint8_t*>& hashList = respHeader.getinfo_hashList();
        std::list<uint8_t*>::iterator hashIter = hashList.begin();
        int c = hashList.size();

        std::list<uint32_t>& seedersList = respHeader.getSeedersList();
        std::list<uint32_t>& completedList = respHeader.getCompletedList();
        std::list<uint32_t>& leechersList = respHeader.getLeechersList();

		for (int i = 0;i < c;i++)
		{
            memcpy(hash, *hashIter, 20);
            
			DatabaseDriver::TorrentEntry tE;
			tE.info_hash = hash;
			if (!usi->conn->getTorrentInfo(&tE))
			{
				sendError(usi, remote, reqHeader.getTransactionId(), "Scrape Failed: couldn't retrieve torrent data");
				return 0;
			}

            seedersList.push_back(tE.seeders);
            completedList.push_back(tE.completed);
            leechersList.push_back(tE.leechers);
		}

		usi->sendto (respHeader, 0, remote);

		return 0;
	}

static int _isIANA_IP (uint32_t ip)
{
	uint8_t x = (ip % 256);
	if (x == 0 || x == 10 || x == 127 || x >= 224)
		return 1;
	return 0;
}

	int UDPTracker::resolveRequest (UDPTracker *usi, Address *remote, UdpP2PHeader& header)
	{
        //NS_LOG_FUNCTION (this);
		uint32_t action;
        InetSocketAddress transport = InetSocketAddress::ConvertFrom (*remote);
        Ipv4Address addressv4 = transport.GetIpv4();

		action = header.getAction();

		if (!usi->allowIANA_IPs)
		{
			if (_isIANA_IP (addressv4.Get()))
			{
				return 0;	// Access Denied: IANA reserved IP.
			}
        }

		//cout << ":: " << (void*)m_hton32(remote->sin_addr.s_addr) << ": " << m_hton16(remote->sin_port) << " ACTION=" << action << endl;

		if (action == 0)
			return UDPTracker::handleConnection (usi, remote, header);
		else if (action == 1)
			return UDPTracker::handleAnnounce (usi, remote, header);
		else if (action == 2)
			return UDPTracker::handleScrape (usi, remote, header);
		else
		{
			cout << "E: action=" << action << endl;
			UDPTracker::sendError (usi, remote, header.getTransactionId(), "Tracker couldn't understand Client's request.");
			return -1;
		}

		return 0;
	}

    void UDPTracker::HandleRead (Ptr<Socket> socket)
    {
        NS_LOG_FUNCTION (this << socket);
        Ptr<Packet> packet;
        Address from;
        // TODO: 与解析代码结合起来！！
        while ((packet = socket->RecvFrom (from)))
        {
            uint32_t size = packet->GetSize();
            uint8_t* buffer = new uint8_t[size];
            packet->CopyData(buffer, size);
            NS_LOG_INFO("Receved Packet" << (char*)buffer);

            UdpP2PHeader header;
            packet->RemoveHeader (header);
            
            if (InetSocketAddress::IsMatchingType (from))
            {
                NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s client received " << packet->GetSize () << " bytes from " <<
                       InetSocketAddress::ConvertFrom (from).GetIpv4 () << " port " <<
                       InetSocketAddress::ConvertFrom (from).GetPort ());

                UDPTracker::resolveRequest (this, &from , header);
            }
            else if (Inet6SocketAddress::IsMatchingType (from))
            {
                NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () << "s client received " << packet->GetSize () << " bytes from " <<
                       Inet6SocketAddress::ConvertFrom (from).GetIpv6 () << " port " <<
                       Inet6SocketAddress::ConvertFrom (from).GetPort ());
            }
        }

    }

//	void* UDPTracker::_thread_start (void *arg)
//	{
//		UDPTracker *usi;
//		SOCKADDR_IN remoteAddr;
//
//#ifdef linux
//		socklen_t addrSz;
//#else
//		int addrSz;
//#endif
//
//		int r;
//		char tmpBuff [UDP_BUFFER_SIZE];
//
//		usi = (UDPTracker*)arg;
//
//		//addrSz = sizeof (SOCKADDR_IN);
//
//
//		while (usi->isRunning)
//		{
//			cout.flush();
//            // TODO: 待修正
//			// peek into the first 12 bytes of data; determine if connection request or announce request.
//			//r = recvfrom(usi->sock, (char*)tmpBuff, UDP_BUFFER_SIZE, 0, (SOCKADDR*)&remoteAddr, &addrSz);
//			if (r <= 0)
//				continue;	// bad request...
//			r = UDPTracker::resolveRequest (usi, &remoteAddr, tmpBuff, r);
//		}
//
//	#ifdef linux
//		pthread_exit (NULL);
//	#endif
//		return 0;
//	}
//
//#ifdef WIN32
//	DWORD UDPTracker::_maintainance_start (LPVOID arg)
//#elif defined (linux)
//	void* UDPTracker::_maintainance_start (void *arg)
//#endif
//	{
//		UDPTracker *usi;
//
//		usi = (UDPTracker *)arg;
//
//		while (usi->isRunning)
//		{
//			usi->conn->cleanup();
//
//            // TODO: sleep需要改成NS3的版本
//            /*
//#ifdef WIN32
//			Sleep (usi->cleanup_interval * 1000);
//#elif defined (linux)
//			sleep (usi->cleanup_interval);
//#else
//#error Unsupported OS.
//#endif*/
//		}
//
//		return 0;
//	}

    void UDPTracker::StartApplication(void)
    {
        NS_LOG_FUNCTION (this);

	    int r = this->start();
	    if (r != UDPTracker::START_OK)
    	{
	    	cerr << "Error While trying to start server." << endl;
		    switch (r)
    		{
	    	case UDPTracker::START_ESOCKET_FAILED:
		    	cerr << "Failed to create socket." << endl;
			    break;
    		case UDPTracker::START_EBIND_FAILED:
	    		cerr << "Failed to bind socket." << endl;
		    	break;
    		default:
	    		cerr << "Unknown Error" << endl;
		    	break;
    		}
    		goto cleanup;
    	}

	    cout << "Hit Control-C to exit." << endl;

    	//usi->wait();

    cleanup:
    	cout << endl << "Goodbye." << endl;

    }

    void UDPTracker::StopApplication(void)
    {
        NS_LOG_FUNCTION(this);
    }

    void UDPTracker::DoDispose(void)
    {
        NS_LOG_FUNCTION(this);
        Application::DoDispose();
    }

    // TODO: 注意修正UDP传输的端口号
    void UDPTracker::sendto(UdpP2PHeader& header, int flags, Address* remote)
    {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> socket = Socket::CreateSocket(GetNode(), tid);
        socket->Bind();
        
        InetSocketAddress transport = InetSocketAddress::ConvertFrom (*remote);
        Ipv4Address addressv4 = transport.GetIpv4();
        uint16_t port = transport.GetPort();

        Ptr<Packet> p = Create<Packet> (header.getSize());
        p->AddHeader(header);
        socket->Connect (InetSocketAddress (addressv4, port));
        socket->Send(p);
		//sendto(usi->sock, (char*)&resp, sizeof(ConnectionResponse), 0, (SOCKADDR*)remote, sizeof(SOCKADDR_IN));
    }
};
