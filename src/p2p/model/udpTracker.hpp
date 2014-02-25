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

#ifndef UDPTRACKER_H_
#define UDPTRACKER_H_


#include <stdint.h>
#include "multiplatform.h"
#include "ns3/driver_sqlite.hpp"
#include "udptSettings.hpp"
#include "ns3/application.h"
#include "ns3/ptr.h"
#include "udp-p2p-header.h"

#include <string>
using namespace std;

#define UDPT_DYNAMIC			0x01	// Track Any info_hash?
#define UDPT_ALLOW_REMOTE_IP	0x02	// Allow client's to send other IPs?
#define UDPT_ALLOW_IANA_IP		0x04	// allow IP's like 127.0.0.1 or other IANA reserved IPs?
#define UDPT_VALIDATE_CLIENT	0x08	// validate client before adding to Database? (check if connection is open?)


namespace UDPT
{
	class UDPTracker : public ns3::Application
	{
	public:
		typedef struct udp_error_response
		{
			uint32_t action;
			uint32_t transaction_id;
			char *message;
		} ErrorResponse;

		enum StartStatus
		{
			START_OK = 0,
			START_ESOCKET_FAILED = 1,
			START_EBIND_FAILED = 2
		};
        static ns3::TypeId GetTypeId(void);

		/**
		 * Initializes the UDP Tracker.
		 * @param settings Settings to start server with
		 */
		UDPTracker (Settings *);

        UDPTracker ();

		/**
		 * Starts the Initialized instance.
		 * @return 0 on success, otherwise non-zero.
		 */
		enum StartStatus start ();

		/**
		 * Joins all threads, and waits for all of them to terminate.
		 */
		void wait ();

		/**
		 * Destroys resources that were created by constructor
		 * @param usi Instance to destroy.
		 */
		virtual ~UDPTracker ();

		Data::DatabaseDriver *conn;
    protected:
        enum StartStatus buildSocket();
        virtual void DoDispose(void);

	private:
        void init(Settings* settings);
        virtual void StartApplication(void);
        virtual void StopApplication(void);

		//SOCKET sock;
        ns3::Ptr<ns3::Socket> m_socket;
        
        // TODO: 待修正
//		SOCKADDR_IN localEndpoint;
		uint16_t port;
		uint8_t thread_count;
		bool isRunning;
		bool isDynamic;
		bool allowRemotes;
		bool allowIANA_IPs;
        // TODO: 待修正
		//HANDLE *threads;
		uint32_t announce_interval;
		uint32_t cleanup_interval;

		Settings *o_settings;
        
        void HandleRead (ns3::Ptr<ns3::Socket> socket);

        /*
#ifdef WIN32
		static DWORD _thread_start (LPVOID arg);
		static DWORD _maintainance_start (LPVOID arg);
#elif defined (linux)
		static void* _thread_start (void *arg);
		static void* _maintainance_start (void *arg);
#endif*/

		static int resolveRequest (UDPTracker *usi, ns3::Address *remote, ns3::UdpP2PHeader& header);

		static int handleConnection (UDPTracker *usi, ns3::Address *remote, ns3::UdpP2PHeader& header);
		static int handleAnnounce (UDPTracker *usi, ns3::Address *remote, ns3::UdpP2PHeader& header);
		static int handleScrape (UDPTracker *usi, ns3::Address *remote, ns3::UdpP2PHeader& header);

		static int sendError (UDPTracker *, ns3::Address *remote, uint32_t transId, const string &);

    protected:
        void sendto(ns3::UdpP2PHeader& header, int flags, ns3::Address* remote);
	};
};

#endif /* UDPTRACKER_H_ */
