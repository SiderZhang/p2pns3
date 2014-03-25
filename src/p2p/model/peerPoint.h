#ifndef PEERPOINT_H
#define PEERPOINT_H

#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/application.h"
#include "ns3/ipv4-address.h"
#include "libtorrent/session.hpp"

namespace ns3
{
    class PeerPoint : public Application
    {
    public:
        static TypeId GetTypeId();

        PeerPoint();
        virtual ~PeerPoint();

        void start();
        // 给这个Peer设定IP 
        void setAddress(ns3::Ipv4Address addr);

        void setInitSeed()
        {
            this->initSeed = true;
        }
    protected:
        virtual void DoDispose (void);

        void loadTorrent(libtorrent::session* sess);

    private:
        virtual void StartApplication (void);
        virtual void StopApplication (void);

        libtorrent::session* ses;
        ns3::Ipv4Address ip;

        // attribute的东西
        uint32_t m_count;
        Time m_interval;
        Address m_peerAddress;
        uint16_t m_peerPort;
        uint32_t size;

        bool initSeed;
    };
}

#endif
