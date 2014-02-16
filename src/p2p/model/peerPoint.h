#ifndef PEER_H
#define PEER_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "libtorrent/session.hpp"

namespace ns3
{
    class PeerPoint : Application
    {
    public:
        static TypeId GetTypeId();

        PeerPoint();
        virtual ~PeerPoint();

        void start();

    protected:
        virtual void DoDispose (void);

        bool loadTorrent();

    private:
        virtual void StartApplication (void);
        virtual void StopApplication (void);

        libtorrent::session ses;
    };
}

#endif
