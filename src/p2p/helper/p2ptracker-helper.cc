/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "p2ptracker-helper.h"
#include "ns3/udpTracker.hpp"

namespace ns3 {
    using namespace UDPT;

/* ... */
    UdpTrackerHelper::UdpTrackerHelper()
    {
        m_factory.SetTypeId(UDPT::UDPTracker::GetTypeId());
    }

    ApplicationContainer UdpTrackerHelper::Install(Ptr<Node> node)
    {
        return ApplicationContainer(InstallPriv(node));
    }

    Ptr<Application> UdpTrackerHelper::InstallPriv(Ptr<Node> node) const
    {
        Ptr<UDPTracker> tracker = m_factory.Create<UDPTracker>();
        node->AddApplication(tracker);
        return tracker;
    }
}

