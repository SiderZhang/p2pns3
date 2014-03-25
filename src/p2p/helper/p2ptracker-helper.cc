/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "p2ptracker-helper.h"
#include "ns3/udpTracker.hpp"

namespace ns3 {
    using namespace UDPT;

/* ... */
    UdpTrackerHelper::UdpTrackerHelper(uint16_t port)
    {
        m_factory.SetTypeId(UDPT::UDPTracker::GetTypeId());
        SetAttribute ("Port", UintegerValue (port));
    }

    ApplicationContainer UdpTrackerHelper::Install(Ptr<Node> node, ns3::Ipv4Address ip)
    {
        return ApplicationContainer(InstallPriv(node, ip));
    }

    Ptr<Application> UdpTrackerHelper::InstallPriv(Ptr<Node> node, ns3::Ipv4Address ip) const
    {
        Ptr<UDPTracker> tracker = m_factory.Create<UDPTracker>();
        tracker->setIp(ip);
        node->AddApplication(tracker);
        return tracker;
    }
    
    void UdpTrackerHelper::SetAttribute(std::string name, const AttributeValue& value)
    {
        m_factory.Set (name, value);
    }
}

