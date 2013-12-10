/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "p2p-client-helper.h"
#include "ns3/udp_tracker_connection.hpp"
#include "ns3/uinteger.h"

namespace ns3 {
    using namespace libtorrent;

/* ... */
    P2P_Client::P2P_Client()
    {
    }

    P2P_Client::P2P_Client(Ipv4Address ip, uint16_t port)
    {
        m_factory.SetTypeId (udp_tracker_connection::GetTypeId());
        SetAttribute("RemoteAddress", AddressValue(Address(ip)));
        SetAttribute("RemotePort", UintegerValue(port));
    }

    P2P_Client::P2P_Client(Address ip, uint16_t port)
    {
        m_factory.SetTypeId (udp_tracker_connection::GetTypeId());
        SetAttribute("RemoteAddress", AddressValue(ip));
        SetAttribute("RemotePort", UintegerValue(port));
    }

    void P2P_Client::SetAttribute (std::string name, const AttributeValue &value)
    {
        m_factory.Set (name, value);
    }

    ApplicationContainer P2P_Client::Install(NodeContainer c)
    {
        ApplicationContainer apps;
        for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
        {
            Ptr<Node> node = *i;
            Ptr<udp_tracker_connection> client = m_factory.Create<udp_tracker_connection> ();
            node->AddApplication (client);
            apps.Add (client);
        }
        return apps;
    }
}

