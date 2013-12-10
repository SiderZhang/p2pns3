/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef P2P_CLIENT_HELPER_H
#define P2P_CLIENT_HELPER_H

#include "ns3/application-container.h"
#include "ns3/ipv4-address.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"

namespace ns3 {

    /*
     * 这是P2P的客户端
     */
    class P2P_Client
    {
    public:
        P2P_Client ();
        P2P_Client (Ipv4Address ip, uint16_t port);
        P2P_Client (Address ip, uint16_t port);

        ApplicationContainer Install (NodeContainer c);

        void SetAttribute (std::string name, const ns3::AttributeValue &value);
    private:
        ObjectFactory m_factory;
    };

}

#endif /* P2P_CLIENT_HELPER_H */

