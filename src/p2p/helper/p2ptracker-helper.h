/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef P2PTRACKER_HELPER_H
#define P2PTRACKER_HELPER_H

#include "ns3/p2ptracker.h"
#include "ns3/log.h"
#include "ns3/abort.h"
#include "ns3/config.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/inet-socket-address.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/udp-client-server-helper.h"
#include "ns3/udp-echo-helper.h"
#include "ns3/simple-net-device.h"
#include "ns3/simple-channel.h"
#include "ns3/ipv4-address.h"

namespace ns3 {

/* ... */
    class UdpTrackerHelper
    {
        public:
            UdpTrackerHelper(uint16_t port);
            ApplicationContainer Install(Ptr<Node> node, ns3::Ipv4Address ip);

            Ptr<Application> InstallPriv(Ptr<Node> node, ns3::Ipv4Address ip) const;

            void SetAttribute(std::string name, const AttributeValue& value);
        private:
            ObjectFactory m_factory;
    };
}

#endif /* P2PTRACKER_HELPER_H */

