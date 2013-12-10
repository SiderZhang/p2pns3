/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// Network topology
//
//       n0    n1
//       |     |
//       =======
//         LAN
//
// - UDP flows from n0 to n1

#include "ns3/log.h"
#include "ns3/abort.h"
#include "ns3/config.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/inet-socket-address.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/tcp-client-server-helper.h"
#include "ns3/simple-net-device.h"
#include "ns3/simple-channel.h"
#include "ns3/test.h"
#include "ns3/simulator.h"
#include "ns3/udpTracker.hpp"

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"

//#include "ns3/video-req-tag.h"
//#include "ns3/peer-node.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/tcp-server.h"
#include "ns3/tcp-client.h"
#include "ns3/udp-client.h"
#include "ns3/p2ptracker-helper.h"
#include "ns3/internet-stack-helper.h"

#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

#include <stdio.h>

using namespace ns3;
using namespace UDPT;

NS_LOG_COMPONENT_DEFINE ("TcpClientServerExample");

int
main (int argc, char *argv[])
{
//
// Enable logging for UdpClient and
//
  LogComponentEnable ("UDPTracker", LOG_FUNCTION);
  LogComponentEnable ("UdpClient", LOG_FUNCTION);

  printf("test");

  NS_LOG_INFO ("Create nodes.");
  NodeContainer n;
  n.Create (2);

  InternetStackHelper internet;
  internet.Install (n);

  // link the two nodes
  Ptr<SimpleNetDevice> txDev = CreateObject<SimpleNetDevice> ();
  Ptr<SimpleNetDevice> rxDev = CreateObject<SimpleNetDevice> ();
  n.Get (0)->AddDevice (txDev);
  n.Get (1)->AddDevice (rxDev);
  Ptr<SimpleChannel> channel1 = CreateObject<SimpleChannel> ();
  rxDev->SetChannel (channel1);
  txDev->SetChannel (channel1);
  NetDeviceContainer d;
  d.Add (txDev);
  d.Add (rxDev);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i = ipv4.Assign (d);

  uint16_t port = 4000;
  UdpTrackerHelper server;
  ApplicationContainer apps = server.Install (n.Get (1));
  apps.Start (Seconds (1.0));
  apps.Stop (Seconds (10.0));

  uint32_t MaxPacketSize = 1000 - 28; // ip/udp header
  UdpClientHelper client (i.GetAddress (1), port);
  client.SetAttribute ("PacketSize", UintegerValue (MaxPacketSize));
  apps = client.Install (n.Get (0));
  apps.Start (Seconds (2.0));
  apps.Stop (Seconds (10.0));

  Simulator::Run ();
  Simulator::Destroy ();
}
