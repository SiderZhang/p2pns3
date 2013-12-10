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

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"

#include "ns3/video-req-tag.h"

#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("UdpClientServerExample");

bool StoponSend(Ptr<Packet> packet)
{
   NS_LOG_INFO("send a information");
   VideoReqTag tag;
   packet->AddPacketTag(tag);
   return true;
}

void SendRequest(Ptr<Node> node, Address* address, uint16_t port)
{
  uint32_t MaxPacketSize = 1024;
  Time interPacketInterval = Seconds (2.0001);
  uint32_t maxPacketCount = 1;

  ObjectFactory cClientFactory;
  cClientFactory.SetTypeId(UdpClient::GetTypeId());
  cClientFactory.Set("RemoteAddress", AddressValue(*address));
  cClientFactory.Set("RemotePort", UintegerValue(port));
  cClientFactory.Set("MaxPackets", UintegerValue (maxPacketCount));
  cClientFactory.Set("Interval", TimeValue (interPacketInterval));
  cClientFactory.Set("PacketSize", UintegerValue (MaxPacketSize));

  Ptr<UdpClient> pClient = cClientFactory.Create<UdpClient>();

  node->AddApplication(pClient);
  pClient->setOnBuildPacket(MakeCallback(StoponSend));

  ApplicationContainer myApps;
  myApps.Add(pClient);

  myApps.Start(Seconds(0.0));
  myApps.Stop(Seconds(1.0));
}

bool CheckTag(Ptr<Packet> packet)
{
    bool result;
    VideoReqTag tag;
    result = packet->PeekPacketTag(tag);

    if (result)
    {
        NS_LOG_INFO("receive req tag");
    }
    return result;
}

int
main (int argc, char *argv[])
{
//
// Enable logging for UdpClient and
//
  LogComponentEnable ("UdpClient", LOG_LEVEL_INFO);
  LogComponentEnable ("UdpServer", LOG_LEVEL_INFO);

  bool useV6 = false;
  Address serverAddress;

  CommandLine cmd;
  cmd.AddValue ("useIpv6", "Use Ipv6", useV6);
  cmd.Parse (argc, argv);

//
// Explicitly create the nodes required by the topology (shown above).
//
  NS_LOG_INFO ("Create nodes.");
  NodeContainer n;
  n.Create (2);

  InternetStackHelper internet;
  internet.Install (n);

  NS_LOG_INFO ("Create channels.");
//
// Explicitly create the channels required by the topology (shown above).
//
    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("1000Mbps"));
    pointToPoint.SetChannelAttribute("Delay", StringValue("0ms"));
    pointToPoint.SetDeviceAttribute ("Mtu", UintegerValue (14000));

    NetDeviceContainer d= pointToPoint.Install(n);
    
//
// We've got the "hardware" in place.  Now we need to add IP addresses.
//
  NS_LOG_INFO ("Assign IP Addresses.");
  if (useV6 == false)
    {
      Ipv4AddressHelper ipv4;
      ipv4.SetBase ("10.1.1.0", "255.255.255.0");
      Ipv4InterfaceContainer i = ipv4.Assign (d);
      serverAddress = Address (i.GetAddress (1));
    }
  else
    {
      Ipv6AddressHelper ipv6;
      ipv6.SetBase ("2001:0000:f00d:cafe::", Ipv6Prefix (64));
      Ipv6InterfaceContainer i6 = ipv6.Assign (d);
      serverAddress = Address(i6.GetAddress (1,1));
    }

  NS_LOG_INFO ("Create Applications.");
//
// Create one udpServer applications on node one.
//
  uint16_t port = 4000;
  ObjectFactory cServerFactory;
  cServerFactory.SetTypeId(UdpServer::GetTypeId());
  cServerFactory.Set("Port", UintegerValue(port));
  Ptr<UdpServer> pServer = cServerFactory.Create<UdpServer>();

  pServer->SetOnReceivePacket(MakeCallback(CheckTag));

  ApplicationContainer myApps;
  n.Get(1)->AddApplication(pServer);
  myApps.Add(pServer);

  myApps.Start(Seconds(0.0));
  myApps.Stop(Seconds(10.0));

//
// Create one UdpClient application to send UDP datagrams from node zero to
// node one.
//

  SendRequest(n.Get(0) , &serverAddress, port);

//
// Now, do the actual simulation.
//
  LogComponentEnable("UdpClientServerExample", LOG_LEVEL_INFO);
  NS_LOG_INFO ("Run Simulation.");
  
  Simulator::Run ();
  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");
}
