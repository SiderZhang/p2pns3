/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2006 Georgia Tech Research Corporation, INRIA
 *
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
 *
 * Authors: George F. Riley<riley@ece.gatech.edu>
 *          Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */
#include "ns3/node.h"
#include "ns3/node-list.h"
#include "ns3/net-device.h"
#include "ns3/application.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/object-vector.h"
#include "ns3/uinteger.h"
#include "ns3/log.h"
#include "ns3/assert.h"
#include "ns3/global-value.h"
#include "ns3/boolean.h"
#include "ns3/simulator.h"

#include "ns3/video-req-tag.h"

#include "peer-node.h"

static uint32_t FileSize = 1024 * 1024;

NS_LOG_COMPONENT_DEFINE ("PeerNode");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (PeerNode);

TypeId 
PeerNode::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::PeerNode")
    .SetParent<PeerNode> ();
  return tid;
}

PeerNode::PeerNode(int tcpDeamonPort, int udpDeamonPort)
{
  NS_LOG_FUNCTION (this);
  this->tcpDeamonPort = tcpDeamonPort;
  this->udpDeamonPort = udpDeamonPort;

  loadDeamonApp();
  deamonApp.Start(Seconds(0.0));
}

void PeerNode::loadDeamonApp()
{
//
// Create one udpServer applications on node one.
//
  ObjectFactory cServerFactory;
  cServerFactory.SetTypeId(UdpServer::GetTypeId());
  cServerFactory.Set("Port", UintegerValue(udpDeamonPort));
  Ptr<UdpServer> pUdpServer = cServerFactory.Create<UdpServer>();

  pUdpServer->SetOnReceivePacket(MakeCallback(&PeerNode::CheckTag, this));
  this->AddApplication(pUdpServer);

  ObjectFactory cTcpServerFactory;
  cTcpServerFactory.SetTypeId(TcpServer::GetTypeId());
  cTcpServerFactory.Set("Port", UintegerValue(tcpDeamonPort));

  Ptr<TcpServer> pTcpServer = cTcpServerFactory.Create<TcpServer>();
  this->AddApplication(pTcpServer);

  deamonApp.Add(pUdpServer);
  deamonApp.Add(pTcpServer);
}

void PeerNode::requestData(Address* address)
{
  uint32_t MaxPacketSize = 5;
  Time interPacketInterval = Seconds (0.01);
  uint32_t maxPacketCount = 1;

  ObjectFactory cClientFactory;
  cClientFactory.SetTypeId(TcpClient::GetTypeId());
  cClientFactory.Set("RemoteAddress", AddressValue(*address));
  cClientFactory.Set("RemotePort", UintegerValue(tcpDeamonPort));
  cClientFactory.Set("MaxPackets", UintegerValue (maxPacketCount));
  cClientFactory.Set("Interval", TimeValue (interPacketInterval));
  cClientFactory.Set("PacketSize", UintegerValue (MaxPacketSize));

  Ptr<TcpClient> pClient = cClientFactory.Create<TcpClient>();

  this->AddApplication(pClient);
  pClient->setOnBuildPacket(MakeCallback(&PeerNode::StoponSend, this));

  ApplicationContainer myApps;
  myApps.Add(pClient);

  myApps.Start(Seconds(0.0));
  myApps.Stop(Seconds(1.0));
}

bool PeerNode::StoponSend(Ptr<Packet> packet)
{
   NS_LOG_INFO("send a information");
   VideoReqTag tag;
   packet->AddPacketTag(tag);

   return true;
}

bool PeerNode::CheckTag(Ptr<Packet> packet, Address from)
{
    bool result;
    VideoReqTag tag;
    result = packet->PeekPacketTag(tag);

    if (result)
    {
        NS_LOG_INFO("receive req tag");
        sendData(&from, FileSize);
    }
    return result;
}

void PeerNode::sendData(Address* address, int size)
{
  uint32_t MaxPacketSize = 1024;
  Time interPacketInterval = Seconds (0.0001);

  uint32_t maxPacketCount = size / MaxPacketSize;
  if (size % MaxPacketSize != 0)
  {
      maxPacketCount++;
  }

  ObjectFactory cClientFactory;
  cClientFactory.SetTypeId(TcpClient::GetTypeId());
  cClientFactory.Set("RemoteAddress", AddressValue(*address));
  cClientFactory.Set("RemotePort", UintegerValue(udpDeamonPort));
  cClientFactory.Set("MaxPackets", UintegerValue (maxPacketCount));
  cClientFactory.Set("Interval", TimeValue (interPacketInterval));
  cClientFactory.Set("PacketSize", UintegerValue (MaxPacketSize));
  
  Ptr<TcpClient> client = cClientFactory.Create<TcpClient>();
  this->AddApplication(client);

  ApplicationContainer myApp;
  myApp.Add(client);

  myApp.Start(Seconds(0.0));
  myApp.Stop(Seconds(maxPacketCount * 0.0001 + 1));
}

}
