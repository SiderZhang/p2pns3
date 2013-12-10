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
#ifndef PEER_NODE_H
#define PEER_NODE_H

#include "ns3/object.h"
#include "ns3/callback.h"
#include "ns3/ptr.h"
#include "ns3/net-device.h"
#include "ns3/applications-module.h"

namespace ns3 {

class PeerNode : public Node
{
public:
  static TypeId GetTypeId (void);

  PeerNode(int tcpDeamonPort = 4678, int udpDeamonPort = 4679);

  virtual ~PeerNode(){};

  /**
   * load the server the listening the request
   */
  void loadDeamonApp();

  /**
   * send request which want data
   */
  void requestData(Address* address);

protected:
  void sendData(Address* address, int size);

  bool StoponSend(Ptr<Packet> packet);

  bool CheckTag(Ptr<Packet> packet, Address from);
private:
  ApplicationContainer deamonApp;

  /*
   * the port deamon app listening
   */
  int tcpDeamonPort;

  int udpDeamonPort;
};
} // namespace ns3

#endif /* NODE_H */
