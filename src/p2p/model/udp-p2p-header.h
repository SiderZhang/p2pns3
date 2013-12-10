/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 INRIA
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
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#ifndef UDP_P2P_HEADER_H 
#define UDP_P2P_HEADER_H

#include "ns3/header.h"
#include "ns3/nstime.h"
#include "tracker_req.hpp"
#include "action.h"

#include <list>

namespace ns3 {
/**
 * The header is made of a 32bits sequence number followed by
 * a 64bits time stamp.
 */
class UdpP2PHeader : public Header
{
public:

  UdpP2PHeader();

  void setAction(int32_t action);

  int32_t getAction() const;

  void setTransactionId(int32_t transactionId);

  int32_t getTransactionId() const;

  void setTrackerReq(const libtorrent::tracker_request req);

  void setAnnounceIp(uint32_t ip);

  uint64_t getConnectionID_64();

  uint32_t getInterval();

  uint32_t getLeechers();

  uint32_t getSeeders();

  uint32_t getIpAddress();

  uint16_t getTcpPort();

  std::list<uint32_t>& getSeedersList()
  {
      return this->seedersList;
  }

  std::list<uint32_t>& getCompletedList()
  {
      return this->completedList;
  }

  std::list<uint32_t>& getLeechersList()
  {
      return this->leechersList;
  }

  std::list<uint16_t>& getTcpPortList()
  {
      return this->tcpPortList;
  }

  std::list<uint8_t*>& getinfo_hashList()
  {
      return this->info_hashList;
  }

  void setIsResponse(bool isResponse);

  static TypeId GetTypeId (void);
private:
  virtual TypeId GetInstanceTypeId (void) const;
  virtual void Print (std::ostream &os) const;
  virtual uint32_t GetSerializedSize (void) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);


  void clearList();

  uint64_t connection_id_64;
  uint32_t action;
  uint32_t transaction_id;

  uint8_t info_hash[20];
  uint8_t peer_id[20];
  uint64_t left;
  uint64_t uploaded;
  uint32_t event;
  uint32_t ipAddress;
  uint32_t key;
  uint32_t num_want;
  uint16_t port;

  uint32_t announce_ip_v4;

  uint32_t interval;
  uint32_t leechers;
  uint32_t seeders;
  uint16_t tcpPort;

  std::list<uint32_t> seedersList;
  std::list<uint32_t> completedList;
  std::list<uint32_t> leechersList;
  std::list<uint32_t> ipAddressList;
  std::list<uint16_t> tcpPortList;
  std::list<uint8_t*> info_hashList;

  libtorrent::tracker_request req;
  bool isResponse;
};

} // namespace ns3

#endif /* SEQ_TS_HEADER_H */
