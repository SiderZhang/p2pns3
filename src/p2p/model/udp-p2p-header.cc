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

#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/header.h"
#include "ns3/simulator.h"
#include "udp-p2p-header.h"
#include "tracker_req.hpp"

#include <assert.h>

NS_LOG_COMPONENT_DEFINE ("UdpP2PHeader");

namespace ns3 {
    
    using namespace libtorrent;
    using namespace std;

NS_OBJECT_ENSURE_REGISTERED (UdpP2PHeader);

UdpP2PHeader::UdpP2PHeader ()
    :connection_id_64(0x27101980)
{
  NS_LOG_FUNCTION (this);
}

void
UdpP2PHeader::setAction (int32_t action)
{
  NS_LOG_FUNCTION (this << action);
  this->action = action;
}

void
UdpP2PHeader::setTrackerReq(const libtorrent::tracker_request request)
{
    this->req = request;
}

int32_t
UdpP2PHeader::getAction (void) const
{
  NS_LOG_FUNCTION (this);
  return this->action;
}

int32_t
UdpP2PHeader::getTransactionId (void) const
{
  NS_LOG_FUNCTION (this);
  return transaction_id;
}

void
UdpP2PHeader::setTransactionId (int32_t transactionId)
{
  NS_LOG_FUNCTION (this << transactionId);
  this->transaction_id = transactionId;
}

uint64_t
UdpP2PHeader::getConnectionID_64 ()
{
  NS_LOG_FUNCTION (this << connection_id_64);
  return connection_id_64;
}

void 
UdpP2PHeader::setAnnounceIp(uint32_t ip)
{
  NS_LOG_FUNCTION (this << ip);
  this->announce_ip_v4 = ip;
}

void UdpP2PHeader::setIsResponse(bool isResponse)
{
  this->isResponse = isResponse;
}

TypeId
UdpP2PHeader::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::UdpP2PHeader")
    .SetParent<Header> ()
    .AddConstructor<UdpP2PHeader> ()
  ;
  return tid;
}
TypeId
UdpP2PHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
UdpP2PHeader::Print (std::ostream &os) const
{
  NS_LOG_FUNCTION (this << &os);
  os << "(connection_id=" << connection_id_64 << 
      " action connect = " << action << " transaction id=" << transaction_id << ")";
}
uint32_t
UdpP2PHeader::GetSerializedSize (void) const
{
  NS_LOG_FUNCTION (this);
  return sizeof(uint32_t) * 2 + sizeof(int32_t) * 2;
}

void UdpP2PHeader::clearList()
{
    seedersList.clear();
    completedList.clear();
    leechersList.clear();
    ipAddressList.clear();
    tcpPortList.clear();

    list<uint8_t*>::iterator iter = info_hashList.begin();
    while (iter != info_hashList.end())
    {
        delete *iter;
    }

    info_hashList.clear();
}

void
UdpP2PHeader::Serialize (Buffer::Iterator start) const
{
  NS_LOG_FUNCTION (this << &start);
  Buffer::Iterator i = start;

  if (this->isResponse)
  {
      switch (action)
      {
          case action_connect:
              {
              i.WriteHtonU32(action);
              i.WriteHtonU32(transaction_id);
              i.WriteHtonU32(connection_id_64);
              break;
              }
          case action_scrape:
              {
              i.WriteHtonU32(action);
              i.WriteHtonU32(transaction_id);

              list<uint32_t>::const_iterator seedersIter = seedersList.begin();
              list<uint32_t>::const_iterator completedIter = completedList.begin();
              list<uint32_t>::const_iterator leechersIter = leechersList.begin();
              for (uint index = 0;index < seedersList.size();++index)
              {
                  i.WriteHtonU32(*seedersIter);
                  i.WriteHtonU32(*completedIter);
                  i.WriteHtonU32(*leechersIter);
                  
                  ++seedersIter;
                  completedIter++;
                  leechersIter++;
              }

              break;
              }
          case action_announce:
              {
              i.WriteHtonU32(action);
              i.WriteHtonU32(transaction_id);
              i.WriteHtonU32(interval);
              i.WriteHtonU32(leechers);
              i.WriteHtonU32(seeders);

              list<uint32_t>::const_iterator ipIter = ipAddressList.begin();
              list<uint16_t>::const_iterator tcpPortIter = tcpPortList.begin();
              for (uint index = 0;index < ipAddressList.size();++index)
              {
                i.WriteHtonU32(*ipIter);
                i.WriteHtonU16(*tcpPortIter);

                ipIter++;
                tcpPortIter++;
              }

              break;
              }
          default:
              {
              NS_LOG_ERROR("Unknown packet type.");
              }
      }
  }
  else
  {
    switch (action)
    {
    case action_connect:
      {
        i.WriteHtonU64 (connection_id_64);
        i.WriteHtonU32 (action);
        i.WriteHtonU32 (transaction_id);
        break;
      }
    case action_scrape:
      {
        i.WriteHtonU64 (connection_id_64);
        i.WriteHtonU32 (action);
        i.WriteHtonU32 (transaction_id);
        i.Write (req.info_hash.begin(), 20);
        break;
      }
    case action_announce:
      {
        i.WriteHtonU64 (connection_id_64);
        i.WriteHtonU32 (action);
        i.WriteHtonU32 (transaction_id);
        
        i.Write (req.info_hash.begin(), 20);
        i.Write (req.pid.begin(), 20);
        bool stats = req.send_stats;
        i.WriteHtonU64 (stats ? req.downloaded : 0);
        
		i.WriteHtonU64 (stats ? req.left : 0 ); // left
		i.WriteHtonU64 (stats ? req.uploaded : 0 ); // uploaded
		i.WriteHtonU64 (req.event ); // event
        i.WriteHtonU32 (announce_ip_v4);
        i.WriteHtonU32 (req.key);
        i.WriteHtonU32 (req.num_want);
        i.WriteHtonU16 (req.listen_port);
        i.WriteHtonU16 (0);

        break;
      }
    case action_error:
      break;
    default:
      NS_LOG_ERROR("Unknown packet type.");
    }
  }
}
uint32_t
UdpP2PHeader::Deserialize (Buffer::Iterator start)
{
  NS_LOG_FUNCTION (this << &start);
  Buffer::Iterator i = start;

  if (!this->isResponse)
  {
      this->connection_id_64 = i.ReadNtohU64();
      this->action = i.ReadNtohU32();

      switch (action)
      {
          case action_connect:
              this->transaction_id = i.ReadNtohU32();
              break;
          case action_scrape:
          {
              int count = i.GetSize() - 16;

              if (count % 20 != 0)
              {
                NS_LOG_ERROR("scrape request packet error.");
              }

              count = count / 20;
              clearList();

              for (int index = 0;index < count;++index)
              {
                  uint8_t* buffer = new uint8_t[20];
                  memset(buffer, 0, 20);
                  i.Read(buffer, 20);
                  info_hashList.push_back(buffer);
              }

              break;
          }
          case action_announce:
          {
              this->transaction_id = i.ReadNtohU32 ();
              memset(this->info_hash, 0, 20);
              i.Read(this->info_hash, 20);
              memset(this->peer_id, 0, 20);
              i.Read(this->peer_id, 20);
              this->left = i.ReadNtohU64();
              this->uploaded = i.ReadNtohU64();
              this->event = i.ReadNtohU32();
              this->ipAddress = i.ReadNtohU32();
              this->key = i.ReadNtohU32();
              this->num_want = i.ReadNtohU32();
              this->port = i.ReadNtohU16();

              break;
          }
          default:
              NS_LOG_ERROR("Unknown packet type.");
      }
  }
  else
  {
    action = i.ReadNtohU32();
    transaction_id = i.ReadNtohU32();
    switch (action)
    {
    case action_connect:
        this->connection_id_64 = i.ReadNtohU64();
        break;
    case action_scrape:
        {
        int count = start.GetSize();
        count -= 8;
        if (count % 12 != 0)
        {
            NS_LOG_ERROR("scrape response packet error.");
        }
        count = count / 12;

        seedersList.clear();
        completedList.clear();
        leechersList.clear();
        
        for (int index = 0;index < count;++index)
        {
            seedersList.push_back(i.ReadNtohU32());
            completedList.push_back(i.ReadNtohU32());
            leechersList.push_back(i.ReadNtohU32());
        }
        break;
        }
    case action_announce:
        {
        this->interval = i.ReadNtohU32();
        this->leechers = i.ReadNtohU32();
        this->seeders = i.ReadNtohU32();
        
        this->ipAddressList.clear();
        this->tcpPortList.clear();

        int count = start.GetSize();
        count -= 8;
        if (count % 12 != 0)
        {
            NS_LOG_ERROR("announce response packet error.");
        }
        count = count / 12;

        for (int index = 0;index < count;++index)
        {
            ipAddressList.push_back(i.ReadNtohU32());
            tcpPortList.push_back(i.ReadNtohU16());
        }

        break;
        }
    default:
        NS_LOG_ERROR("Unknown packet type.");
    }

  }

  return GetSerializedSize ();
}

} // namespace ns3
