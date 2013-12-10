/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008 INRIA
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
#ifndef VIDEO_REQUEST_TAG_H
#define VIDEO_REQUEST_TAG_H

#include "ns3/object-base.h"
#include "ns3/tag-buffer.h"
#include "ns3/tag.h"
#include <stdint.h>

namespace ns3 {

#define REQ_DATA 0
#define RES_DATA_COUNT 1
#define SEND_DATA 2
#define SEND_OVER 3

/**
 * \ingroup packet
 *
 * \brief tag a set of bytes in a packet
 *
 * New kinds of tags can be created by subclassing this base class.
 */
class VideoReqTag : public Tag 
{
public:
  static TypeId GetTypeId (void);

  /**
   * \returns the number of bytes required to serialize the data of the tag.
   *
   * This method is typically invoked by Packet::AddPacketTag or Packet::AddByteTag
   * just prior to calling VideoReqTag::Serialize.
   */
  virtual uint32_t GetSerializedSize (void) const;
  /**
   * \param i the buffer to write data into.
   *
   * Write the content of the tag in the provided tag buffer.
   * DO NOT attempt to write more bytes than you requested
   * with VideoReqTag::GetSerializedSize.
   */
  virtual void Serialize (TagBuffer i) const;
  /**
   * \param i the buffer to read data from.
   *
   * Read the content of the tag from the provided tag buffer.
   * DO NOT attempt to read more bytes than you wrote with
   * VideoReqTag::Serialize.
   */
  virtual void Deserialize (TagBuffer i);

  /**
   * \param os the stream to print to
   *
   * This method is typically invoked from the Packet::PrintByteTags
   * or Packet::PrintPacketTags methods.
   */
  virtual void Print (std::ostream &os) const;

  virtual TypeId GetInstanceTypeId (void) const;

  uint8_t getTagType();
private:
  uint8_t m_simpleValue;
};

} // namespace ns3

#endif /* TAG_H */
