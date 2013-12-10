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
 * Author: Mohamed Amine Ismail <amine.ismail@sophia.inria.fr>
 */
#include "tcp-client-server-helper.h"
#include "ns3/tcp-server.h"
#include "ns3/tcp-client.h"
#include "ns3/tcp-trace-client.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"

namespace ns3 {

TcpServerHelper::TcpServerHelper ()
{
}

TcpServerHelper::TcpServerHelper (uint16_t port)
{
  m_factory.SetTypeId (TcpServer::GetTypeId ());
  SetAttribute ("Port", UintegerValue (port));
}

void
TcpServerHelper::SetAttribute (std::string name, const AttributeValue &value)
{
  m_factory.Set (name, value);
}

ApplicationContainer
TcpServerHelper::Install (NodeContainer c)
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      Ptr<Node> node = *i;

      m_server = m_factory.Create<TcpServer> ();
      node->AddApplication (m_server);
      apps.Add (m_server);

    }
  return apps;
}

Ptr<TcpServer>
TcpServerHelper::GetServer (void)
{
  return m_server;
}

TcpClientHelper::TcpClientHelper ()
{
}

TcpClientHelper::TcpClientHelper (Address address, uint16_t port)
{
  m_factory.SetTypeId (TcpClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (address));
  SetAttribute ("RemotePort", UintegerValue (port));
}

TcpClientHelper::TcpClientHelper (Ipv4Address address, uint16_t port)
{
  m_factory.SetTypeId (TcpClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (Address(address)));
  SetAttribute ("RemotePort", UintegerValue (port));
}

TcpClientHelper::TcpClientHelper (Ipv6Address address, uint16_t port)
{
  m_factory.SetTypeId (TcpClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (Address(address)));
  SetAttribute ("RemotePort", UintegerValue (port));
}

void
TcpClientHelper::SetAttribute (std::string name, const AttributeValue &value)
{
  m_factory.Set (name, value);
}

ApplicationContainer
TcpClientHelper::Install (NodeContainer c)
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      Ptr<Node> node = *i;
      Ptr<TcpClient> client = m_factory.Create<TcpClient> ();
      node->AddApplication (client);
      apps.Add (client);
    }
  return apps;
}

TcpTraceClientHelper::TcpTraceClientHelper ()
{
}

TcpTraceClientHelper::TcpTraceClientHelper (Address address, uint16_t port, std::string filename)
{
  m_factory.SetTypeId (TcpTraceClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (address));
  SetAttribute ("RemotePort", UintegerValue (port));
  SetAttribute ("TraceFilename", StringValue (filename));
}

TcpTraceClientHelper::TcpTraceClientHelper (Ipv4Address address, uint16_t port, std::string filename)
{
  m_factory.SetTypeId (TcpTraceClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (Address (address)));
  SetAttribute ("RemotePort", UintegerValue (port));
  SetAttribute ("TraceFilename", StringValue (filename));
}

TcpTraceClientHelper::TcpTraceClientHelper (Ipv6Address address, uint16_t port, std::string filename)
{
  m_factory.SetTypeId (TcpTraceClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (Address (address)));
  SetAttribute ("RemotePort", UintegerValue (port));
  SetAttribute ("TraceFilename", StringValue (filename));
}

void
TcpTraceClientHelper::SetAttribute (std::string name, const AttributeValue &value)
{
  m_factory.Set (name, value);
}

ApplicationContainer
TcpTraceClientHelper::Install (NodeContainer c)
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      Ptr<Node> node = *i;
      Ptr<TcpTraceClient> client = m_factory.Create<TcpTraceClient> ();
      node->AddApplication (client);
      apps.Add (client);
    }
  return apps;
}

} // namespace ns3
