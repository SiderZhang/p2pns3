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
#include "ns3/peerPoint.h"
#include "peer-point-helper.h"
#include "ns3/uinteger.h"
#include "ns3/names.h"

#include "ns3/log.h"
#include <iostream>

using namespace std;

namespace ns3 {
NS_LOG_COMPONENT_DEFINE ("PeerPointHelper");

PeerPointHelper::PeerPointHelper ()
{
    NS_LOG_FUNCTION (this);
  m_factory.SetTypeId (PeerPoint::GetTypeId ());
}

ApplicationContainer
PeerPointHelper::Install (Ptr<Node> node) const
{
    NS_LOG_FUNCTION (this);
  return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
PeerPointHelper::Install (std::string nodeName) const
{
    NS_LOG_FUNCTION (this);
  Ptr<Node> node = Names::Find<Node> (nodeName);
  return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
PeerPointHelper::Install (NodeContainer c) const
{
    NS_LOG_FUNCTION (this);

  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      apps.Add (InstallPriv (*i));
    }

  return apps;
}

Ptr<Application>
PeerPointHelper::InstallPriv (Ptr<Node> node) const
{
    NS_LOG_FUNCTION (this);
  Ptr<Application> app = m_factory.Create<PeerPoint> ();
    NS_LOG_INFO("wewe");
  node->AddApplication (app);

  return app;
}
} // namespace ns3
