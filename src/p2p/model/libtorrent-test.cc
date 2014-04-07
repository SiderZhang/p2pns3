#include "libtorrent-test.h"
#include "ns3/test.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/p2ptracker-helper.h"
#include "ns3/peer-point-helper.h"
#include "ns3/point-to-point-layout-module.h"
#include "libtorrent/torrent.hpp"

#include "ns3/ipv4-global-routing-helper.h"

#include <string>
#include <iostream>

using namespace ns3;
using namespace libtorrent;

NS_LOG_COMPONENT_DEFINE ("LibTorrentTest");

void LoadTorrentTestCase1::finishAssert(ns3::Time time)
{
    NS_LOG_INFO("current time is: "<<time);
}

void LoadTorrentTestCase1::setFinishCallback(libtorrent::torrent_handle t)
{
    boost::shared_ptr<libtorrent::torrent> torrent =  t.native_handle();
    torrent->onFinished = MakeCallback(&LoadTorrentTestCase1::finishAssert, this);
    torrent->set_upload_limit(80000000);
    torrent->set_download_limit(8000000);
}

void LoadTorrentTestCase1::DoRun()
{
    LogComponentEnable("Torrent", LOG_INFO);
    LogComponentEnable("PIECE_PICKER", LOG_INFO);
    LogComponentEnable("Policy", LOG_INFO);
    LogComponentEnable("LibTorrentTest", LOG_ALL);

  InternetStackHelper internet;

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("50Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("1ms"));
  PointToPointStarHelper star(4, pointToPoint);
  star.InstallStack(internet);

  Ipv4AddressHelper ipv4;
  //star.InstallStack(ipv4);

  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  star.AssignIpv4Addresses(ipv4);
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  ApplicationContainer apps;

  //TODO: 加入种子节点
  PeerPointHelper helper(8000);
  ns3::Ipv4Address addr = star.GetSpokeIpv4Address(2);
  apps = helper.Install(star.GetSpokeNode(2), addr, false);

  ns3::Ptr<PeerPoint> pPoint = helper.lastPtr;
  pPoint->addUdpTracker(star.GetSpokeIpv4Address(0));
  pPoint->torrentPath = std::string("128mb.torrent");
  pPoint->onLoadTorrent = MakeCallback(&LoadTorrentTestCase1::setFinishCallback, this);
  apps.Start(Seconds(1.0));
  apps.Stop(Seconds(10.0));

  PeerPointHelper helper2(8000);
  addr = star.GetSpokeIpv4Address(1);
  apps = helper2.Install(star.GetSpokeNode(1), addr, true);
  apps.Start (Seconds (1.0));
  apps.Stop (Seconds (10.0));

  pPoint = helper2.lastPtr;
  pPoint->addUdpTracker(star.GetSpokeIpv4Address(0));
  pPoint->torrentPath = std::string("128mb.torrent");
  pPoint->onLoadTorrent = MakeCallback(&LoadTorrentTestCase1::setFinishCallback, this);

  UdpTrackerHelper trackerHelper(8000);
  addr = star.GetSpokeIpv4Address(0);
  apps = trackerHelper.Install(star.GetSpokeNode(0), addr);
  apps.Start (Seconds (0.0));
  apps.Stop (Seconds(30.0));

  cout<<"tracerk ip " << addr<<endl;

  Simulator::Run ();
  Simulator::Destroy ();
}
