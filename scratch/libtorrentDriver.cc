#include "ns3/log.h"
#include "ns3/udp-echo-helper.h"
#include "ns3/abort.h"
#include "ns3/config.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/inet-socket-address.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/inet-socket-address.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/simple-net-device.h"
#include "ns3/simple-channel.h"
#include "ns3/test.h"
#include "ns3/simulator.h"
#include "ns3/application-container.h"

#include "ns3/peerPoint.h"
#include "ns3/peer-point-helper.h"
#include "ns3/p2ptracker-helper.h"
#include "ns3/point-to-point-module.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"

#include "ns3/libtorrent-test.h"

#include <iostream>
#include <unistd.h>

using namespace std;
using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("LibtorrentTest");

void ConnectionTest(Ipv4Address serverIp, Ptr<Node> client, Ptr<Node> server);

void TcpConnectionTest(Ipv4Address serverIp, Ptr<Node> client, Ptr<Node> server);

void runTestCase1();

void runTestBandwidthCase();

void setLog()
{
//    LogComponentEnable("PeerPoint", LOG_ALL);
//    LogComponentEnable("LibtorrentTest", LOG_INFO);
//    LogComponentEnable("PeerPointHelper", LOG_INFO);
//    LogComponentEnable("PeerPointHelper", LOG_FUNCTION);
    //LogComponentEnable("Session", LOG_FUNCTION);
    //LogComponentEnable("Session_Impl", LOG_ALL);
//    LogComponentEnable("DefaultSimulatorImpl", LOG_INFO);
//    LogComponentEnable("Adapter", LOG_ALL);
//    LogComponentEnable("TrackerManager", LOG_FUNCTION);
//    LogComponentEnable("UdpTrackerConnection", LOG_ALL);
//    LogComponentEnable("UDPTracker", LOG_ALL);
//    LogComponentEnable("Torrent", LOG_INFO);
//    LogComponentEnable("PIECE_PICKER", LOG_INFO);
//    LogComponentEnable("Policy", LOG_INFO);
//    LogComponentEnable("BT_PEER_CONNECTION", LOG_INFO);
//    LogComponentEnable("Peer_Connection", LOG_INFO);
//
//   LogComponentEnable("Torrent", LOG_FUNCTION);
//   LogComponentEnable("PIECE_PICKER", LOG_FUNCTION);
//   LogComponentEnable("Policy", LOG_FUNCTION);
//   LogComponentEnable("BT_PEER_CONNECTION", LOG_FUNCTION);
//   LogComponentEnable("Peer_Connection", LOG_FUNCTION);
//
//   LogComponentEnable("Torrent", LOG_ALL);
//   LogComponentEnable("PIECE_PICKER", LOG_ALL);
//   LogComponentEnable("Policy", LOG_ALL);
//   LogComponentEnable("BT_PEER_CONNECTION", LOG_ALL);
//   LogComponentEnable("Peer_Connection", LOG_ALL);
//    LogComponentEnable("Bandwidth_Manager", LOG_ALL);
//    LogComponentEnable("PIECE_PICKER", LOG_ALL);
//    LogComponentEnable("PeerPoint", LOG_FUNCTION);
    
//    LogComponentEnable("TcpL4Protocol", LOG_LEVEL_ALL);
//    LogComponentEnable("TcpSocketBase", LOG_ALL);
  //  LogComponentEnable("TcpSocketImpl", LOG_LEVEL_ALL);
}

int main(int argc, char* arg[])
{
    setLog();
  //  runTestCase1();
    runTestBandwidthCase();
}

void runTestCase1()
{
  NodeContainer c;
  c.Create (5);
  NodeContainer n0n1 = NodeContainer (c.Get (0), c.Get (1));
  NodeContainer n0n2 = NodeContainer (c.Get (0), c.Get (2));
  NodeContainer n0n3 = NodeContainer (c.Get (0), c.Get (3));
  NodeContainer n0n4 = NodeContainer (c.Get (0), c.Get (4));

  InternetStackHelper internet;
  internet.Install (c);

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("50Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NetDeviceContainer d0d1 = pointToPoint.Install (n0n1);
  NetDeviceContainer d0d2 = pointToPoint.Install (n0n2);
  NetDeviceContainer d0d3 = pointToPoint.Install (n0n3);
  NetDeviceContainer d0d4 = pointToPoint.Install (n0n4);

  NS_LOG_INFO ("Assign IP Addresses.");
  Ipv4AddressHelper ipv4;

  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i0i1 = ipv4.Assign (d0d1);

  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer i0i2 = ipv4.Assign (d0d2);

  ipv4.SetBase ("10.1.3.0", "255.255.255.0");
  Ipv4InterfaceContainer i0i3 = ipv4.Assign (d0d3);

  ipv4.SetBase ("10.1.4.0", "255.255.255.0");
  Ipv4InterfaceContainer i0i4 = ipv4.Assign (d0d4);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  ApplicationContainer apps;

//  ConnectionTest(i0i1.GetAddress(1), c.Get(2), c.Get(1));
//  TcpConnectionTest(i0i1.GetAddress(1), c.Get(2), c.Get(1));

  //PeerPointHelper helper(i0i3.GetAddress(0), 8000);
  PeerPointHelper helper(8000);
  ns3::Ipv4Address addr = i0i3.GetAddress(1);
  apps = helper.Install(c.Get(3), addr, false);
  apps.Start (Seconds (3.0));
  apps.Stop (Seconds (40.0));

  addr = i0i2.GetAddress(1);
  //PeerPointHelper helper2(i0i2.GetAddress(0), 8000);
  PeerPointHelper helper2(8000);
  apps = helper2.Install(c.Get(2), addr, true);
  apps.Start (Seconds (1.0));
  apps.Stop (Seconds (40.0));

  addr = i0i4.GetAddress(1);
  //PeerPointHelper helper3(i0i4.GetAddress(0), 8000);
  PeerPointHelper helper3(8000);
  apps = helper2.Install(c.Get(4), addr, false);
  apps.Start (Seconds (6.0));
  apps.Stop (Seconds (40.0));

  UdpTrackerHelper trackerHelper(8000);
  apps = trackerHelper.Install(c.Get(1), i0i1.GetAddress(1));
  apps.Start (Seconds (0.0));
  apps.Stop (Seconds(100000.0));

  Simulator::Run ();
  Simulator::Destroy ();
  //NS_TEST_ASSERT_MSG_EQ (ptrPeerPoint->isTorrentLoaded(), true, "failed to load the torrent file");
}

void ConnectionTest(Ipv4Address serverIp, Ptr<Node> client, Ptr<Node> server)
{
  LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_INFO);
  LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_INFO);
  UdpServerHelper echoServer (8000);
  ApplicationContainer serverApps = echoServer.Install (server);
  serverApps.Start (Seconds (1.0));
  serverApps.Stop (Seconds (10.0));

  UdpClientHelper echoClient (serverIp, 8000);
  echoClient.SetAttribute ("MaxPackets", UintegerValue (1));
  echoClient.SetAttribute ("Interval", TimeValue (Seconds (1.0)));
  echoClient.SetAttribute ("PacketSize", UintegerValue (1024));
  ApplicationContainer clientApps = echoClient.Install(client);
  clientApps.Start(Seconds(2.0));
  clientApps.Stop(Seconds(10.0));
}

void TcpConnectionTest(Ipv4Address serverIp, Ptr<Node> client, Ptr<Node> server)
{
   LogComponentEnable("PacketSink", LOG_ALL);
   LogComponentEnable("OnOffApplication", LOG_ALL);
  uint16_t port = 50000;
  Address hubLocalAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
  PacketSinkHelper packetSinkHelper ("ns3::TcpSocketFactory",
                         InetSocketAddress (Ipv4Address::GetAny (), port));
  ApplicationContainer hubApp = packetSinkHelper.Install (server);
  hubApp.Start (Seconds (1.0));
  hubApp.Stop (Seconds (10.0));

  OnOffHelper onOffHelper ("ns3::TcpSocketFactory", Address ());
  onOffHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
  AddressValue remoteAddress (InetSocketAddress (serverIp, port));
  onOffHelper.SetAttribute ("Remote", remoteAddress);
  ApplicationContainer spokeApps;
  spokeApps.Add (onOffHelper.Install (client));
  spokeApps.Start (Seconds (1.0));
  spokeApps.Stop (Seconds (10.0));
}

void runTestBandwidthCase()
{
    LoadTorrentTestCase1 case1;
    case1.DoRun();
}
