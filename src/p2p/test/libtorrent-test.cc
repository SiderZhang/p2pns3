#include "libtorrent-test.h"
#include "ns3/test.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("LibTorrentTest");
static LibtorrentTestSuite libtorrentTestSuite;

LibtorrentTestSuite::LibtorrentTestSuite()
        :TestSuite("lib-torrent", UNIT)
{
    AddTestCase(new LoadTorrentTestCase1(), TestCase::QUICK);
}

LoadTorrentTestCase1::LoadTorrentTestCase1()
    :TestCase ("test libtorrent")
{
}

LoadTorrentTestCase1::~LoadTorrentTestCase1()
{
}

void LoadTorrentTestCase1::DoRun()
{
    LogComponentEnable("PeerPoint", LOG_ALL);
  NodeContainer n;
  n.Create (2);

  InternetStackHelper internet;
  internet.Install (n);

  // link the two nodes
  Ptr<SimpleNetDevice> txDev = CreateObject<SimpleNetDevice> ();
  Ptr<SimpleNetDevice> rxDev = CreateObject<SimpleNetDevice> ();
  n.Get (0)->AddDevice (txDev);
  n.Get (1)->AddDevice (rxDev);
  Ptr<SimpleChannel> channel1 = CreateObject<SimpleChannel> ();
  rxDev->SetChannel (channel1);
  txDev->SetChannel (channel1);
  NetDeviceContainer d;
  d.Add (txDev);
  d.Add (rxDev);

  Ipv4AddressHelper ipv4;

  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i = ipv4.Assign (d);

  ObjectFactory factory;

  factory.SetTypeId(PeerPoint::GetTypeId());
  ApplicationContainer apps;

    Ptr<PeerPoint> ptrPeerPoint = factory.Create<PeerPoint>();
  for (NodeContainer::Iterator i = n.Begin (); i != n.End (); ++i)
  {
    (*i)->AddApplication(ptrPeerPoint);
    apps.Add(ptrPeerPoint);
    break;
  }

  apps.Start (Seconds (1.0));
  apps.Stop (Seconds (10.0));

  Simulator::Run ();
  Simulator::Destroy ();

  NS_TEST_ASSERT_MSG_EQ (ptrPeerPoint->isTorrentLoaded(), true, "failed to load the torrent file");
}
