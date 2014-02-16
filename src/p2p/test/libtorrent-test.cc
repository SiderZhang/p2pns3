#include "libtorrent/session.h"
#include "ns3/test.h"

using namespace ns3;

class LoadTorrentTestCase1 : public TestCase
{
public:
    LoadTorrentTestCase1();
    virtual ~LoadTorrentTestCase1();
private:
    virtual void DoRun();
}

void LoadTorrentTestCase1::DoRun()
{
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
  Ptr<PeerPoint> ptrPeerPoint = factory.Create<PeerPoint>();
  ApplicationContainer apps;
  n.Get(1).Begin()->AddApplication(ptrPeerPoint);
  apps.Add(apps);

  uint16_t port = 4000;
  apps.Start (Seconds (1.0));
  apps.Stop (Seconds (10.0));

  Simulator::Run ();
  Simulator::Destroy ();
}
