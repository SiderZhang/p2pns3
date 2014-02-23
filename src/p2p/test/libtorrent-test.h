#include "libtorrent/session.hpp"
#include "ns3/test.h"
#include "ns3/peerPoint.h"

#include "ns3/log.h"
#include "ns3/abort.h"
#include "ns3/config.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/simple-net-device.h"
#include "ns3/simple-channel.h"
#include "ns3/test.h"
#include "ns3/simulator.h"
#include "ns3/node-container.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/application-container.h"

namespace ns3
{
class LibtorrentTestSuite : public TestSuite
{
public:
    LibtorrentTestSuite();
};

class LoadTorrentTestCase1 : public TestCase
{
public:
    LoadTorrentTestCase1();
    virtual ~LoadTorrentTestCase1();
private:
    virtual void DoRun();
};
}

