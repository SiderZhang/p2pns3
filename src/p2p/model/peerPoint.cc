#include "peerPoint.h"
#include "ns3/libtorrent/torrent_handle.hpp"
#include "libtorrent/add_torrent_params.hpp"
#include "libtorrent/torrent_info.hpp"
#include "libtorrent/error_code.hpp"

#include "ns3/uinteger.h"
#include <string>
#include <sstream>

#include "ns3/log.h"

using namespace std;
using namespace ns3;
using namespace libtorrent;
using namespace libtorrent::aux;

namespace ns3
{
NS_LOG_COMPONENT_DEFINE ("PeerPoint");
NS_OBJECT_ENSURE_REGISTERED (PeerPoint);

TypeId PeerPoint::GetTypeId()
{
    static TypeId tid = TypeId("ns3::PeerPoint")
        .SetParent<Application>()
        .AddConstructor<PeerPoint>()
        .AddAttribute("MaxPackets",
                "The maximum number of packets the application will send",
                UintegerValue(99999),
                MakeUintegerAccessor (&PeerPoint::m_count),
                MakeUintegerChecker<uint32_t>())
        .AddAttribute("RemoteAddress",
                "The destination Address of the outbound packets",
                AddressValue(),
                MakeAddressAccessor (&PeerPoint::m_peerAddress),
                MakeAddressChecker())
        .AddAttribute("RemotePort", "the destination port of the outbound packets",
                UintegerValue (8000),
                MakeUintegerAccessor(&PeerPoint::m_peerPort),
                MakeUintegerChecker<uint16_t>())
        .AddAttribute("PacketSize",
                "Size of packets generated. The minimum packet size is 12 bytes which is the size of the header carrying the sequence numner and the time stamp",
                UintegerValue (1024),
                MakeUintegerAccessor (&PeerPoint::size),
                MakeUintegerChecker<uint32_t>(12, 1500));
    return tid;
}

PeerPoint::PeerPoint()
{
  NS_LOG_FUNCTION (this);
    ses = NULL;
}

PeerPoint::~PeerPoint()
{
  NS_LOG_FUNCTION (this);
}

void PeerPoint::start()
{
  NS_LOG_FUNCTION (this);
  StartApplication();
}

void PeerPoint::DoDispose()
{
  NS_LOG_FUNCTION (this);
  Application::DoDispose ();
}

void PeerPoint::StartApplication()
{
  NS_LOG_FUNCTION (this);
    if (ip == ns3::Ipv4Address())
    {
        NS_LOG_ERROR("ip is not initialed!");
        return;
    }
    ses = new session(MakeCallback(&PeerPoint::loadTorrent, this),GetNode(), ip);
}

void PeerPoint::setAddress(ns3::Ipv4Address addr)
{
    ip = addr;
}

void PeerPoint::loadTorrent(session* sess)
{
    NS_LOG_FUNCTION (this);
    add_torrent_params param;
    std::string path;
    param.save_path = path;
    path.append("./");

    try
    {
        torrent_info* info;
        if (torrentPath.empty())
        {
            info = new torrent_info("./testTor.torrent");
        }
        else
        {
            info = new torrent_info(torrentPath.c_str());
        }

        for (uint i = 0;i < dTrackers.size();++i)
        {
            info->clear_trackers();
            info->add_tracker(dTrackers[i]);
        }

        info->peer_log();

        boost::intrusive_ptr<torrent_info> pTor(info);
        param.ti = pTor;
    }
    catch(libtorrent_exception e)
    {
        NS_LOG_ERROR("failed to load torrent file!");
    }

    if (this->initSeed)
    {
        param.init_Seed = true;
    }
    else
    {
        param.init_Seed =false;
    }

    torrent_handle handle = sess->add_torrent(param);
    if (!onLoadTorrent.IsNull())
    {
        onLoadTorrent(handle);
    }
}

void PeerPoint::StopApplication()
{
  NS_LOG_FUNCTION (this);
  ses->setAborted(true);
}

void PeerPoint::addUdpTracker(Ipv4Address ip)
{
    stringstream str;
    str<<"udp://"<<ip<<":8000/announce";
    NS_LOG_INFO(str.str());
    dTrackers.push_back(str.str());
}

}
