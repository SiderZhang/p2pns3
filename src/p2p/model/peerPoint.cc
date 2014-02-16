#include "peerPoint.h"
#include "libtorrent/torrent_handle.hpp"
#include "libtorrent/add_torrent_params.hpp"
#include "libtorrent/torrent_info.hpp"
#include <string>

#include "ns3/log.h"

using namespace ns3;
using namespace libtorrent;

NS_LOG_COMPONENT_DEFINE ("PeerPoint");
NS_OBJECT_ENSURE_REGISTERED (PeerPoint);

TypeId PeerPoint::GetTypeId()
{
    static TypeId tid = TypeId("ns3::PeerPoint")
        .SetParent<Application>();
    return tid;
}

PeerPoint::PeerPoint()
{
  NS_LOG_FUNCTION (this);
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
    loadTorrent();
}

bool PeerPoint::loadTorrent()
{
    torrent_handle handle;
    add_torrent_params param;
    std::string path;
    path.append("./");
    param.save_path = path;
    try
    {
        torrent_info* info = new torrent_info("./testTor");
        boost::intrusive_ptr<torrent_info> pTor(info);
        param.ti = pTor;
    }
    catch(libtorrent_exception e)
    {
        NS_LOG_ERROR("failed to load torrent file!");
        return false;
    }

    ses.add_torrent(param);
    return true;
}

void PeerPoint::StopApplication()
{
  NS_LOG_FUNCTION (this);
}
