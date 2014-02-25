#include "peerPoint.h"
#include "ns3/libtorrent/torrent_handle.hpp"
#include "libtorrent/add_torrent_params.hpp"
#include "libtorrent/torrent_info.hpp"
#include "libtorrent/error_code.hpp"
#include <string>

#include "ns3/log.h"

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
        .AddConstructor<PeerPoint>();
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
  NS_LOG_INFO(this);
    ses = new session(MakeCallback(&PeerPoint::loadTorrent, this),GetNode());
}

void PeerPoint::loadTorrent(session* sess)
{
  NS_LOG_FUNCTION (this);
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
    }

    sess->add_torrent(param);
}

void PeerPoint::StopApplication()
{
  NS_LOG_FUNCTION (this);
}
}
