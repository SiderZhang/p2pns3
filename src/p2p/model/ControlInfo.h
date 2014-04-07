#include "ns3/ipv4-address.h"
#include "ns3/libtorrent/torrent.hpp"
#include <map>
#include <vector>

class ControlInfo
{
public:
    typedef std::map<ns3::Ipv4Address, boost::shared_ptr<libtorrent::torrent> >::iterator iter;
    // TODO: 临时用这个全局变量保存Peer的信息。
    static std::map<ns3::Ipv4Address, boost::shared_ptr<libtorrent::torrent> > torrentMap;

    static void updateTorrent(ns3::Ipv4Address& addr, boost::shared_ptr<libtorrent::torrent> tor)
    {
        torrentMap.insert(std::pair<ns3::Ipv4Address, boost::shared_ptr<libtorrent::torrent> > (addr, tor));
    }
}
;
