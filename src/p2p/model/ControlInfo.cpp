#include "ControlInfo.h"

std::map<ns3::Ipv4Address, boost::shared_ptr<libtorrent::torrent> > ControlInfo::torrentMap;
