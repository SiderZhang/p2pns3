#include "adapter.h"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <time.h>

#include "ns3/log.h"

using namespace libtorrent;
using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE ("Adapter");

Time boostTimeConvert(ptime& time)
{
    Time t = Simulator::Now();
    Time t2 = time.time;
    return t2 - t;
}
