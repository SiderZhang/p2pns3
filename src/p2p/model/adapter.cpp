#include "adapter.h"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <time.h>

using namespace libtorrent;
using namespace ns3;
using namespace std;

Time boostTimeConvert(ptime& time)
{
    Time t = Simulator::Now();
    time_t my_time_t = time.time;
    Time t2(my_time_t);
    return t2 - t;
}
