#include "video-packet-helper.h"

VideoPacketHelper::VideoPacketHelper()
    :GOPIndex(-1), layer(-1)
{
}

VideoPacketHelper::VideoPacketHelper(int GOP_Index, int _layer)
    :GOPIndex(GOP_Index), layer(_layer)
{
}

VideoPacketHelper::~VideoPacketHelper()
{
}

uint32_t VideoPacketHelper::getTotalSize()
{
    // TODO: wait to inte:q
    return 5120;
}
