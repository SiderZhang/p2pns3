#include <stdint.h>

#ifndef VIDEO_PACKET_HELPER
#define VIDEO_PACKET_HELPER

class VideoPacketHelper
{
public:
    VideoPacketHelper(int GOPIndex, int layer);
    VideoPacketHelper();
    ~VideoPacketHelper();

    uint32_t getTotalSize();
private:
    int GOPIndex;
    int layer;
};

#endif
