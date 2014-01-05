#include "peerHeader.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("PeerHeader");

PeerHeader::PeerHeader()
{
    buffer = NULL;
}

PeerHeader::~PeerHeader()
{
    if (buffer != NULL)
    {
        delete buffer;
        buffer = NULL;
    }
}

TypeId PeerHeader::GetTypeId()
{
    static TypeId tid = TypeId ("ns3::PeerHeader")
        .SetParent<Header>()
        .AddConstructor<PeerHeader>();
    return tid;
}

uint32_t PeerHeader::GetSerializedSize() const
{
    NS_LOG_FUNCTION (this);
    return headerSize;
}

void PeerHeader::Serialize(Buffer::Iterator start) const
{
    NS_LOG_FUNCTION (this);
}

uint32_t PeerHeader::Deserialize(Buffer::Iterator start)
{
    NS_LOG_FUNCTION (this);
    return -1;
}

void PeerHeader::Print(std::ostream &os) const
{
    NS_LOG_FUNCTION (this << &os);
}
    
void PeerHeader::setBuffer(const uint8_t* nbuffer, uint32_t size)
{
    if (buffer != NULL)
    {
        delete buffer;
        buffer = NULL;
    }

    buffer = new uint8_t[size];
    memset (buffer, '0', size * sizeof(uint8_t));
    memcpy (buffer, nbuffer, size);
    bufSize = size;
}

const uint8_t* PeerHeader::getBuffer() const
{
    return buffer;
}
