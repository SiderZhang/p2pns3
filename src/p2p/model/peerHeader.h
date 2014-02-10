#include "ns3/header.h"

namespace ns3
{
class PeerHeader : public Header
{
public:
    PeerHeader();

    virtual ~PeerHeader();

    uint32_t GetSerializedSize (void) const;
    void Serialize (Buffer::Iterator start) const;
    uint32_t Deserialize (Buffer::Iterator start);
    void Print (std::ostream &os) const;

    void setBuffer(const uint8_t* buffer, uint32_t size);
    const uint8_t* getBuffer() const;
    int getSize(){return bufSize;}

    static TypeId GetTypeId (void);
private:
    virtual TypeId GetInstanceTypeId (void) const;
    uint32_t headerSize;

    uint8_t* buffer;
    int bufSize;
};
}
