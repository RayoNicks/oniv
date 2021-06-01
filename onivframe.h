#ifndef _ONIV_FRAME_H_
#define _ONIV_FRAME_H_

#include <chrono>
#include <string>
#include <vector>

#include "oniv.h"

class OnivPort;

class OnivFrame
{
private:
    std::string frame;
    OnivPort *ingress;
    std::chrono::time_point<std::chrono::system_clock> entry;
public:
    OnivFrame();
    OnivFrame(const OnivFrame &of);
    OnivFrame(OnivFrame &&of);
    OnivFrame& operator=(const OnivFrame &of);
    OnivFrame& operator=(OnivFrame &&of);
    ~OnivFrame();
    OnivFrame(const char *buf, const size_t size, OnivPort *port, const std::chrono::time_point<std::chrono::system_clock> &tp);

    void dump() const;
    OnivPort* IngressPort() const;
    const std::chrono::time_point<std::chrono::system_clock> EntryTime() const;

    bool empty() const;
    size_t size() const;
    OnivPacketType type() const;
    const char* buffer() const;
    const char* Layer2Hdr() const;
    const char* Layer3Hdr() const;
    const char* Layer4Hdr() const;
    const std::string OriginUserData() const;
    const char* OnivHdr() const;
    bool IsLayer4Oniv() const;

    const std::string DestHwAddr() const;
    const std::string SrcHwAddr() const;
    bool IsBroadcast() const;
    bool IsARP() const;
    bool IsIP() const;
    uint8_t IPHdrLen() const;
    in_addr_t SrcIPAddr() const;
    in_addr_t DestIPAddr() const;
    bool IsICMP() const;
    bool IsTCP() const;
    bool IsUDP() const;
    in_port_t SrcPort() const;
    in_port_t DestPort() const;

    void append(const char *p, size_t n);
    std::vector<OnivFrame> fragement(int mtu) const;
};

#endif
