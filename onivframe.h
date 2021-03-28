#ifndef _ONIV_FRAME_H_
#define _ONIV_FRAME_H_

#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <netinet/in.h>

#include "oniv.h"
#include "onivglobal.h"

using std::chrono::system_clock;
using std::chrono::time_point;
using std::string;
using std::vector;

class OnivPort;

class OnivFrame
{
private:
    string frame;
    OnivPort *ingress;
    time_point<system_clock> entry;
public:
    OnivFrame();
    OnivFrame(const OnivFrame &of);
    OnivFrame(OnivFrame &&of);
    OnivFrame& operator=(const OnivFrame &of);
    OnivFrame& operator=(OnivFrame &&of);
    ~OnivFrame();
    OnivFrame(const char *buf, const size_t size, OnivPort *port, const time_point<system_clock> &tp);

    void dump() const;
    OnivPort* IngressPort() const;
    const time_point<system_clock> EntryTime() const;

    bool empty() const;
    size_t size() const;
    OnivPacketType type() const;
    const char* buffer() const;
    const char* Layer2Hdr() const;
    const char* Layer3Hdr() const;
    const char* Layer4Hdr() const;
    const string OriginUserData() const;
    const char* OnivHdr() const;
    bool IsLayer4Oniv() const;

    const string DestHwAddr() const;
    const string SrcHwAddr() const;
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
    vector<OnivFrame> fragement(int mtu) const;
};

#endif
