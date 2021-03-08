#ifndef _ONIV_FRAME_H_
#define _ONIV_FRAME_H_

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include <netinet/in.h>

#include "oniv.h"
#include "onivglobal.h"

using std::cout;
using std::hex;
using std::setfill;
using std::setw;
using std::string;
using std::swap;

class OnivPort;

class OnivFrame
{
private:
    string frame;
    OnivPort *ingress;
public:
    OnivFrame();
    OnivFrame(const OnivFrame &of);
    OnivFrame(OnivFrame &&of);
    OnivFrame& operator=(const OnivFrame &of);
    OnivFrame& operator=(OnivFrame &&of);
    ~OnivFrame();
    OnivFrame(const char *buf, const size_t size, OnivPort *port);

    void dump() const;
    OnivPort* IngressPort() const;

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
    bool IsTCP() const;
    bool IsUDP() const;
    in_port_t SrcPort() const;
    in_port_t DestPort() const;
};

#endif
