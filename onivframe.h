#ifndef _ONIV_FRAME_H_
#define _ONIV_FRAME_H_

#include <cstring>
#include <string>

#include <iomanip>
#include <iostream>

#include <netinet/in.h>

#include "onivglobal.h"

using std::string;

using std::cout;
using std::hex;
using std::setfill;
using std::setw;

class OnivPort;
class OnivPacket;

class OnivFrame
{
private:
    string frame;
    OnivPort *ingress;
    const char* Layer3Hdr() const;
public:
    OnivFrame();
    OnivFrame(const OnivFrame &of);
    OnivFrame(OnivFrame &&of);
    OnivFrame& operator=(const OnivFrame &of);
    OnivFrame& operator=(OnivFrame &&of);
    ~OnivFrame();
    OnivFrame(const char *buf, const size_t size, OnivPort *port);
    OnivFrame(const OnivPacket &op);

    void dump() const;
    OnivPort* IngressPort() const;

    bool empty() const;
    size_t size() const;
    const char* data() const;
    const char* DestHwAddr() const;
    const char* SrcHwAddr() const;
    bool IsBroadcast();
    bool ARP() const;
    bool IP() const;
    in_addr_t SrcIPAddr() const;
    in_addr_t DestIPAddr() const;
    bool TCP() const;
    bool UDP() const;
};

#endif
