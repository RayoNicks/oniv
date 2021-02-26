#ifndef _ONIV_FRAME_H_
#define _ONIV_FRAME_H_

#include <algorithm>
#include <cstring>
#include <string>

#include <iomanip>
#include <iostream>

#include <netinet/in.h>

#include "oniv.h"
#include "onivcrypto.h"
#include "onivglobal.h"

using std::string;

using std::cout;
using std::hex;
using std::setfill;
using std::setw;
using std::swap;

class OnivPort;
class OnivPacket;

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
    OnivFrame(const OnivPacket &packet);

    void dump() const;
    // vector<OnivFrame> encapsulate(const string &LnkSK, OnivVerifyAlg VerifyAlg);
    // void decapsulate(const string &LnkSK, OnivVerifyAlg VerifyAlg);
    OnivPort* IngressPort() const;

    bool empty() const;
    size_t size() const;
    OnivPacketType type() const;
    const char* buffer() const;
    const char* Layer2Hdr() const;
    const char* Layer3Hdr() const;
    const char* Layer4Hdr() const;
    const char* TCPHdr() const;
    const char* UDPHdr() const;
    const string UserData() const;
    const char* OnivHdr() const;
    bool IsLayer3Oniv() const;
    bool IsLayer4Oniv() const;
    bool IsOniv() const;

    uint8_t Layer4Protocol() const;
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

    void reverse();
};

#endif
