#ifndef _ONIV_FRAME_H_
#define _ONIV_FRAME_H_

#include <cstring>
#include <string>

#include <arpa/inet.h>

#include "onivglobal.h"

using std::string;

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
    
    OnivPort* IngressPort() const;

    bool empty() const;
    size_t size() const;
    const char* data() const;
    const char* DestHwAddr() const;
    const char* SrcHwAddr() const;
    bool IsBroadcast();
    bool AddressResolutionProtocol();
    bool InternetProtocol() const;
    in_addr_t SrcIPAddr() const;
    in_addr_t DestIPAddr() const;
    bool TransferControlProtocol() const;
    bool UserDatagramProtocol() const;
};

#endif
