#ifndef _ONIV_PACKET_H_
#define _ONIV_PACKET_H_

#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include <netinet/in.h>
#include <unistd.h>

#include "oniv.h"

using std::string;

class OnivTunnel;

class OnivPacket
{
private:
    string packet;
    OnivTunnel *ingress;
    sockaddr_in remote;
public:
    OnivPacket();
    OnivPacket(const OnivPacket &op);
    OnivPacket(OnivPacket &&op);
    OnivPacket& operator=(const OnivPacket &op);
    OnivPacket& operator=(OnivPacket &&op);
    ~OnivPacket();
    OnivPacket(const char *buf, const size_t size, OnivTunnel *tunnel, const sockaddr_in &RemoteSocketAddress);

    void dump() const;
    OnivTunnel* IngressPort() const;
    string SenderID() const;
    in_port_t RemotePortNo() const;
    in_addr_t RemoteIPAddress() const;
    uint32_t BroadcastDomain() const;

    size_t size() const;
    OnivPacketType type() const;
    const char* buffer() const;

    void DiapatchIngressTunnel(OnivTunnel *tunnel);
};

#endif
