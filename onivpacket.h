#ifndef _ONIV_PACKET_H_
#define _ONIV_PACKET_H_

#include <cstring>

#include <netinet/in.h>
#include <unistd.h>

#include "oniv.h"
#include "onivglobal.h"

class OnivFrame;
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
    OnivPacket(const OnivFrame &frame);

    void dump() const;
    OnivTunnel* IngressPort() const;
    string SenderID() const;
    in_port_t RemotePortNo() const;
    in_addr_t RemoteIPAddress() const;
    uint32_t BroadcastID() const;
    OnivFrame ConvertToFrame() const;

    size_t size() const;
    size_t HdrSize() const;
    OnivPacketType type() const;
    const char* data() const;
    const char* frame() const;

    bool belong(const OnivTunnel &tunnel) const;
    void ResetIngressTunnel(OnivTunnel *tunnel);
};

#endif
