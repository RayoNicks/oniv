#ifndef _ONIV_PACKET_H_
#define _ONIV_PACKET_H_

#include <cstring>

#include <netinet/in.h>
#include <unistd.h>

#include "onivglobal.h"

enum class OnivPacketType
{
    UNKNOWN,
    TUN_KA_REQ,
    TUN_KA_RES,
    ONIV_RECORD,
    LNK_KA_REQ,
    LNK_KA_RES,
};

class OnivFrame;
class OnivTunnel;

class OnivPacket
{
private:
    string packet;
    OnivTunnel* ingress;
    sockaddr_in remote;
public:
    OnivPacket();
    OnivPacket(const OnivPacket &op);
    OnivPacket(OnivPacket &&op);
    OnivPacket& operator=(const OnivPacket &op);
    OnivPacket& operator=(OnivPacket &&op);
    ~OnivPacket();
    OnivPacket(const char *buf, const size_t size, OnivTunnel *tunnel, const sockaddr_in &RemoteSocketAddress);
    OnivPacket(const OnivFrame &of);

    OnivTunnel* IngressPort() const;
    in_port_t RemotePortNo() const;
    in_addr_t RemoteIPAddress() const;
    uint32_t BroadcastID() const;
    OnivFrame ConvertToFrame() const;

    size_t size() const;
    size_t HdrSize() const;
    OnivPacketType type() const;
    const char* data() const;

    bool belong(const OnivTunnel &tunnel) const;
    void ResetIngressTunnel(OnivTunnel *tunnel);
};

#endif
