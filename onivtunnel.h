#ifndef _ONIV_TUNNEL_H_
#define _ONIV_TUNNEL_H_

#include <algorithm>
#include <cstring>
#include <map>
#include <string>

#include <arpa/inet.h>
#include <err.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "onivglobal.h"
#include "oniventry.h"
#include "onivport.h"
#include "onivsecond.h"

using std::map;
using std::min;
using std::string;

class OnivPacket;

class OnivTunnel : public OnivPort
{
private:
    static int LocalTunnelSocket;
    sockaddr_in RemoteSocket;
    bool ValidSignature;
    OnivKeyEntry keyent;
    in_addr_t AdapterNameToAddr(const string &TunnelAdapterName);
public:
    OnivTunnel(const string &TunnelAdapterName, in_port_t PortNo, int mtu);
    OnivTunnel(in_addr_t address, in_port_t PortNo,  uint32_t vni, int mtu);
    OnivTunnel() = delete;
    OnivTunnel(const OnivTunnel &tunnel) = delete;
    OnivTunnel& operator=(const OnivTunnel &tunnel) = delete;
    virtual ~OnivTunnel() override;
    
    virtual OnivErr send() override;
    OnivErr recv(OnivPacket &packet);

    OnivErr AuthCert(const OnivPacket &packet);
    OnivErr VerifyPacket(const OnivPacket &packet);

    int handle() const;
    string RemoteID() const;
    in_port_t RemotePortNo() const;
    in_addr_t RemoteIPAddress() const;
    void UpdateSocket(const OnivPacket &packet);
    OnivKeyEntry* KeyEntry();
};

#endif
