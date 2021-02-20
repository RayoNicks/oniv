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
#include "onivport.h"

using std::map;
using std::min;
using std::string;

class OnivPacket;

class OnivTunnel : public OnivPort
{
private:
    static int LocalTunnelSocket;
    sockaddr_in RemoteSocket;
    in_addr_t AdapterNameToAddr(const string &TunnelAdapterName);
public:
    OnivTunnel(const string &TunnelAdapterName, in_port_t PortNo, int TunnelMTU);
    OnivTunnel(in_addr_t address, in_port_t PortNo,  uint32_t vni, int TunnelMTU);
    OnivTunnel() = delete;
    OnivTunnel(const OnivTunnel &tunnel) = delete;
    OnivTunnel& operator=(const OnivTunnel &tunnel) = delete;
    virtual ~OnivTunnel() override;
    
    virtual OnivErr send() override;
    virtual OnivErr send(const OnivFrame &frame) override;
    virtual OnivErr recv(OnivFrame &frame) override;

    OnivErr recv(OnivPacket &packet);

    int handle() const;
    in_port_t RemotePortNo() const;
    in_addr_t RemoteIPAddress() const;
};

#endif
