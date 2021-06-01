#ifndef _ONIV_TUNNEL_H_
#define _ONIV_TUNNEL_H_

#include <chrono>
#include <string>

#include "oniventry.h"
#include "onivport.h"

class OnivMessage;

class OnivTunnel : public OnivPort
{
private:
    static int LocalTunnelSocket;
    bool ValidSignature;
    OnivKeyEntry keyent;
    in_addr_t AdapterNameToAddr(const std::string &TunnelAdapterName);
    OnivErr EnableSend();
    OnivErr DisableSend();
public:
    OnivTunnel(const std::string &TunnelAdapterName, in_port_t PortNo, int mtu);
    OnivTunnel(in_addr_t address, in_port_t PortNo,  uint32_t bdi, int mtu);
    OnivTunnel() = delete;
    OnivTunnel(const OnivTunnel &tunnel) = delete;
    OnivTunnel& operator=(const OnivTunnel &tunnel) = delete;
    virtual ~OnivTunnel() override;
    
    virtual OnivErr send() override;
    OnivErr recv(OnivMessage &message);

    OnivErr VerifySignature(const OnivMessage &message);

    int handle() const;
    std::string RemoteID() const;
    in_port_t RemotePortNo() const;
    in_addr_t RemoteIPAddress() const;
    void UpdateSocket(const OnivMessage &message);
    OnivKeyEntry* KeyEntry();
};

#endif
