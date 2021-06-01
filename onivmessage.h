#ifndef _ONIV_MESSAGE_H_
#define _ONIV_MESSAGE_H_

#include <chrono>
#include <string>

#include "oniv.h"

class OnivTunnel;

class OnivMessage
{
private:
    std::string message;
    OnivTunnel *ingress;
    sockaddr_in remote;
    std::chrono::time_point<std::chrono::system_clock> tp;
public:
    OnivMessage();
    OnivMessage(const OnivMessage &om);
    OnivMessage(OnivMessage &&om);
    OnivMessage& operator=(const OnivMessage &om);
    OnivMessage& operator=(OnivMessage &&om);
    ~OnivMessage();
    OnivMessage(const char *buf, const size_t size, OnivTunnel *tunnel, const sockaddr_in &RemoteSocketAddress, const std::chrono::time_point<std::chrono::system_clock> &tp);

    void dump() const;
    OnivTunnel* IngressPort() const;
    const std::chrono::time_point<std::chrono::system_clock> EntryTime() const;
    std::string SenderID() const;
    in_port_t RemotePortNo() const;
    in_addr_t RemoteIPAddress() const;
    uint32_t BroadcastDomain() const;

    size_t size() const;
    OnivPacketType type() const;
    const char* buffer() const;

    void DiapatchIngressTunnel(OnivTunnel *tunnel);
};

#endif
