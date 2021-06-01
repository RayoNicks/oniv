#include "onivmessage.h"

#include <cstring>
#include <iomanip>
#include <iostream>

#include <unistd.h>

#include "onivsecond.h"
#include "onivtunnel.h"

using std::chrono::system_clock;
using std::chrono::time_point;
using std::cout;
using std::endl;
using std::hex;
using std::setfill;
using std::setw;
using std::string;

OnivMessage::OnivMessage() : ingress(nullptr)
{

}

OnivMessage::OnivMessage(const OnivMessage &om) : message(om.message), ingress(om.ingress), tp(om.tp)
{
    memcpy(&remote, &om.remote, sizeof(struct sockaddr_in));
}

OnivMessage::OnivMessage(OnivMessage &&om) : message(om.message), ingress(om.ingress), tp(om.tp)
{
    memcpy(&remote, &om.remote, sizeof(struct sockaddr_in));
}

OnivMessage& OnivMessage::operator=(const OnivMessage &om)
{
    message = om.message;
    ingress = om.ingress;
    tp = om.tp;
    memcpy(&remote, &om.remote, sizeof(struct sockaddr_in));
    return *this;
}

OnivMessage& OnivMessage::operator=(OnivMessage &&om)
{
    message = om.message;
    ingress = om.ingress;
    tp = om.tp;
    memcpy(&remote, &om.remote, sizeof(struct sockaddr_in));
    return *this;
}

OnivMessage::~OnivMessage()
{

}

OnivMessage::OnivMessage(const char *buf, const size_t size, OnivTunnel *tunnel, const sockaddr_in &RemoteSocketAddress, const time_point<system_clock> &tp)
    : message(buf, size), ingress(tunnel), tp(tp)
{
    memcpy(&remote, &RemoteSocketAddress, sizeof(struct sockaddr_in));
}

void OnivMessage::dump() const
{
    for(size_t i = 0; i < message.size(); i += 16)
    {
        for(size_t j = 0; j < 16 && i + j < message.size(); j++)
        {
            cout << hex << setw(2) << setfill('0') << (message[i + j] & 0xff) << ' ';
        }
        cout << '\n';
    }
    cout << endl;
}

OnivTunnel* OnivMessage::IngressPort() const
{
    return ingress;
}

const time_point<system_clock> OnivMessage::EntryTime() const
{
    return tp;
}

string OnivMessage::SenderID() const
{
    OnivTunCommon tc;
    tc.structuration((const uint8_t*)buffer());
    return string((char*)tc.common.UUID, sizeof(tc.common.UUID));
}

in_port_t OnivMessage::RemotePortNo() const
{
    return remote.sin_port;
}

in_addr_t OnivMessage::RemoteIPAddress() const
{
    return remote.sin_addr.s_addr;
}

uint32_t OnivMessage::BroadcastDomain() const
{
    return ntohl(*(uint32_t*)(buffer() + OnivCommon::LinearSize()));
}

size_t OnivMessage::size() const
{
    return message.size();
}

OnivPacketType OnivMessage::type() const
{
    return CastFrom16<OnivPacketType>(ntohs(((OnivCommon*)buffer())->type));
}

const char* OnivMessage::buffer() const
{
    return message.c_str();
}

void OnivMessage::DiapatchIngressTunnel(OnivTunnel *tunnel)
{
    ingress = tunnel;
}
