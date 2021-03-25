#include "onivpacket.h"
#include "onivtunnel.h"

using std::cout;
using std::endl;
using std::hex;
using std::setfill;
using std::setw;

OnivPacket::OnivPacket() : ingress(nullptr)
{

}

OnivPacket::OnivPacket(const OnivPacket &op) : packet(op.packet), ingress(op.ingress), tp(op.tp)
{
    memcpy(&remote, &op.remote, sizeof(struct sockaddr_in));
}

OnivPacket::OnivPacket(OnivPacket &&op) : packet(op.packet), ingress(op.ingress), tp(op.tp)
{
    memcpy(&remote, &op.remote, sizeof(struct sockaddr_in));
}

OnivPacket& OnivPacket::operator=(const OnivPacket &op)
{
    packet = op.packet;
    ingress = op.ingress;
    tp = op.tp;
    memcpy(&remote, &op.remote, sizeof(struct sockaddr_in));
    return *this;
}

OnivPacket& OnivPacket::operator=(OnivPacket &&op)
{
    packet = op.packet;
    ingress = op.ingress;
    tp = op.tp;
    memcpy(&remote, &op.remote, sizeof(struct sockaddr_in));
    return *this;
}

OnivPacket::~OnivPacket()
{

}

OnivPacket::OnivPacket(const char *buf, const size_t size, OnivTunnel *tunnel, const sockaddr_in &RemoteSocketAddress, const time_point<system_clock> &tp)
    : packet(buf, size), ingress(tunnel), tp(tp)
{
    memcpy(&remote, &RemoteSocketAddress, sizeof(struct sockaddr_in));
}

void OnivPacket::dump() const
{
    for(size_t i = 0; i < packet.size(); i += 16)
    {
        for(size_t j = 0; j < 16 && i + j < packet.size(); j++)
        {
            cout << hex << setw(2) << setfill('0') << (packet[i + j] & 0xff) << ' ';
        }
        cout << '\n';
    }
    cout << endl;
}

OnivTunnel* OnivPacket::IngressPort() const
{
    return ingress;
}

const time_point<system_clock> OnivPacket::EntryTime() const
{
    return tp;
}

string OnivPacket::SenderID() const
{
    OnivTunCommon tc;
    tc.structuration((const uint8_t*)buffer());
    return string((char*)tc.common.UUID, sizeof(tc.common.UUID));
}

in_port_t OnivPacket::RemotePortNo() const
{
    return remote.sin_port;
}

in_addr_t OnivPacket::RemoteIPAddress() const
{
    return remote.sin_addr.s_addr;
}

uint32_t OnivPacket::BroadcastDomain() const
{
    return ntohl(*(uint32_t*)(buffer() + OnivCommon::LinearSize()));
}

size_t OnivPacket::size() const
{
    return packet.size();
}

OnivPacketType OnivPacket::type() const
{
    return CastFrom16<OnivPacketType>(ntohs(((OnivCommon*)buffer())->type));
}

const char* OnivPacket::buffer() const
{
    return packet.c_str();
}

void OnivPacket::DiapatchIngressTunnel(OnivTunnel *tunnel)
{
    ingress = tunnel;
}
