#include "onivpacket.h"
#include "onivframe.h"
#include "onivtunnel.h"

OnivPacket::OnivPacket() : ingress(nullptr)
{

}

OnivPacket::OnivPacket(const OnivPacket &op) : packet(op.packet), ingress(op.ingress)
{
    memcpy(&remote, &op.remote, sizeof(struct sockaddr_in));
}

OnivPacket::OnivPacket(OnivPacket &&op) : packet(op.packet), ingress(op.ingress)
{
    memcpy(&remote, &op.remote, sizeof(struct sockaddr_in));
}

OnivPacket& OnivPacket::operator=(const OnivPacket &op)
{
    this->packet = op.packet;
    ingress = op.ingress;
    memcpy(&remote, &op.remote, sizeof(struct sockaddr_in));
    return *this;
}

OnivPacket& OnivPacket::operator=(OnivPacket &&op)
{
    this->packet = op.packet;
    ingress = op.ingress;
    memcpy(&remote, &op.remote, sizeof(struct sockaddr_in));
    return *this;
}

OnivPacket::~OnivPacket()
{

}

OnivPacket::OnivPacket(const char *buf, const size_t size, OnivTunnel *tunnel, const sockaddr_in &RemoteSocketAddress)
    : packet(buf, size), ingress(tunnel)
{
    memcpy(&remote, &RemoteSocketAddress, sizeof(struct sockaddr_in));
}

OnivPacket::OnivPacket(const OnivFrame &of)
{
    packet.push_back(static_cast<char>(OnivPacketType::ONIV_RECORD));
    packet.push_back(0x00); // flags
    uint32_t vni = htonl(of.IngressPort()->BroadcastID());
    packet.push_back(static_cast<char>(vni >> 24));
    packet.push_back(static_cast<char>(vni >> 16));
    packet.push_back(static_cast<char>(vni >> 8));
    packet.push_back(static_cast<char>(vni));
    packet.append(of.data(), of.size());
}

OnivTunnel* OnivPacket::IngressPort() const
{
    return ingress;
}

in_port_t OnivPacket::RemotePortNo() const
{
    return remote.sin_port;
}

in_addr_t OnivPacket::RemoteIPAddress() const
{
    return remote.sin_addr.s_addr;
}

uint32_t OnivPacket::BroadcastID() const
{
    return static_cast<uint32_t>(*(packet.c_str() + 2));
}

OnivFrame OnivPacket::ConvertToFrame() const
{
    return OnivFrame(packet.c_str() + HdrSize(), packet.size() - HdrSize(), ingress);
}

size_t OnivPacket::size() const
{
    return packet.size();
}

size_t OnivPacket::HdrSize() const
{
    // TODO
    return 2 + sizeof(uint32_t);
}

OnivPacketType OnivPacket::type() const
{
    return static_cast<OnivPacketType>(*packet.c_str());
}

const char* OnivPacket::data() const
{
    return packet.c_str() + HdrSize();
}

bool OnivPacket::belong(const OnivTunnel &tunnel) const
{
    return BroadcastID() == tunnel.BroadcastID()
        && RemotePortNo() == tunnel.RemotePortNo()
        && RemoteIPAddress() == tunnel.RemoteIPAddress();
}

void OnivPacket::ResetIngressTunnel(OnivTunnel *tunnel)
{
    this->ingress = tunnel;
}
