#include "onivtunnel.h"
#include "onivpacket.h"

OnivTunnel::~OnivTunnel()
{

}

OnivTunnel::OnivTunnel(const string &TunnelAdapterName, in_port_t PortNo, int TunnelMTU)
    : OnivPort(TunnelMTU)
{
    struct sockaddr_in LocalTunnelSockAddress;
    memset(&LocalTunnelSockAddress, 0, sizeof(struct sockaddr_in));
    LocalTunnelSockAddress.sin_family = AF_INET;
    LocalTunnelSockAddress.sin_port = PortNo;
    LocalTunnelSockAddress.sin_addr.s_addr = AdapterNameToAddr(TunnelAdapterName);

    if((LocalTunnelSocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
        err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_CREATE_TUNNEL_SOCKET).ErrMsg().c_str());
    }

    if(bind(LocalTunnelSocket, (const struct sockaddr*)&LocalTunnelSockAddress, sizeof(struct sockaddr_in)) == -1){
        err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_BIND_TUNNEL_SOCKET).ErrMsg().c_str());
    }

    vni = UINT32_MAX;
}

in_addr_t OnivTunnel::AdapterNameToAddr(const string &TunnelAdapterName)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, TunnelAdapterName.c_str(), min((size_t)IFNAMSIZ, TunnelAdapterName.length()));

    int CtrlFD = socket(AF_INET, SOCK_DGRAM, 0);
    if(CtrlFD < 0){
        err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_CREATE_TUNNEL_SOCKET).ErrMsg().c_str());
    }
    if(ioctl(CtrlFD, SIOCGIFADDR, &ifr) < 0){
        err(EXIT_FAILURE,"%s", OnivErr(OnivErrCode::ERROR_CREATE_TUNNEL_SOCKET).ErrMsg().c_str());
    }
    return ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
}

OnivTunnel::OnivTunnel(in_addr_t address, in_port_t PortNo, uint32_t vni, int TunnelMTU)
    : OnivPort(TunnelMTU, vni)
{
    memset(&RemoteSocket, 0, sizeof(struct sockaddr_in));
    RemoteSocket.sin_family = AF_INET;
    RemoteSocket.sin_port = PortNo;
    RemoteSocket.sin_addr.s_addr = address;
}

OnivErr OnivTunnel::send()
{
    OnivFrame of;
    while(1){
        sq.dequeue(of);
        if(of.empty()){
            break;
        }
        OnivPacket packet(of);
        sendto(handle(), packet.data(), packet.size(), 0, (const struct sockaddr*)&RemoteSocket, sizeof(struct sockaddr_in));
    }
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr OnivTunnel::send(const OnivFrame &frame)
{
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr OnivTunnel::recv(OnivFrame &frame)
{
    sockaddr_in remote;
    socklen_t len = sizeof(struct sockaddr_in);
    char buf[mtu] = { 0 };
    size_t FrameSize;
    FrameSize = recvfrom(LocalTunnelSocket, buf, mtu, 0, (struct sockaddr*)&remote, &len);
    if(FrameSize < 0){
        return OnivErr(OnivErrCode::ERROR_RECV_TUNNEL);
    }

    OnivPacket packet(buf, FrameSize, this, remote);

    frame = packet.ConvertToFrame();

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr OnivTunnel::recv(OnivPacket &packet)
{
    sockaddr_in remote;
    socklen_t len = sizeof(struct sockaddr_in);
    char buf[mtu] = { 0 };
    size_t PacketSize;
    PacketSize = recvfrom(LocalTunnelSocket, buf, mtu, 0, (struct sockaddr*)&remote, &len);
    if(PacketSize < 0){
        return OnivErr(OnivErrCode::ERROR_RECV_TUNNEL);
    }
    packet = OnivPacket(buf, PacketSize, this, remote);

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

int OnivTunnel::handle() const
{
    return LocalTunnelSocket;
}

in_port_t OnivTunnel::RemotePortNo() const
{
    return RemoteSocket.sin_port;
}

in_addr_t OnivTunnel::RemoteIPAddress() const
{
    return RemoteSocket.sin_addr.s_addr;
}

int OnivTunnel::LocalTunnelSocket = -1;
