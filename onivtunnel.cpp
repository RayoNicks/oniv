#include "onivtunnel.h"
#include "onivpacket.h"

in_addr_t OnivTunnel::AdapterNameToAddr(const string &TunnelAdapterName)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, TunnelAdapterName.c_str(), min((size_t)IFNAMSIZ, TunnelAdapterName.length()));

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0){
        err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_CREATE_TUNNEL_SOCKET).ErrMsg().c_str());
    }
    if(ioctl(fd, SIOCGIFADDR, &ifr) < 0){
        err(EXIT_FAILURE,"%s", OnivErr(OnivErrCode::ERROR_CREATE_TUNNEL_SOCKET).ErrMsg().c_str());
    }
    return ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
}

OnivTunnel::OnivTunnel(const string &TunnelAdapterName, in_port_t PortNo, int mtu)
    : OnivPort(mtu, UINT32_MAX)
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

OnivTunnel::OnivTunnel(in_addr_t address, in_port_t PortNo, uint32_t vni, int mtu)
    : OnivPort(mtu, vni)
{
    memset(&RemoteSocket, 0, sizeof(struct sockaddr_in));
    RemoteSocket.sin_family = AF_INET;
    RemoteSocket.sin_port = PortNo;
    RemoteSocket.sin_addr.s_addr = address;
}

OnivTunnel::~OnivTunnel()
{

}

OnivErr OnivTunnel::send()
{
    if(RemoteUUID.empty()){ // 构造隧道密钥协商请求
        OnivTunReq req;
        sendto(LocalTunnelSocket, req.request(), req.size(), 0, (const struct sockaddr*)&RemoteSocket, sizeof(struct sockaddr_in));
        BlockSendingQueue(); // 暂时阻塞发送队列
    }
    else if(AuthCertPass){
        if(TunSK.empty()){ // 构造隧道密钥协商响应
            OnivTunRes res(VerifyAlg, KeyAgrAlg);
            sendto(LocalTunnelSocket, res.response(), res.size(), 0, (const struct sockaddr*)&RemoteSocket, sizeof(struct sockaddr_in));
            BlockSendingQueue(); // 暂时阻塞发送队列
        }
        else{
            OnivFrame frame;
            while(1){
                sq.dequeue(frame);
                if(frame.empty()){
                    break;
                }
                OnivPacket packet(frame); // 封装第二种身份信息的相关参数
                sendto(LocalTunnelSocket, packet.data(), packet.size(), 0, (const struct sockaddr*)&RemoteSocket, sizeof(struct sockaddr_in));
            }
            BlockSendingQueue();
        }
    }
    else{ // 构造隧道密钥协商失败消息
        // TODO
    }
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

OnivErr OnivTunnel::AuthCert(const OnivPacket &packet)
{
    if(packet.type() == OnivPacketType::TUN_KA_REQ){
        OnivTunReq req(packet);
        AuthCertPass = req.AuthCert();
        if(AuthCertPass){
            RemoteUUID.assign((char*)req.common.UUID, sizeof(req.common.UUID));
            VerifyAlg = req.PreVerifyAlg;
            KeyAgrAlg = req.PreKeyAgrAlg;
        }
    }
    else if(packet.type() == OnivPacketType::TUN_KA_RES){
        OnivTunRes res(packet);
        AuthCertPass = res.AuthCert();
        if(AuthCertPass){
            RemoteUUID.assign((char*)res.common.UUID, sizeof(res.common.UUID));
            VerifyAlg = res.VerifyAlg;
            KeyAgrAlg = res.KeyAgrAlg;
            TunSK = res.pk; // 计算隧道会话密钥
        }
    }

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

int OnivTunnel::handle() const
{
    return LocalTunnelSocket;
}

string OnivTunnel::RemoteID() const
{
    return RemoteUUID;
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
