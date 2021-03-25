#include "onivtunnel.h"
#include "onivpacket.h"

using std::chrono::system_clock;
using std::min;

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

OnivErr OnivTunnel::EnableSend()
{
    if(keyent.RemoteUUID.empty()){ // 构造隧道密钥协商请求
        OnivTunReq req(bdi);
        sendto(LocalTunnelSocket, req.request(), req.size(), 0, (const struct sockaddr*)&RemoteSocket, sizeof(struct sockaddr_in));
        BlockSendingQueue(); // 暂时阻塞发送队列
    }
    else if(ValidSignature){
        if(keyent.SessionKey.empty()){ // 构造隧道密钥协商响应
            OnivTunRes res(bdi, &keyent);
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
                OnivTunRecord rec(bdi, frame, &keyent);
                sendto(LocalTunnelSocket, rec.record(), rec.size(), 0, (const struct sockaddr*)&RemoteSocket, sizeof(struct sockaddr_in));
                keyent.UpdateOnSend();
            }
            BlockSendingQueue();
        }
    }
    else{
        // 发送隧道密钥协商失败消息
    }
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr OnivTunnel::DisableSend()
{
    OnivFrame frame;
    while(1){
        sq.dequeue(frame);
        if(frame.empty()){
            break;
        }
        OnivTunRecord rec(bdi, frame, nullptr);
        sendto(LocalTunnelSocket, rec.record(), rec.size(), 0, (const struct sockaddr*)&RemoteSocket, sizeof(struct sockaddr_in));
    }
    BlockSendingQueue();
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
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

    bdi = UINT32_MAX;
}

OnivTunnel::OnivTunnel(in_addr_t address, in_port_t PortNo, uint32_t bdi, int mtu)
    : OnivPort(mtu, bdi)
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
    if(OnivGlobal::EnableTun()){
        return EnableSend();
    }
    else{
        return DisableSend();
    }
}

OnivErr OnivTunnel::recv(OnivPacket &packet)
{
    sockaddr_in remote;
    socklen_t len = sizeof(struct sockaddr_in);
    char buf[OnivGlobal::KeyAgrBufSize] = { 0 };
    size_t PacketSize;
    PacketSize = recvfrom(LocalTunnelSocket, buf, OnivGlobal::KeyAgrBufSize, 0, (struct sockaddr*)&remote, &len);
    if(PacketSize < 0){
        return OnivErr(OnivErrCode::ERROR_RECV_TUNNEL);
    }
    packet = OnivPacket(buf, PacketSize, this, remote, system_clock::now());
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr OnivTunnel::VerifySignature(const OnivPacket &packet)
{
    if(packet.type() == OnivPacketType::TUN_KA_REQ){
        OnivTunReq req(packet);
        ValidSignature = req.VerifySignature();
        if(ValidSignature){
            keyent.lock();
            keyent.RemoteUUID.assign((char*)req.tc.common.UUID, sizeof(req.tc.common.UUID));
            keyent.VerifyAlg = OnivCrypto::SelectVerifyAlg(req.PreVerifyAlg, req.SupVerifyAlgSet);
            keyent.KeyAgrAlg = OnivCrypto::SelectKeyAgrAlg(req.PreKeyAgrAlg, req.SupKeyAgrAlgSet);
            keyent.LocalPriKey = OnivCrypto::GenPriKey(keyent.KeyAgrAlg);
            keyent.LocalPubKey = OnivCrypto::GenPubKey(keyent.LocalPriKey);
            keyent.ts = req.ts;
            keyent.unlock();
            return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
        }
        else{
            return OnivErr(OnivErrCode::ERROR_SIGNATURE);
        }
    }
    else if(packet.type() == OnivPacketType::TUN_KA_RES){
        OnivTunRes res(packet);
        ValidSignature = res.VerifySignature();
        if(ValidSignature){
            keyent.lock();
            keyent.RemoteUUID.assign((char*)res.tc.common.UUID, sizeof(res.tc.common.UUID));
            keyent.VerifyAlg = res.VerifyAlg;
            keyent.KeyAgrAlg = res.KeyAgrAlg;
            keyent.RemotePubKey = res.pk.data();
            keyent.LocalPriKey = OnivCrypto::GenPriKey(keyent.KeyAgrAlg);
            keyent.LocalPubKey = OnivCrypto::GenPubKey(keyent.LocalPriKey);
            keyent.SessionKey = OnivCrypto::ComputeSessionKey(keyent.RemotePubKey, keyent.LocalPriKey);
            keyent.UpdPk = true;
            keyent.AckPk = false;
            keyent.ts = res.ResTs;
            keyent.unlock();
            return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
        }
        else{
            return OnivErr(OnivErrCode::ERROR_SIGNATURE);
        }
    }
    else{
        return OnivErr(OnivErrCode::ERROR_UNKNOWN);
    }
}

int OnivTunnel::handle() const
{
    return LocalTunnelSocket;
}

string OnivTunnel::RemoteID() const
{
    return keyent.RemoteUUID;
}

in_port_t OnivTunnel::RemotePortNo() const
{
    return RemoteSocket.sin_port;
}

in_addr_t OnivTunnel::RemoteIPAddress() const
{
    return RemoteSocket.sin_addr.s_addr;
}

void OnivTunnel::UpdateSocket(const OnivPacket &packet)
{
    RemoteSocket.sin_port = packet.RemotePortNo();
    RemoteSocket.sin_addr.s_addr = packet.RemoteIPAddress();
}

OnivKeyEntry* OnivTunnel::KeyEntry()
{
    return &keyent;
}

int OnivTunnel::LocalTunnelSocket = -1;
