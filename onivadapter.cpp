#include "onivadapter.h"

OnivAdapter::OnivAdapter(const string &name, in_addr_t address, uint32_t vni, int AdapterMTU)
    : OnivPort(AdapterMTU, vni), FrameFD(-1), CtrlFD(-1), AdapterName(name)
{
    // 创建隧道设备
    struct ifreq ifr;
    if((FrameFD = open("/dev/net/tun", O_RDWR)) < 0){
        return;
    }
    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
    if(ioctl(FrameFD, TUNSETIFF, &ifr) < 0){
        close(FrameFD);
    }

    // 开启网卡
    if((CtrlFD = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        return;
    }
    ifr.ifr_flags = IFF_UP;
    if(ioctl(CtrlFD, SIOCSIFFLAGS, &ifr) < 0){
        close(CtrlFD);
        close(FrameFD);
    }

    // 设定覆盖网络地址
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = address;
    memcpy(&ifr.ifr_addr, &sa, sizeof(struct sockaddr_in));
    if(ioctl(CtrlFD, SIOCSIFADDR, &ifr) < 0){
        close(CtrlFD);
        close(FrameFD);
    }

    up = true;
}

OnivAdapter::~OnivAdapter()
{
    close(CtrlFD);
    close(FrameFD);
}

OnivErr OnivAdapter::send()
{
    OnivFrame of;
    while(1){
        sq.dequeue(of);
        if(of.empty()){
            break;
        }
        write(handle(), of.data(), of.size());
    }

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr OnivAdapter::send(const OnivFrame &frame)
{
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr OnivAdapter::recv(OnivFrame &frame)
{
    char buf[mtu] = { 0 };
    size_t FrameSize;
    FrameSize = read(handle(), buf, mtu);
    if(FrameSize < 0){
        return OnivErr(OnivErrCode::ERROR_RECV_ADAPTER);
    }
    frame = OnivFrame(buf, FrameSize, this);

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

int OnivAdapter::handle() const
{
    return FrameFD;
}

bool OnivAdapter::IsUp() const
{
    return up;
}

const string OnivAdapter::name() const
{
    return AdapterName;
}
