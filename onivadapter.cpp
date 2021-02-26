#include "onivadapter.h"

OnivAdapter::OnivAdapter(const string &name, in_addr_t address, in_addr_t mask, uint32_t vni, int mtu)
    : OnivPort(mtu, vni), fd(-1), ctrl(-1), AdapterName(name), addr(address), NetMask(mask)
{
    // 创建隧道设备
    struct ifreq ifr;
    if((fd = open("/dev/net/tun", O_RDWR)) < 0){
        return;
    }
    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
    if(ioctl(fd, TUNSETIFF, &ifr) < 0){
        close(fd);
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    if((ctrl = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        return;
    }
    
    // 设置地址
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = address;
    memcpy(&ifr.ifr_addr, &sa, sizeof(struct sockaddr_in));
    if(ioctl(ctrl, SIOCSIFADDR, &ifr) < 0){
        close(ctrl);
        close(fd);
    }

    // 设置掩码
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = mask;
    memcpy(&ifr.ifr_netmask, &sa, sizeof(struct sockaddr_in));
    if(ioctl(ctrl, SIOCSIFNETMASK, &ifr) < 0){
        close(ctrl);
        close(fd);
    }

    // 设置mtu
    ifr.ifr_mtu = mtu;
    if(ioctl(ctrl, SIOCSIFMTU, &ifr) < 0){
        close(ctrl);
        close(fd);
    }

    // 开启网卡
    ifr.ifr_flags = IFF_UP;
    if(ioctl(ctrl, SIOCSIFFLAGS, &ifr) < 0){
        close(ctrl);
        close(fd);
    }

    // 读取MAC地址
    if(ioctl(ctrl, SIOCGIFHWADDR, &ifr) < 0){
        close(ctrl);
        close(fd);
    }
    HwAddr.assign(ifr.ifr_hwaddr.sa_data, 6);

    up = true;
}

OnivAdapter::~OnivAdapter()
{
    close(ctrl);
    close(fd);
}

OnivErr OnivAdapter::send()
{
    OnivFrame frame;
    while(1){
        sq.dequeue(frame);
        if(frame.empty()){
            break;
        }
        write(handle(), frame.buffer(), frame.size());
    }

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr OnivAdapter::recv(OnivFrame &frame)
{
    // mtu一般不包含以太网帧头部，需要增加14字节的以太网头部大小
    char buf[mtu + OnivGlobal::AdapterExtraMTU] = { 0 };
    size_t FrameSize;
    FrameSize = read(handle(), buf, sizeof(buf));
    if(FrameSize < 0){
        return OnivErr(OnivErrCode::ERROR_RECV_ADAPTER);
    }
    frame = OnivFrame(buf, FrameSize, this);

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

int OnivAdapter::handle() const
{
    return fd;
}

bool OnivAdapter::IsUp() const
{
    return up;
}

const string OnivAdapter::name() const
{
    return AdapterName;
}

in_addr_t OnivAdapter::address() const
{
    return addr;
}

const string OnivAdapter::MAC() const
{
    return HwAddr;
}
