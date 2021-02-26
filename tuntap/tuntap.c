#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

int CreateTap(const char *name, const char *addr, const char *mask)
{
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0){
        err(EXIT_FAILURE, "open() %s failed", name);
    }
    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, strlen(name));
    if(ioctl(fd, TUNSETIFF, &ifr) < 0){
        err(EXIT_FAILURE, "ioctl() %s failed", name);
    };
    // up
    int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udpfd < 0){
        err(EXIT_FAILURE, "socket() failed");
    }
    ifr.ifr_flags = IFF_UP;
    if(ioctl(udpfd, SIOCSIFFLAGS, &ifr) < 0){
        err(EXIT_FAILURE, "ioctl() up failed");
    }
    // address
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(addr);
    memcpy(&ifr.ifr_addr, &sa, sizeof(struct sockaddr_in));
    if(ioctl(udpfd, SIOCSIFADDR, &ifr) < 0){
        err(EXIT_FAILURE, "ioctl() address failed");
    }
    // mask
    sa.sin_addr.s_addr = inet_addr(mask);
    memcpy(&ifr.ifr_netmask, &sa, sizeof(struct sockaddr_in));
    if(ioctl(udpfd, SIOCSIFNETMASK, &ifr) < 0){
        err(EXIT_FAILURE, "ioctl() mask failed");
    }
    return fd;
}

int GetTunnelAddress(const char *name)
{
    struct ifreq ifr;
    int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, name, strlen(name));
    if(ioctl(udpfd, SIOCGIFADDR, &ifr) < 0){
        err(EXIT_FAILURE, "ioctl() get address failed");
    }
    printf("Device address is %s\n", inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
}

void SetGateway(char *name, const char *addr, const char *mask, const char *gw)
{
    struct rtentry rt;
    struct sockaddr_in *sa;
    memset(&rt, 0, sizeof(struct rtentry));
    // 地址
    sa = (struct sockaddr_in*)&rt.rt_dst;
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = inet_addr(addr);
    // 掩码
    sa = (struct sockaddr_in*)&rt.rt_genmask;
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = inet_addr(mask);
    // 网关
    sa = (struct sockaddr_in*)&rt.rt_gateway;
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = inet_addr(gw);
    // 接口
    rt.rt_dev = name;
    // 启用路由
    rt.rt_flags = RTF_UP | RTF_GATEWAY;

    int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(udpfd, SIOCADDRT, &rt) < 0){
        err(EXIT_FAILURE, "ioctl() route failed");
    }
    return;
}

int main()
{
    // int fd1 = CreateTap("oniv0", "10.0.1.1");
    // int fd2 = CreateTap("oniv1", "10.0.2.1");
    // int fd3 = GetTunnelAddress("wlp3s0");
    int fd4 = CreateTap("oniv2", "172.16.1.11", "255.255.255.0");
    SetGateway("oniv2", "172.16.3.0", "255.255.255.0", "172.16.1.1");
    // SetGateway("oniv2", "0.0.0.0", "0.0.0.0", "172.16.1.1");
    getchar();
    return 0;
}
