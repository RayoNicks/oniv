#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

int CreateTap(const char* DevName, const char* IPAddress)
{
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0){
        err(EXIT_FAILURE, "open() %s failed", DevName);
    }
    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, DevName, strlen(DevName));
    if(ioctl(fd, TUNSETIFF, &ifr) < 0){
        err(EXIT_FAILURE, "ioctl() %s failed", DevName);
    };
    // up
    int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udpfd < 0){
        err(EXIT_FAILURE, "socket() failed");
    }
    // memset(&ifr, 0, sizeof(struct ifreq));
    // strncpy(ifr.ifr_name, "oniv0", sizeof("oniv0"));
    ifr.ifr_flags = IFF_UP;
    if(ioctl(udpfd, SIOCSIFFLAGS, &ifr) < 0){
        err(EXIT_FAILURE, "ioctl() up failed");
    }
    // address
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(IPAddress);
    memcpy(&ifr.ifr_addr, &sa, sizeof(struct sockaddr_in));
    if(ioctl(udpfd, SIOCSIFADDR, &ifr) < 0){
        err(EXIT_FAILURE, "ioctl() address failed");
    }
    return fd;
}

int GetTunnelAddress(const char* DevName)
{
    struct ifreq ifr;
    int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, DevName, strlen(DevName));
    if(ioctl(udpfd, SIOCGIFADDR, &ifr) < 0){
        err(EXIT_FAILURE, "ioctl() up failed");
    }
    printf("Device address is %s\n", inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
}

int main()
{
    // int fd1 = CreateTap("oniv0", "10.0.1.1");
    // int fd2 = CreateTap("oniv1", "10.0.2.1");
    int fd = GetTunnelAddress("wlp3s0");
    getchar();
    return 0;
}
