#ifndef _ONIVD_H_
#define _ONIVD_H_

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <list>
#include <map>
#include <string>

#include <arpa/inet.h>
#include <asm-generic/errno.h>
#include <linux/un.h>
#include <net/route.h>
#include <pthread.h>
#include <sys/epoll.h>

#include "onivadapter.h"
#include "onivcmd.h"
#include "oniverr.h"
#include "onivfdb.h"
#include "onivframe.h"
#include "onivglobal.h"
#include "onivpacket.h"
#include "onivport.h"
#include "onivtunnel.h"

using std::find_if;
using std::list;
using std::make_pair;
using std::map;
using std::pair;
using std::string;

class Onivd
{
private:
    pthread_t ServerThreadID, AdapterThreadID, TunnelThreadID, EgressThreadID;
    int ListenSocket, EpollAdapter, EpollTunnel, EpollEgress;
    OnivFDB fdb;

    typedef list<OnivAdapter>::iterator AdapterIter;
    list<OnivAdapter> adapters;

    typedef list<OnivTunnel>::iterator TunnelIter;
    list<OnivTunnel> tunnels; // 第一个隧道类似listen()，其余隧道类似accept()

    static void* SwitchServerThread(void *para);
    static void* AdapterThread(void *para);
    static void* TunnelThread(void *para);
    static void* EgressThread(void *para);
    
    // server线程使用的函数
    OnivErr CreateSwitchServerSocket(const string &ControllerSocketPath);

    OnivErr AuxAddAdapter(const string &name, in_addr_t address, in_addr_t mask, uint32_t vni, int mtu);
    OnivErr AddAdapter(const char *cmd, size_t length);
    OnivErr DelAdapter(const char *cmd, size_t length);
    OnivErr ClrAdapter();

    OnivErr AuxAddTunnel(in_addr_t address, in_port_t PortNo, uint32_t vni, int mtu);
    OnivErr AddTunnel(const char *cmd, size_t length);
    OnivErr DelTunnel(const char *cmd, size_t length);
    OnivErr ClrTunnel();

    OnivErr ManipulateRoute(in_addr_t dest, in_addr_t mask, in_addr_t gateway, const string &name);
    OnivErr AddRoute(const char *cmd, size_t length);
    OnivErr DelRoute(const char *cmd, size_t length);

    OnivErr ProcessCommand(const char *cmd, size_t length);

    // 隧道接收线程使用的函数
    OnivErr ProcessTunKeyAgrReq(const OnivPacket &packet);
    OnivErr ProcessTunKeyAgrRes(const OnivPacket &packet);
    OnivErr ProcessRecord(OnivPacket &packet);

    OnivErr CreateSwitchServer();
    OnivErr CreateAdapterThread();
    OnivErr CreateTunnelThread(const string &TunnelAdapterName);
    OnivErr CreateEgressThread();
public:
    Onivd(const string &TunnelAdapterName);
    void run();
};

#endif
