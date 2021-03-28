#ifndef _ONIVD_H_
#define _ONIVD_H_

#include <algorithm>
#include <cstring>
#include <list>
#include <string>

#include <err.h>
#include <linux/un.h>
#include <net/route.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "onivadapter.h"
#include "onivcmd.h"
#include "oniverr.h"
#include "onivdb.h"
#include "onivfirst.h"
#include "onivframe.h"
#include "onivglobal.h"
#include "onivpacket.h"
#include "onivsecond.h"
#include "onivtunnel.h"

using std::list;
using std::string;

class Onivd
{
private:
    pthread_t ServerThreadID, AdapterThreadID, TunnelThreadID, EgressThreadID;
    int ListenSocket, EpollAdapter, EpollTunnel, EpollEgress;
    OnivFDB fdb;
    OnivKDB kdb;
    OnivRDB rdb;

    OnivBlockingQueue bq;

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

    OnivErr AuxAddAdapter(const string &name, in_addr_t address, in_addr_t mask, uint32_t bdi, int mtu);
    OnivErr AddAdapter(const char *cmd, size_t length);
    OnivErr DelAdapter(const char *cmd, size_t length);
    OnivErr ClrAdapter();

    OnivErr AuxAddTunnel(in_addr_t address, in_port_t PortNo, uint32_t bdi, int mtu);
    OnivErr AddTunnel(const char *cmd, size_t length);
    OnivErr DelTunnel(const char *cmd, size_t length);
    OnivErr ClrTunnel();

    OnivErr ManipulateRoute(in_addr_t dest, in_addr_t mask, in_addr_t gateway, const string &name);
    OnivErr AddRoute(const char *cmd, size_t length);
    OnivErr DelRoute(const char *cmd, size_t length);

    OnivErr ProcessCommand(const char *cmd, size_t length);

    OnivErr ProcessBroadcast(OnivFrame &frame);

    OnivErr ProcessLnkForwarding(OnivFrame &frame);
    OnivErr ProcessLnkEncapusulation(OnivFrame &frame);

    OnivErr ProcessTunnelForwarding(OnivPacket &packet);
    OnivErr ProcessTunnelDecapusulation(OnivPacket &packet);

    OnivErr ProcessTunKeyAgrReq(OnivPacket &packet);
    OnivErr ProcessTunKeyAgrRes(OnivPacket &packet);
    OnivErr ProcessTunRecord(OnivPacket &packet);

    OnivErr ProcessLnkDecapusulation(OnivFrame &frame);
    OnivErr ProcessLnkKeyAgrReq(OnivFrame &frame);
    OnivErr ProcessLnkKeyAgrRes(OnivFrame &frame);
    OnivErr ProcessLnkRecord(OnivFrame &frame);

    OnivErr CreateSwitchServer();
    OnivErr CreateAdapterThread();
    OnivErr CreateTunnelThread(const string &TunnelAdapterName);
    OnivErr CreateEgressThread();
public:
    Onivd(const string &TunnelAdapterName);
    ~Onivd();
    void run();
};

#endif
