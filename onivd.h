#ifndef _ONIVD_H_
#define _ONIVD_H_

#include <list>
#include <string>

#include <pthread.h>

#include "onivdb.h"
#include "oniverr.h"
#include "onivqueue.h"

class OnivAdapter;
class OnivMessage;
class OnivTunnel;

class Onivd
{
private:
    pthread_t ServerThreadID, AdapterThreadID, TunnelThreadID, EgressThreadID;
    int ListenSocket, EpollAdapter, EpollTunnel, EpollEgress;
    OnivFDB fdb;
    OnivKDB kdb;
    OnivRDB rdb;

    OnivBlockingQueue bq;

    typedef std::list<OnivAdapter>::iterator AdapterIter;
    std::list<OnivAdapter> adapters;

    typedef std::list<OnivTunnel>::iterator TunnelIter;
    std::list<OnivTunnel> tunnels; // 第一个隧道类似listen()，其余隧道类似accept()

    static void* SwitchServerThread(void *para);
    static void* AdapterThread(void *para);
    static void* TunnelThread(void *para);
    static void* EgressThread(void *para);
    
    // server线程使用的函数
    OnivErr CreateSwitchServerSocket(const std::string &ControllerSocketPath);

    OnivErr AuxAddAdapter(const std::string &name, in_addr_t address, in_addr_t mask, uint32_t bdi, int mtu);
    OnivErr AddAdapter(const char *cmd, size_t length);
    OnivErr DelAdapter(const char *cmd, size_t length);
    OnivErr ClrAdapter();

    OnivErr AuxAddTunnel(in_addr_t address, in_port_t PortNo, uint32_t bdi, int mtu);
    OnivErr AddTunnel(const char *cmd, size_t length);
    OnivErr DelTunnel(const char *cmd, size_t length);
    OnivErr ClrTunnel();

    OnivErr ManipulateRoute(in_addr_t dest, in_addr_t mask, in_addr_t gateway, const std::string &name);
    OnivErr AddRoute(const char *cmd, size_t length);
    OnivErr DelRoute(const char *cmd, size_t length);

    OnivErr ProcessCommand(const char *cmd, size_t length);

    OnivErr ProcessBroadcast(OnivFrame &frame);

    OnivErr ProcessLnkForwarding(OnivFrame &frame);
    OnivErr ProcessLnkEncapusulation(OnivFrame &frame);

    OnivErr ProcessTunnelForwarding(OnivMessage &message);
    OnivErr ProcessTunnelDecapusulation(OnivMessage &message);

    OnivErr ProcessTunKeyAgrReq(OnivMessage &message);
    OnivErr ProcessTunKeyAgrRes(OnivMessage &message);
    OnivErr ProcessTunRecord(OnivMessage &message);

    OnivErr ProcessLnkDecapusulation(OnivFrame &frame);
    OnivErr ProcessLnkKeyAgrReq(OnivFrame &frame);
    OnivErr ProcessLnkKeyAgrRes(OnivFrame &frame);
    OnivErr ProcessLnkRecord(OnivFrame &frame);

    OnivErr CreateSwitchServer();
    OnivErr CreateAdapterThread();
    OnivErr CreateTunnelThread(const std::string &TunnelAdapterName);
    OnivErr CreateEgressThread();
public:
    Onivd(const std::string &TunnelAdapterName);
    ~Onivd();
    void run();
};

#endif
