#ifndef _ONIV_ENTRY_H_
#define _ONIV_ENTRY_H_

#include <chrono>
#include <functional>
#include <list>
#include <mutex>
#include <string>

#include <netinet/in.h>

#include "oniv.h"
#include "onivcrypto.h"
#include "onivfirst.h"
#include "onivframe.h"
#include "onivlog.h"
#include "onivport.h"
#include "onivsecond.h"

using std::chrono::system_clock;
using std::equal_to;
using std::hash;
using std::list;
using std::mutex;
using std::pair;
using std::string;

class OnivLnkRecord;
class OnivTunRecord;

struct OnivForwardingEntry
{
    string HwAddr;
    OnivPort *egress;
    OnivForwardingEntry(const string &HwAddr, OnivPort *egress);
    OnivForwardingEntry(const OnivForwardingEntry &forent);
    OnivForwardingEntry& operator=(const OnivForwardingEntry &forent);
};

namespace std{
    template<> class hash<OnivForwardingEntry>
    {
    public:
        size_t operator()(const OnivForwardingEntry &ent) const noexcept
        {
            return hash<string>()(ent.HwAddr);
        }
    };
    template<> class equal_to<OnivForwardingEntry>
    {
    public:
        bool operator()(const OnivForwardingEntry &e1, const OnivForwardingEntry &e2) const
        {
            return equal_to<string>()(e1.HwAddr, e2.HwAddr);
        }
    };
}

struct OnivKeyEntry
{
private:
    mutex mtx;
    void UpdatePublibKey(const string &pk, time_point<system_clock> UpdTp);
    void UpdateAcknowledge(time_point<system_clock> AckTp);
public:
    sockaddr_in RemoteAddress;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    string RemoteUUID, RemoteCert;
    string RemotePubKey, LocalPriKey, LocalPubKey, SessionKey;
    string ThirdCert;
    bool UpdPk, AckPk;
    time_point<system_clock> tp;
    OnivKeyEntry();
    OnivKeyEntry(const OnivKeyEntry &keyent);
    OnivKeyEntry& operator=(const OnivKeyEntry &keyent);
    void lock();
    void unlock();
    void UpdateOnSendLnkReq();
    void UpdateOnRecvLnkReq(const OnivLnkReq &req);
    void UpdateOnSendTunReq();
    void UpdateOnRecvTunReq(const OnivTunReq &req);
    void UpdateOnSendLnkRes();
    void UpdateOnRecvLnkRes(const OnivLnkRes &res);
    void UpdateOnSendTunRes();
    void UpdateOnRecvTunRes(const OnivTunRes &res);
    void UpdateOnSendLnkRec();
    void UpdateOnRecvLnkRec(const OnivLnkRecord &record);
    void UpdateOnSendTunRec();
    void UpdateOnRecvTunRec(const OnivTunRecord &record);
    void UpdateAddress(in_port_t port, in_addr_t address);
};

struct OnivFragementEntry
{
private:
    char *buffer, *fragment;
    size_t BufferSize;
    list<pair<unsigned short, unsigned short>> unreached;
    bool reassemble(uint16_t offset, uint16_t len);
public:
    string RemoteUUID;
    OnivFragementEntry(const OnivFrame &frame, const OnivLnkKA &lka, const string &RemoteUUID);
    OnivFragementEntry(const OnivFragementEntry &frgent);
    OnivFragementEntry& operator=(const OnivFragementEntry &frgent);
    ~OnivFragementEntry();
    void AddFragement(const OnivFrame &frame, const OnivLnkKA &lka);
    bool completed();
    const char* OnivHdr();
    size_t OnivSize();
};

#endif
