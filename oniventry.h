#ifndef _ONIV_ENTRY_H_
#define _ONIV_ENTRY_H_

#include <chrono>
#include <functional>
#include <list>
#include <mutex>
#include <string>

#include "oniv.h"

class OnivFrame;
class OnivLnkKA;
class OnivLnkReq;
class OnivLnkRes;
class OnivLnkRec;
class OnivPort;
class OnivTunReq;
class OnivTunRes;
class OnivTunRec;

struct OnivForwardingEntry
{
    std::string HwAddr;
    OnivPort *egress;
    OnivForwardingEntry(const std::string &HwAddr, OnivPort *egress);
    OnivForwardingEntry(const OnivForwardingEntry &forent);
    OnivForwardingEntry& operator=(const OnivForwardingEntry &forent);
};

namespace std{
    template<> class hash<OnivForwardingEntry>
    {
    public:
        size_t operator()(const OnivForwardingEntry &ent) const noexcept
        {
            return hash<std::string>()(ent.HwAddr);
        }
    };
    template<> class equal_to<OnivForwardingEntry>
    {
    public:
        bool operator()(const OnivForwardingEntry &e1, const OnivForwardingEntry &e2) const
        {
            return equal_to<std::string>()(e1.HwAddr, e2.HwAddr);
        }
    };
}

struct OnivKeyEntry
{
private:
    std::mutex mtx;
    void UpdatePublibKey(const std::string &pk, std::chrono::time_point<std::chrono::system_clock> UpdTp);
    void UpdateAcknowledge(std::chrono::time_point<std::chrono::system_clock> AckTp);
    void UpdateEscrow(const std::string &trustee);
public:
    sockaddr_in RemoteAddress;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    std::string RemoteUUID, RemoteCert;
    std::string RemotePubKey, LocalPriKey, LocalPubKey, SessionKey;
    std::string ThirdCert, EscrowData;
    bool UpdPk, AckPk;
    std::chrono::time_point<std::chrono::system_clock> tp;
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
    void UpdateOnRecvLnkRec(const OnivLnkRec &record);
    void UpdateOnSendTunRec();
    void UpdateOnRecvTunRec(const OnivTunRec &record);
    void UpdateAddress(in_port_t port, in_addr_t address);
};

struct OnivFragementEntry
{
private:
    char *buffer, *fragment;
    size_t BufferSize;
    std::list<std::pair<unsigned short, unsigned short>> unreached;
    bool reassemble(uint16_t offset, uint16_t len);
public:
    std::string RemoteUUID;
    OnivFragementEntry(const OnivFrame &frame, const OnivLnkKA &lka, const std::string &RemoteUUID);
    OnivFragementEntry(const OnivFragementEntry &frgent);
    OnivFragementEntry& operator=(const OnivFragementEntry &frgent);
    ~OnivFragementEntry();
    void AddFragement(const OnivFrame &frame, const OnivLnkKA &lka);
    bool completed();
    const char* OnivHdr();
    size_t OnivSize();
};

#endif
