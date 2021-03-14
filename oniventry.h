#ifndef _ONIV_ENTRY_H_
#define _ONIV_ENTRY_H_

#include <functional>
#include <list>
#include <mutex>
#include <string>

#include <netinet/in.h>

#include "oniv.h"
#include "onivcrypto.h"
#include "onivframe.h"
#include "onivport.h"

using std::equal_to;
using std::hash;
using std::list;
using std::make_pair;
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
    void UpdatePublibKey(const string &pk, uint64_t UpdTs);
    void UpdateAcknowledge(uint64_t AckTs);
public:
    in_addr_t RemoteAddress;
    in_port_t RemotePort;
    string RemoteUUID, RemotePubKey, LocalPriKey, LocalPubKey, SessionKey, ThirdCert;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    bool UpdPk, AckPk;
    uint64_t ts;
    OnivKeyEntry();
    OnivKeyEntry(const OnivKeyEntry &keyent);
    OnivKeyEntry& operator=(const OnivKeyEntry &keyent);
    void lock();
    void unlock();
    void UpdateOnSend();
    void UpdateOnRecvLnkRec(const OnivLnkRecord &record);
    void UpdateOnRecvTunRec(const OnivTunRecord &record);
};

struct OnivFragementEntry
{
private:
    char *buffer, *oniv;
    size_t FrameSize;
    list<pair<unsigned int, unsigned int>> unreached;
    bool reassemble(uint16_t offset, uint16_t len);
public:
    string RemoteUUID;
    OnivFragementEntry(const OnivFrame &frame, const OnivCommon &common, const string &RemoteUUID);
    ~OnivFragementEntry();
    void AddFragement(const OnivFrame &frame, const OnivCommon &common);
    bool completed();
    const char* OnivHdr();
    size_t size();
};

#endif
