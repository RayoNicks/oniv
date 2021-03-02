#ifndef _ONIV_ENTRY_H_
#define _ONIV_ENTRY_H_

#include <mutex>
#include <functional>
#include <string>

#include <netinet/in.h>

#include "oniv.h"
#include "onivcrypto.h"
#include "onivport.h"

using std::equal_to;
using std::hash;
using std::mutex;
using std::string;

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
public:
    in_addr_t RemoteAddress;
    in_port_t RemotePort;
    string RemoteUUID, RemotePubKey, LocalPriKey, LocalPubKey, SessionKey;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    bool UpdPk, AckPk;
    uint64_t ts;
    OnivKeyEntry();
    OnivKeyEntry(in_addr_t address, in_port_t port, const string &RemoteUUID,
                    OnivKeyAgrAlg KeyAgrAlg, const string &RemotePubKey,
                    const string &LocalPriKey, const string &LocalPubKey,
                    OnivVerifyAlg VerifyAlg, const string &LnkSK);
    OnivKeyEntry(const OnivKeyEntry &keyent);
    OnivKeyEntry& operator=(const OnivKeyEntry &keyent);
    void lock();
    void unlock();
};

#endif
