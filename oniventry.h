#ifndef _ONIV_ENTRY_H_
#define _ONIV_ENTRY_H_

#include <string>
#include <functional>

#include "onivcrypto.h"
#include "onivport.h"

using std::equal_to;
using std::hash;
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
    // 可以不保存HwAddr
    string HwAddr, RemoteUUID, RemotePubKey, LocalPriKey, LocalPubKey, SessionKey;
    in_addr_t address;
    in_port_t PortNo;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    bool UpdPk, AckPk;
    uint64_t ts;
    OnivKeyEntry();
    OnivKeyEntry(const string &HwAddr, in_addr_t address, in_port_t port, const string &RemoteUUID,
                    OnivKeyAgrAlg KeyAgrAlg, const string &RemotePubKey,
                    const string &LocalPriKey, const string &LocalPubKey,
                    OnivVerifyAlg VerifyAlg, const string &LnkSK);
    OnivKeyEntry(const OnivKeyEntry &keyent);
    OnivKeyEntry& operator=(const OnivKeyEntry &keyent);
};

namespace std{
    template<> class hash<OnivKeyEntry>
    {
    public:
        size_t operator()(const OnivKeyEntry &ent) const noexcept
        {
            return hash<string>()(ent.HwAddr) + ent.address;
        }
    };
    template<> class equal_to<OnivKeyEntry>
    {
    public:
        bool operator()(const OnivKeyEntry &e1, const OnivKeyEntry &e2) const
        {
            return equal_to<string>()(e1.HwAddr, e2.HwAddr) &&
                equal_to<in_addr_t>()(e1.address, e2.address);
        }
    };
}

#endif
