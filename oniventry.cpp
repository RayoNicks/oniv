#include "oniventry.h"

OnivForwardingEntry::OnivForwardingEntry(const string &HwAddr, OnivPort *egress)
    : HwAddr(HwAddr), egress(egress)
{

}

OnivForwardingEntry::OnivForwardingEntry(const OnivForwardingEntry &forent)
    : HwAddr(forent.HwAddr), egress(forent.egress)
{

}

OnivForwardingEntry& OnivForwardingEntry::operator=(const OnivForwardingEntry &forent)
{
    HwAddr = forent.HwAddr;
    egress = forent.egress;
    return *this;
}

OnivKeyEntry::OnivKeyEntry()
    : RemoteAddress(0), RemotePort(0), VerifyAlg(OnivVerifyAlg::NONE), KeyAgrAlg(OnivKeyAgrAlg::NONE),
    UpdPk(false), AckPk(false), ts(0)
{

}

OnivKeyEntry::OnivKeyEntry(in_addr_t address, in_port_t port, const string &RemoteUUID,
                            OnivKeyAgrAlg KeyAgrAlg, const string &RemotePubKey,
                            const string &LocalPriKey, const string &LocalPubKey,
                            OnivVerifyAlg VerifyAlg, const string &LnkSK)
    : RemoteAddress(address), RemotePort(port), RemoteUUID(RemoteUUID), RemotePubKey(RemotePubKey),
    LocalPriKey(LocalPriKey), LocalPubKey(LocalPubKey), SessionKey(LnkSK),
    VerifyAlg(VerifyAlg), KeyAgrAlg(KeyAgrAlg), UpdPk(false), AckPk(false), ts(0)
{

}

OnivKeyEntry::OnivKeyEntry(const OnivKeyEntry &keyent)
    : RemoteAddress(keyent.RemoteAddress), RemotePort(keyent.RemotePort),
    RemoteUUID(keyent.RemoteUUID), RemotePubKey(keyent.RemotePubKey),
    LocalPriKey(keyent.LocalPriKey), LocalPubKey(keyent.LocalPubKey), SessionKey(keyent.SessionKey),
    VerifyAlg(keyent.VerifyAlg), KeyAgrAlg(keyent.KeyAgrAlg),
    UpdPk(keyent.UpdPk), AckPk(keyent.AckPk), ts(keyent.ts)
{

}

OnivKeyEntry& OnivKeyEntry::operator=(const OnivKeyEntry &keyent)
{
    RemoteAddress = keyent.RemoteAddress;
    RemotePort = keyent.RemotePort;
    RemoteUUID = keyent.RemoteUUID;
    RemotePubKey = keyent.RemotePubKey;
    LocalPriKey = keyent.LocalPriKey;
    LocalPubKey = keyent.LocalPubKey;
    SessionKey = keyent.SessionKey;
    VerifyAlg = keyent.VerifyAlg;
    KeyAgrAlg = keyent.KeyAgrAlg;
    UpdPk = keyent.UpdPk;
    AckPk = keyent.AckPk;
    ts = keyent.ts;
    return *this;
}

void OnivKeyEntry::lock()
{
    return mtx.lock();
}

void OnivKeyEntry::unlock()
{
    return mtx.unlock();
}
