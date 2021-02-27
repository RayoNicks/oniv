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
}

OnivKeyEntry::OnivKeyEntry()
{

}

OnivKeyEntry::OnivKeyEntry(const string &HwAddr, in_addr_t address, in_port_t port, const string &RemoteUUID,
                            OnivKeyAgrAlg KeyAgrAlg, const string &RemotePubKey,
                            const string &LocalPriKey, const string &LocalPubKey,
                            OnivVerifyAlg VerifyAlg, const string &LnkSK)
    : HwAddr(HwAddr), RemoteUUID(RemoteUUID), RemotePubKey(RemotePubKey),
    LocalPriKey(LocalPriKey), LocalPubKey(LocalPubKey), SessionKey(LnkSK),
    address(address), PortNo(port), VerifyAlg(VerifyAlg), KeyAgrAlg(KeyAgrAlg),
    UpdPk(false), AckPk(false), ts(0)
    
{

}

OnivKeyEntry::OnivKeyEntry(const OnivKeyEntry &keyent)
    : HwAddr(keyent.HwAddr), RemoteUUID(keyent.RemoteUUID), RemotePubKey(keyent.RemotePubKey),
    LocalPriKey(keyent.LocalPriKey), LocalPubKey(keyent.LocalPubKey), SessionKey(keyent.SessionKey),
    address(keyent.address), VerifyAlg(keyent.VerifyAlg), KeyAgrAlg(keyent.KeyAgrAlg),
    UpdPk(false), AckPk(false), ts(0)
{

}

OnivKeyEntry& OnivKeyEntry::operator=(const OnivKeyEntry &keyent)
{
    HwAddr = keyent.HwAddr;
    RemoteUUID = keyent.RemoteUUID;
    RemotePubKey = keyent.RemotePubKey;
    LocalPriKey = keyent.LocalPriKey;
    LocalPubKey = keyent.LocalPubKey;
    SessionKey = keyent.SessionKey;
    address = keyent.address;
    VerifyAlg = keyent.VerifyAlg;
    KeyAgrAlg = keyent.KeyAgrAlg;
    UpdPk = keyent.UpdPk;
    AckPk = keyent.AckPk;
    ts = keyent.ts;
}
