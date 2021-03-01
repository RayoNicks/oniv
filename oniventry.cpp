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

OnivKeyEntry::OnivKeyEntry(in_addr_t address, in_port_t port, const string &RemoteUUID,
                            OnivKeyAgrAlg KeyAgrAlg, const string &RemotePubKey,
                            const string &LocalPriKey, const string &LocalPubKey,
                            OnivVerifyAlg VerifyAlg, const string &LnkSK)
    : RemoteUUID(RemoteUUID), RemotePubKey(RemotePubKey),
    LocalPriKey(LocalPriKey), LocalPubKey(LocalPubKey), SessionKey(LnkSK),
    VerifyAlg(VerifyAlg), KeyAgrAlg(KeyAgrAlg)
{
    memset(&RemoteSocket, 0, sizeof(RemoteSocket));
    RemoteSocket.sin_family = AF_INET;
    RemoteSocket.sin_addr.s_addr = address;
    RemoteSocket.sin_port = port;
    UpdPk = false, AckPk = false, ts = 0;
}

OnivKeyEntry::OnivKeyEntry(const OnivKeyEntry &keyent)
    : RemoteUUID(keyent.RemoteUUID), RemotePubKey(keyent.RemotePubKey),
    LocalPriKey(keyent.LocalPriKey), LocalPubKey(keyent.LocalPubKey), SessionKey(keyent.SessionKey),
    VerifyAlg(keyent.VerifyAlg), KeyAgrAlg(keyent.KeyAgrAlg),
    UpdPk(keyent.UpdPk), AckPk(keyent.AckPk), ts(keyent.ts)
{
    memcpy(&RemoteSocket, &keyent.RemoteSocket, sizeof(RemoteSocket));
}

OnivKeyEntry& OnivKeyEntry::operator=(const OnivKeyEntry &keyent)
{
    memcpy(&RemoteSocket, &keyent.RemoteSocket, sizeof(RemoteSocket));
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
}
