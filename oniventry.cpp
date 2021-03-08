#include "oniventry.h"
#include "onivfirst.h"
#include "onivsecond.h"

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

void OnivKeyEntry::UpdatePublibKey(const string &pk, uint64_t UpdTs)
{
    lock();
    RemotePubKey = pk;
    SessionKey = OnivCrypto::ComputeSessionKey(KeyAgrAlg, RemotePubKey, LocalPriKey);
    AckPk = true;
    ts = UpdTs;
    unlock();
}

void OnivKeyEntry::UpdateAcknowledge(uint64_t AckTs)
{
    lock();
    UpdPk = false;
    ts = AckTs;
    unlock();
}

OnivKeyEntry::OnivKeyEntry()
    : RemoteAddress(0), RemotePort(0),
    VerifyAlg(OnivVerifyAlg::NONE), KeyAgrAlg(OnivKeyAgrAlg::NONE),
    UpdPk(false), AckPk(false), ts(0)
{

}

OnivKeyEntry::OnivKeyEntry(const OnivKeyEntry &keyent)
    : RemoteAddress(keyent.RemoteAddress), RemotePort(keyent.RemotePort),
    RemoteUUID(keyent.RemoteUUID), RemotePubKey(keyent.RemotePubKey),
    LocalPriKey(keyent.LocalPriKey), LocalPubKey(keyent.LocalPubKey), SessionKey(keyent.SessionKey),
    ThirdName(keyent.ThirdName), VerifyAlg(keyent.VerifyAlg), KeyAgrAlg(keyent.KeyAgrAlg),
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
    ThirdName = keyent.ThirdName;
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

void OnivKeyEntry::UpdateOnSend()
{
    lock();
    AckPk = false;
    unlock();
}

void OnivKeyEntry::UpdateOnRecvLnkRec(const OnivLnkRecord &record)
{
    if(record.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND)){
        UpdatePublibKey(record.pk, record.UpdTs);
    }
    else if(record.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND)){
        UpdateAcknowledge(record.AckTs);
    }
    ThirdName = record.trustee;
}

void OnivKeyEntry::UpdateOnRecvTunRec(const OnivTunRecord &record)
{
    if(record.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND)){
        UpdatePublibKey(record.pk, record.UpdTs);
    }
    else if(record.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND)){
        UpdateAcknowledge(record.AckTs);
    }
}
