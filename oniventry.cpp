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
    SessionKey = OnivCrypto::ComputeSessionKey(RemotePubKey, LocalPriKey);
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
    VerifyAlg(OnivVerifyAlg::UNKNOWN), KeyAgrAlg(OnivKeyAgrAlg::UNKNOWN),
    UpdPk(false), AckPk(false), ts(0)
{

}

OnivKeyEntry::OnivKeyEntry(const OnivKeyEntry &keyent)
    : RemoteAddress(keyent.RemoteAddress), RemotePort(keyent.RemotePort),
    RemoteUUID(keyent.RemoteUUID), RemotePubKey(keyent.RemotePubKey),
    LocalPriKey(keyent.LocalPriKey), LocalPubKey(keyent.LocalPubKey), SessionKey(keyent.SessionKey),
    ThirdCert(keyent.ThirdCert), VerifyAlg(keyent.VerifyAlg), KeyAgrAlg(keyent.KeyAgrAlg),
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
    ThirdCert = keyent.ThirdCert;
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
        UpdatePublibKey(record.pk.data(), record.UpdTs);
    }
    else if(record.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND)){
        UpdateAcknowledge(record.AckTs);
    }
    lock();
    ThirdCert = OnivCrypto::GetCertFromSubject(record.trustee.data());
    unlock();
}

void OnivKeyEntry::UpdateOnRecvTunRec(const OnivTunRecord &record)
{
    if(record.tc.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND)){
        UpdatePublibKey(record.pk.data(), record.UpdTs);
    }
    else if(record.tc.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND)){
        UpdateAcknowledge(record.AckTs);
    }
}

bool OnivFragementEntry::reassemble(uint16_t offset, uint16_t len)
{
    for(auto iter = unreached.begin(); iter != unreached.end(); iter++)
    {
        if(iter->first <= offset && offset + len <= iter->second){
            if(iter->first == offset){
                if(offset + len == iter->second){
                    unreached.erase(iter);
                }
                else{
                    iter->first = offset + len;
                }
            }
            else if(offset + len == iter->second){
                iter->second = offset;
            }
            else{
                unreached.insert(iter, make_pair(iter->first, offset));
                iter->first = offset + len;
            }
            return true;
        }
    }
    return false;
}

OnivFragementEntry::OnivFragementEntry(const OnivFrame &frame, const OnivLnkKA &lka, const string &RemoteUUID)
    : buffer(nullptr), fragment(nullptr), BufferSize(0), RemoteUUID(RemoteUUID)
{
    BufferSize = frame.OnivHdr() - frame.Layer2Hdr() + OnivLnkKA::LinearSize() + lka.total;
    buffer = new char[BufferSize];
    fragment = buffer + BufferSize - lka.total;
    memcpy(buffer, frame.Layer2Hdr(), BufferSize - lka.total);
    memcpy(fragment + lka.offset, frame.OnivHdr() + OnivLnkKA::LinearSize(), lka.FrgSize);
    unreached.push_back(make_pair(0, lka.total));
    reassemble(lka.offset, lka.FrgSize);
}

OnivFragementEntry::OnivFragementEntry(const OnivFragementEntry &frgent)
    : BufferSize(frgent.BufferSize), unreached(frgent.unreached), RemoteUUID(frgent.RemoteUUID)
{
    buffer = new char[BufferSize];
    fragment = buffer + (frgent.fragment - frgent.buffer);
    memcpy(buffer, frgent.buffer, BufferSize);
}

OnivFragementEntry& OnivFragementEntry::operator=(const OnivFragementEntry &frgent)
{
    BufferSize = frgent.BufferSize;
    unreached = frgent.unreached;
    RemoteUUID = frgent.RemoteUUID;
    buffer = new char[BufferSize];
    fragment = buffer + (frgent.fragment - frgent.buffer);
    memcpy(buffer, frgent.buffer, BufferSize);
    return *this;
}

OnivFragementEntry::~OnivFragementEntry()
{
    delete[] buffer;
}

void OnivFragementEntry::AddFragement(const OnivFrame &frame, const OnivLnkKA &lka)
{
    memcpy(buffer, frame.Layer2Hdr(), BufferSize - lka.total);
    if(reassemble(lka.offset, lka.FrgSize)){
        memcpy(fragment + lka.offset, frame.OnivHdr() + OnivLnkKA::LinearSize(), lka.FrgSize);
    }
}

bool OnivFragementEntry::completed()
{
    return unreached.empty();
}

const char* OnivFragementEntry::OnivHdr()
{
    return fragment - OnivLnkKA::LinearSize();
}

size_t OnivFragementEntry::OnivSize()
{
    return buffer + BufferSize - OnivHdr();
}
