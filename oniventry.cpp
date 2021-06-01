#include "oniventry.h"

#include <cstring>

#include "onivcrypto.h"
#include "onivfirst.h"
#include "onivframe.h"
#include "onivlog.h"
#include "onivsecond.h"

using std::chrono::system_clock;
using std::chrono::time_point;
using std::make_pair;
using std::string;

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

void OnivKeyEntry::UpdatePublibKey(const string &pk, time_point<system_clock> UpdTp)
{
    lock();
    RemotePubKey = pk;
    SessionKey = OnivCrypto::ComputeSessionKey(RemotePubKey, LocalPriKey);
    AckPk = true;
    tp = UpdTp;
    unlock();
}

void OnivKeyEntry::UpdateAcknowledge(time_point<system_clock> AckTp)
{
    lock();
    UpdPk = false;
    tp = AckTp;
    unlock();
}

void OnivKeyEntry::UpdateEscrow(const string &trustee)
{
    lock();
    ThirdCert = OnivCrypto::GetCertFromUUID(trustee);
    EscrowData = OnivCrypto::GenEscrowData(ThirdCert, SessionKey, string());
    unlock();
}

OnivKeyEntry::OnivKeyEntry()
    : VerifyAlg(OnivVerifyAlg::UNKNOWN), KeyAgrAlg(OnivKeyAgrAlg::UNKNOWN),
    UpdPk(false), AckPk(false)
{
    memset(&RemoteAddress, 0, sizeof(RemoteAddress));
    RemoteAddress.sin_family = AF_INET;
}

OnivKeyEntry::OnivKeyEntry(const OnivKeyEntry &keyent)
    : VerifyAlg(keyent.VerifyAlg), KeyAgrAlg(keyent.KeyAgrAlg),
    RemoteUUID(keyent.RemoteUUID), RemoteCert(keyent.RemoteCert),
    RemotePubKey(keyent.RemotePubKey), LocalPriKey(keyent.LocalPriKey),
    LocalPubKey(keyent.LocalPubKey), SessionKey(keyent.SessionKey),
    ThirdCert(keyent.ThirdCert), EscrowData(keyent.EscrowData),
    UpdPk(keyent.UpdPk), AckPk(keyent.AckPk), tp(keyent.tp)
{
    memcpy(&RemoteAddress, &keyent.RemoteAddress, sizeof(RemoteAddress));
}

OnivKeyEntry& OnivKeyEntry::operator=(const OnivKeyEntry &keyent)
{
    memcpy(&RemoteAddress, &keyent.RemoteAddress, sizeof(RemoteAddress));
    VerifyAlg = keyent.VerifyAlg;
    KeyAgrAlg = keyent.KeyAgrAlg;
    RemoteUUID = keyent.RemoteUUID;
    RemoteCert = keyent.RemoteCert;
    RemotePubKey = keyent.RemotePubKey;
    LocalPriKey = keyent.LocalPriKey;
    LocalPubKey = keyent.LocalPubKey;
    SessionKey = keyent.SessionKey;
    ThirdCert = keyent.ThirdCert;
    EscrowData = keyent.EscrowData;
    UpdPk = keyent.UpdPk;
    AckPk = keyent.AckPk;
    tp = keyent.tp;
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

void OnivKeyEntry::UpdateOnSendLnkReq()
{
    // Nothing to update
}

void OnivKeyEntry::UpdateOnRecvLnkReq(const OnivLnkReq &req)
{
    VerifyAlg = OnivCrypto::SelectAlg<OnivVerifyAlg>(req.PreVerifyAlg, req.SupVerifyAlgSet);
    KeyAgrAlg = OnivCrypto::SelectAlg<OnivKeyAgrAlg>(req.PreKeyAgrAlg, req.SupKeyAgrAlgSet);
    RemoteUUID.assign((char*)req.lka.common.UUID, sizeof(req.lka.common.UUID));
    RemoteCert = req.certs.CertChain.back();
    LocalPriKey = OnivCrypto::GenPriKey(KeyAgrAlg);
    LocalPubKey = OnivCrypto::GetPubKeyFromPriKey(LocalPriKey);
    tp = req.tp;
    OnivLog::LogLnkReq(*this);
}

void OnivKeyEntry::UpdateOnSendTunReq()
{
    // Nothing to update
}

void OnivKeyEntry::UpdateOnRecvTunReq(const OnivTunReq &req)
{
    lock();
    VerifyAlg = OnivCrypto::SelectAlg<OnivVerifyAlg>(req.PreVerifyAlg, req.SupVerifyAlgSet);
    KeyAgrAlg = OnivCrypto::SelectAlg<OnivKeyAgrAlg>(req.PreKeyAgrAlg, req.SupKeyAgrAlgSet);
    RemoteUUID.assign((char*)req.tc.common.UUID, sizeof(req.tc.common.UUID));
    RemoteCert = req.certs.CertChain.back();
    LocalPriKey = OnivCrypto::GenPriKey(KeyAgrAlg);
    LocalPubKey = OnivCrypto::GetPubKeyFromPriKey(LocalPriKey);
    tp = req.tp;
    unlock();
    OnivLog::LogTunReq(*this);
}

void OnivKeyEntry::UpdateOnSendLnkRes()
{
    // Nothing to update
}

void OnivKeyEntry::UpdateOnRecvLnkRes(const OnivLnkRes &res)
{
    lock();
    VerifyAlg = res.VerifyAlg;
    KeyAgrAlg = res.KeyAgrAlg;
    RemoteUUID.assign((char*)res.lka.common.UUID, sizeof(res.lka.common.UUID));
    RemoteCert = res.certs.CertChain.back();
    RemotePubKey = res.pk.data();
    LocalPriKey = OnivCrypto::GenPriKey(KeyAgrAlg);
    LocalPubKey = OnivCrypto::GetPubKeyFromPriKey(LocalPriKey);
    SessionKey = OnivCrypto::ComputeSessionKey(RemotePubKey, LocalPriKey);
    ThirdCert = OnivCrypto::SelectTrusteeCert(res.RmdTp, res.AppTp);
    EscrowData = OnivCrypto::GenEscrowData(ThirdCert, SessionKey, string());
    UpdPk = true;
    AckPk = false;
    tp = res.ReqTp; // 记录请求时间
    unlock();
    OnivLog::LogRes(*this, OnivKeyAgrType::LNK_KA);
}

void OnivKeyEntry::UpdateOnSendTunRes()
{
    // Nothing to update
}

void OnivKeyEntry::UpdateOnRecvTunRes(const OnivTunRes &res)
{
    lock();
    VerifyAlg = res.VerifyAlg;
    KeyAgrAlg = res.KeyAgrAlg;
    RemoteUUID.assign((char*)res.tc.common.UUID, sizeof(res.tc.common.UUID));
    RemoteCert = res.certs.CertChain.back();
    RemotePubKey = res.pk.data();
    LocalPriKey = OnivCrypto::GenPriKey(KeyAgrAlg);
    LocalPubKey = OnivCrypto::GetPubKeyFromPriKey(LocalPriKey);
    SessionKey = OnivCrypto::ComputeSessionKey(RemotePubKey, LocalPriKey);
    UpdPk = true;
    AckPk = false;
    tp = res.ReqTp; // 记录请求时间
    unlock();
    OnivLog::LogRes(*this, OnivKeyAgrType::TUN_KA);
}

void OnivKeyEntry::UpdateOnSendLnkRec()
{
    lock();
    if(UpdPk){
        OnivLog::LogUpd(*this, OnivKeyAgrType::LNK_KA);
    }
    
    if(AckPk){
        OnivLog::LogAck(*this, OnivKeyAgrType::LNK_KA);
        AckPk = false;
    }
    unlock();
}

void OnivKeyEntry::UpdateOnRecvLnkRec(const OnivLnkRec &record)
{
    if(record.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_PK)){
        UpdatePublibKey(record.pk.data(), record.UpdTp);
        UpdateEscrow(record.trustee.data());
        OnivLog::LogUpd(*this, OnivKeyAgrType::LNK_KA);
    }
    else if(record.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_PK)){
        UpdateAcknowledge(record.AckTp);
        OnivLog::LogAck(*this, OnivKeyAgrType::LNK_KA);
    }
}

void OnivKeyEntry::UpdateOnSendTunRec()
{
    lock();
    if(UpdPk){
        OnivLog::LogUpd(*this, OnivKeyAgrType::TUN_KA);
    }
    if(AckPk){
        OnivLog::LogAck(*this, OnivKeyAgrType::TUN_KA);
        AckPk = false;
    }
    unlock();
}

void OnivKeyEntry::UpdateOnRecvTunRec(const OnivTunRec &record)
{
    if(record.tc.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_PK)){
        UpdatePublibKey(record.pk.data(), record.UpdTp);
        OnivLog::LogUpd(*this, OnivKeyAgrType::TUN_KA);
    }
    else if(record.tc.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_PK)){
        UpdateAcknowledge(record.AckTp);
        OnivLog::LogAck(*this, OnivKeyAgrType::TUN_KA);
    }
}

void OnivKeyEntry::UpdateAddress(in_port_t port, in_addr_t address)
{
    RemoteAddress.sin_port = port;
    RemoteAddress.sin_addr.s_addr = address;
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
