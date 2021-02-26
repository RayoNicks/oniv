#include "onivfdb.h"

const OnivForwardingEntry* OnivFDB::search(const OnivFrame &frame)
{
    OnivForwardingEntry ent(frame.DestHwAddr(), nullptr);
    auto iter = ForwardingTable.find(ent);
    if(iter != ForwardingTable.end()){
        return &(*iter);
    }
    else{
        return nullptr;
    }
}

void OnivFDB::update(const OnivFrame &frame)
{
    OnivForwardingEntry ent(frame.SrcHwAddr(), frame.IngressPort());

    mtx.lock();
    auto iter = ForwardingTable.find(ent);
    if(iter != ForwardingTable.end()){
        ForwardingTable.erase(iter);
    }
    ForwardingTable.insert(ent);
    mtx.unlock();
}

const OnivKeyEntry* OnivKDB::SearchTo(const OnivFrame &frame)
{
    OnivKeyEntry ent(frame.DestHwAddr(), frame.DestIPAddr(), htons(OnivGlobal::TunnelPortNo),
                    string(), OnivKeyAgrAlg::NONE, string(), string(), string(),
                    OnivVerifyAlg::NONE, string());
    auto iter = KeyTable.find(ent);
    if(iter != KeyTable.end()){
        return &(*iter);
    }
    else{
        return nullptr;
    }
}

const OnivKeyEntry* OnivKDB::SearchFrom(const OnivFrame &frame)
{
    OnivKeyEntry ent(frame.SrcHwAddr(), frame.SrcIPAddr(), frame.SrcPort(), string(),
                    OnivKeyAgrAlg::NONE, string(), string(), string(),
                    OnivVerifyAlg::NONE, string());
    auto iter = KeyTable.find(ent);
    if(iter != KeyTable.end()){
        return &(*iter);
    }
    else{
        return nullptr;
    }
}

const OnivKeyEntry* OnivKDB::update(const OnivFrame &frame)
{
    OnivKeyEntry ent(frame.DestHwAddr(), frame.DestIPAddr(), htons(OnivGlobal::TunnelPortNo),
                    string(), OnivKeyAgrAlg::NONE, string(), string(), string(),
                    OnivVerifyAlg::NONE, string());
    mtx.lock();
    auto iter = KeyTable.find(ent);
    if(iter != KeyTable.end()){
        KeyTable.erase(iter);
    }
    auto ret = KeyTable.insert(ent);
    mtx.unlock();
    return &(*ret.first);
}

const OnivKeyEntry* OnivKDB::update(const OnivFrame &frame, const OnivLnkReq &req)
{
    OnivKeyEntry ent(frame.SrcHwAddr(), frame.SrcIPAddr(), frame.SrcPort(),
                        string((char*)req.common.UUID, sizeof(req.common.UUID)),
                        OnivKeyAgrAlg::NONE, string(), string(), string(),
                        OnivVerifyAlg::NONE, string());
    ent.VerifyAlg = static_cast<OnivVerifyAlg>(req.PreVerifyAlg);
    ent.KeyAgrAlg = static_cast<OnivKeyAgrAlg>(req.PreKeyAgrAlg);
    ent.LocalPriKey = OnivCrypto::GenPriKey(ent.KeyAgrAlg);
    ent.LocalPubKey = OnivCrypto::GenPubKey(ent.KeyAgrAlg, ent.LocalPriKey);

    mtx.lock();
    auto iter = KeyTable.find(ent);
    if(iter != KeyTable.end()){
        KeyTable.erase(iter);
    }
    auto ret = KeyTable.insert(ent);
    mtx.unlock();
    if(ret.second){
        return &(*ret.first);
    }
    else{
        return nullptr;
    }
}

const OnivKeyEntry* OnivKDB::update(const OnivFrame &frame, const OnivLnkRes &res)
{
    OnivKeyEntry ent(frame.SrcHwAddr(), frame.SrcIPAddr(), frame.SrcPort(),
                        string((char*)res.common.UUID, sizeof(res.common.UUID)),
                        static_cast<OnivKeyAgrAlg>(res.KeyAgrAlg), res.pk,
                        string(), string(),
                        static_cast<OnivVerifyAlg>(res.VerifyAlg), string());
    ent.LocalPriKey = OnivCrypto::GenPriKey(ent.KeyAgrAlg);
    ent.LocalPubKey = OnivCrypto::GenPubKey(ent.KeyAgrAlg, ent.LocalPriKey);
    ent.LnkSK = OnivCrypto::ComputeSessionKey(ent.KeyAgrAlg, ent.RemotePubKey, ent.LocalPriKey);
    ent.UpdPk = true;
    ent.AckPk = false;

    mtx.lock();
    auto iter = KeyTable.find(ent);
    if(iter != KeyTable.end()){
        KeyTable.erase(iter);
    }
    auto ret = KeyTable.insert(ent);
    mtx.unlock();
    if(ret.second){
        return &(*ret.first);
    }
    else{
        return nullptr;
    }
}
