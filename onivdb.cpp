#include "onivdb.h"

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

OnivKeyEntry* OnivKDB::SearchTo(const OnivFrame &frame)
{
    OnivKeyEntry ent(frame.DestIPAddr(), htons(OnivGlobal::TunnelPortNo),
                    string(), OnivKeyAgrAlg::NONE, string(), string(), string(),
                    OnivVerifyAlg::NONE, string());
    auto iter = KeyTable.find(ent.RemoteAddress);
    if(iter != KeyTable.end()){
        return &iter->second;
    }
    else{
        return nullptr;
    }
}

OnivKeyEntry* OnivKDB::SearchFrom(const OnivFrame &frame)
{
    OnivKeyEntry ent(frame.SrcIPAddr(), frame.SrcPort(), string(),
                    OnivKeyAgrAlg::NONE, string(), string(), string(),
                    OnivVerifyAlg::NONE, string());
    auto iter = KeyTable.find(ent.RemoteAddress);
    if(iter != KeyTable.end()){
        return &iter->second;
    }
    else{
        return nullptr;
    }
}

OnivKeyEntry* OnivKDB::update(const OnivFrame &frame)
{
    OnivKeyEntry ent(frame.DestIPAddr(), htons(OnivGlobal::TunnelPortNo),
                    string(), OnivKeyAgrAlg::NONE, string(), string(), string(),
                    OnivVerifyAlg::NONE, string());
    mtx.lock();
    KeyTable.erase(ent.RemoteAddress);
    auto ret = KeyTable.insert(make_pair(ent.RemoteAddress, ent));
    mtx.unlock();
    if(ret.second){
        return &ret.first->second;
    }
    else{
        return nullptr;
    }
}

OnivKeyEntry* OnivKDB::update(const OnivFrame &frame, const OnivLnkReq &req)
{
    OnivKeyEntry ent(frame.SrcIPAddr(), frame.SrcPort(),
                        string((char*)req.common.UUID, sizeof(req.common.UUID)),
                        OnivKeyAgrAlg::NONE, string(), string(), string(),
                        OnivVerifyAlg::NONE, string());
    ent.VerifyAlg = OnivCrypto::SelectVerifyAlg(static_cast<OnivVerifyAlg>(req.PreVerifyAlg), static_cast<OnivVerifyAlg>(req.SupVerifyAlg));
    ent.KeyAgrAlg = OnivCrypto::SelectKeyAgrAlg(static_cast<OnivKeyAgrAlg>(req.PreKeyAgrAlg), static_cast<OnivKeyAgrAlg>(req.SupKeyAgrAlg));
    ent.LocalPriKey = OnivCrypto::GenPriKey(ent.KeyAgrAlg);
    ent.LocalPubKey = OnivCrypto::GenPubKey(ent.KeyAgrAlg, ent.LocalPriKey);

    mtx.lock();
    KeyTable.erase(ent.RemoteAddress);
    auto ret = KeyTable.insert(make_pair(ent.RemoteAddress, ent));
    mtx.unlock();
    if(ret.second){
        return &ret.first->second;
    }
    else{
        return nullptr;
    }
}

OnivKeyEntry* OnivKDB::update(const OnivFrame &frame, const OnivLnkRes &res)
{
    OnivKeyEntry ent(frame.SrcIPAddr(), frame.SrcPort(),
                        string((char*)res.common.UUID, sizeof(res.common.UUID)),
                        static_cast<OnivKeyAgrAlg>(res.KeyAgrAlg), res.pk,
                        string(), string(),
                        static_cast<OnivVerifyAlg>(res.VerifyAlg), string());
    ent.LocalPriKey = OnivCrypto::GenPriKey(ent.KeyAgrAlg);
    ent.LocalPubKey = OnivCrypto::GenPubKey(ent.KeyAgrAlg, ent.LocalPriKey);
    ent.SessionKey = OnivCrypto::ComputeSessionKey(ent.KeyAgrAlg, ent.RemotePubKey, ent.LocalPriKey);
    ent.UpdPk = true;
    ent.AckPk = false;

    mtx.lock();
    KeyTable.erase(ent.RemoteAddress);
    auto ret = KeyTable.insert(make_pair(ent.RemoteAddress, ent));
    mtx.unlock();
    if(ret.second){
        return &ret.first->second;
    }
    else{
        return nullptr;
    }
}
