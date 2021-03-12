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

OnivKeyEntry* OnivKDB::SearchTo(in_addr_t DestAddr)
{
    for(auto iter = KeyTable.begin(); iter != KeyTable.end(); iter++)
    {
        if(iter->second.RemoteAddress == DestAddr){
            return &iter->second;
        }
    }
    return nullptr;
}

OnivKeyEntry* OnivKDB::SearchFrom(const string &RemoteUUID)
{
    auto iter = KeyTable.find(RemoteUUID);
    if(iter != KeyTable.end()){
        return &iter->second;
    }
    else{
        return nullptr;
    }
}

OnivKeyEntry* OnivKDB::update(const OnivFrame &frame, const OnivLnkReq &req)
{
    OnivKeyEntry ent;
    ent.RemoteAddress = frame.SrcIPAddr();
    ent.RemotePort = frame.SrcPort();
    ent.RemoteUUID.assign((char*)req.common.UUID, sizeof(req.common.UUID));
    ent.VerifyAlg = OnivCrypto::SelectVerifyAlg(req.PreVerifyAlg, req.SupVerifyAlgSet);
    ent.KeyAgrAlg = OnivCrypto::SelectKeyAgrAlg(req.PreKeyAgrAlg, req.SupKeyAgrAlgSet);
    ent.LocalPriKey = OnivCrypto::GenPriKey(ent.KeyAgrAlg);
    ent.LocalPubKey = OnivCrypto::GenPubKey(ent.KeyAgrAlg, ent.LocalPriKey);
    ent.ts = req.ts;

    mtx.lock();
    KeyTable.erase(ent.RemoteUUID);
    auto ret = KeyTable.insert(make_pair(ent.RemoteUUID, ent));
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
    OnivKeyEntry ent;
    ent.RemoteAddress = frame.SrcIPAddr();
    ent.RemotePort = frame.SrcPort();
    ent.RemoteUUID.assign((char*)res.common.UUID, sizeof(res.common.UUID));
    ent.VerifyAlg = res.VerifyAlg;
    ent.KeyAgrAlg = res.KeyAgrAlg;
    ent.RemotePubKey = res.pk.data();
    ent.LocalPriKey = OnivCrypto::GenPriKey(ent.KeyAgrAlg);
    ent.LocalPubKey = OnivCrypto::GenPubKey(ent.KeyAgrAlg, ent.LocalPriKey);
    ent.SessionKey = OnivCrypto::ComputeSessionKey(ent.KeyAgrAlg, ent.RemotePubKey, ent.LocalPriKey);
    ent.ThirdName = OnivCrypto::SelectThirdParty(res.RmdTp, res.AppTp);
    ent.UpdPk = true;
    ent.AckPk = false;
    ent.ts = res.ResTs;

    mtx.lock();
    KeyTable.erase(ent.RemoteUUID);
    auto ret = KeyTable.insert(make_pair(ent.RemoteUUID, ent));
    mtx.unlock();
    if(ret.second){
        return &ret.first->second;
    }
    else{
        return nullptr;
    }
}
