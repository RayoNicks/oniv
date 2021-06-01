#include "onivdb.h"

#include "onivfirst.h"
#include "onivframe.h"

using std::string;

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
        if(iter->second.RemoteAddress.sin_addr.s_addr == DestAddr){
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
    OnivKeyEntry keyent;
    keyent.RemoteAddress.sin_port = frame.SrcPort();
    keyent.RemoteAddress.sin_addr.s_addr = frame.SrcIPAddr();
    keyent.UpdateOnRecvLnkReq(req);

    mtx.lock();
    KeyTable.erase(keyent.RemoteUUID);
    auto ret = KeyTable.insert(make_pair(keyent.RemoteUUID, keyent));
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
    OnivKeyEntry keyent;
    keyent.RemoteAddress.sin_port = frame.SrcPort();
    keyent.RemoteAddress.sin_addr.s_addr = frame.SrcIPAddr();
    keyent.UpdateOnRecvLnkRes(res);

    mtx.lock();
    KeyTable.erase(keyent.RemoteUUID);
    auto ret = KeyTable.insert(make_pair(keyent.RemoteUUID, keyent));
    mtx.unlock();
    if(ret.second){
        return &ret.first->second;
    }
    else{
        return nullptr;
    }
}

OnivFragementEntry* OnivRDB::AddFragement(const OnivFrame &frame)
{
    string RemoteUUID;
    OnivLnkKA lka;
    lka.structuration((const uint8_t*)frame.OnivHdr());
    RemoteUUID.assign((char*)lka.common.UUID, sizeof(lka.common.UUID));
    mtx.lock();
    auto iter = FragTable.find(RemoteUUID);
    if(iter == FragTable.end()){
        auto ret = FragTable.insert(make_pair(RemoteUUID, OnivFragementEntry(frame, lka, RemoteUUID)));
        if(!ret.second){
            return nullptr;
        }
        iter = ret.first;
    }
    else{
        iter->second.AddFragement(frame, lka);
    }
    mtx.unlock();
    return &iter->second;
}

void OnivRDB::RemoveFragement(OnivFragementEntry *fraent)
{
    mtx.lock();
    FragTable.erase(fraent->RemoteUUID);
    mtx.unlock();
}
