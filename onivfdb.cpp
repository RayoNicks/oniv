#include "onivfdb.h"

const OnivEntry* OnivFDB::search(const OnivFrame &frame)
{
    OnivEntry ent(string(frame.DestHwAddr(), 6), nullptr);
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
    OnivEntry ent(string(frame.SrcHwAddr(), 6), frame.IngressPort());

    mtx.lock();
    auto iter = ForwardingTable.find(ent);
    if(iter != ForwardingTable.end()){
        ForwardingTable.erase(iter);
    }
    ForwardingTable.insert(ent);
    mtx.unlock();
}
