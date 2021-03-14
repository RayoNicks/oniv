#ifndef _ONIV_DB_H_
#define _ONIV_DB_H_

#include <unordered_map>
#include <unordered_set>

#include "oniventry.h"
#include "onivfirst.h"
#include "onivframe.h"

using std::unordered_map;
using std::unordered_set;

class OnivFDB
{
private:
    unordered_set<OnivForwardingEntry> ForwardingTable;
    mutex mtx;
public:
    OnivFDB() = default;
    const OnivForwardingEntry* search(const OnivFrame &frame);
    void update(const OnivFrame &frame);
};

class OnivKDB
{
private:
    unordered_map<string, OnivKeyEntry> KeyTable;
    mutex mtx;
public:
    OnivKDB() = default;
    OnivKeyEntry* SearchTo(in_addr_t DestAddr);
    OnivKeyEntry* SearchFrom(const string &RemoteUUID);
    OnivKeyEntry* update(const OnivFrame &frame, const OnivLnkReq &req);
    OnivKeyEntry* update(const OnivFrame &frame, const OnivLnkRes &res);
};

class OnivRDB
{
private:
    unordered_map<string, OnivFragementEntry> FragTable;
    mutex mtx;
public:
    OnivRDB() = default;
    OnivFragementEntry* AddFragement(const OnivFrame &frame);
    void RemoveFragement(OnivFragementEntry *fraent);
};

#endif
