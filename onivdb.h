#ifndef _ONIV_DB_H_
#define _ONIV_DB_H_

#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "oniventry.h"

class OnivFrame;
class OnivLnkReq;
class OnivLnkRes;

class OnivFDB
{
private:
    std::unordered_set<OnivForwardingEntry> ForwardingTable;
    std::mutex mtx;
public:
    OnivFDB() = default;
    const OnivForwardingEntry* search(const OnivFrame &frame);
    void update(const OnivFrame &frame);
};

class OnivKDB
{
private:
    std::unordered_map<std::string, OnivKeyEntry> KeyTable;
    std::mutex mtx;
public:
    OnivKDB() = default;
    OnivKeyEntry* SearchTo(in_addr_t DestAddr);
    OnivKeyEntry* SearchFrom(const std::string &RemoteUUID);
    OnivKeyEntry* update(const OnivFrame &frame, const OnivLnkReq &req);
    OnivKeyEntry* update(const OnivFrame &frame, const OnivLnkRes &res);
};

class OnivRDB
{
private:
    std::unordered_map<std::string, OnivFragementEntry> FragTable;
    std::mutex mtx;
public:
    OnivRDB() = default;
    OnivFragementEntry* AddFragement(const OnivFrame &frame);
    void RemoveFragement(OnivFragementEntry *fraent);
};

#endif
