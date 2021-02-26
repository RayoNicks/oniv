#ifndef _ONIV_FDB_H_
#define _ONIV_FDB_H_

#include <mutex>
#include <unordered_set>

#include "oniventry.h"
#include "onivfirst.h"
#include "onivframe.h"
#include "onivport.h"

using std::mutex;
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
    unordered_set<OnivKeyEntry> KeyTable;
    mutex mtx;
public:
    OnivKDB() = default;
    const OnivKeyEntry* SearchTo(const OnivFrame &frame);
    const OnivKeyEntry* SearchFrom(const OnivFrame &frame);
    const OnivKeyEntry* update(const OnivFrame &frame);
    const OnivKeyEntry* update(const OnivFrame &frame, const OnivLnkReq &req);
    const OnivKeyEntry* update(const OnivFrame &frame, const OnivLnkRes &res);
};

#endif
