#ifndef _ONIV_FDB_H_
#define _ONIV_FDB_H_

#include <mutex>
#include <unordered_set>

#include "oniventry.h"
#include "onivframe.h"
#include "onivport.h"

using std::mutex;
using std::unordered_set;

class OnivFDB
{
private:
    unordered_set<OnivEntry> ForwardingTable;
    mutex mtx;
public:
    OnivFDB() = default;
    const OnivEntry* search(const OnivFrame &frame);
    void update(const OnivFrame &frame);
};

#endif
