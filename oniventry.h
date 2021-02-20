#ifndef _ONIV_ENTRY_H_
#define _ONIV_ENTRY_H_

#include <string>
#include <functional>

#include "onivport.h"

using std::equal_to;
using std::hash;
using std::string;

struct OnivEntry
{
    string HwAddr;
    // 第一种身份信息相关字段
    OnivPort* egress;
    OnivEntry(const string &HwAddr, OnivPort *egress);
    OnivEntry(const OnivEntry &ent);
    OnivEntry& operator=(const OnivEntry &ent);
    const string MAC() const;
};

namespace std{
    template<> class hash<OnivEntry>
    {
    public:
        size_t operator()(const OnivEntry &ent) const noexcept
        {
            return hash<string>()(ent.HwAddr);
        }
    };
    template<> class equal_to<OnivEntry>
    {
    public:
        bool operator()(const OnivEntry &e1, const OnivEntry &e2) const
        {
            return equal_to<string>()(e1.HwAddr, e2.HwAddr);
        }
    };
}

#endif
