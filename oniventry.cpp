#include "oniventry.h"

OnivEntry::OnivEntry(const string &HwAddr, OnivPort *egress) : HwAddr(HwAddr), egress(egress)
{

}

OnivEntry::OnivEntry(const OnivEntry &ent) : HwAddr(ent.HwAddr), egress(ent.egress)
{

}

OnivEntry& OnivEntry::operator=(const OnivEntry &ent)
{
    HwAddr = ent.HwAddr;
    egress = ent.egress;
}

const string OnivEntry::MAC() const
{
    return HwAddr;
}
