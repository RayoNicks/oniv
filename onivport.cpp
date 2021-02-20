#include "onivport.h"
#include "onivframe.h"

OnivPort::OnivPort(int mtu, uint32_t vni, const OnivQueue &sq)
    : mtu(mtu), vni(vni)
{

}

OnivPort::~OnivPort()
{

}

int OnivPort::MTU() const
{
    return mtu;
}

uint32_t OnivPort::BroadcastID() const
{
    return vni;
}

void OnivPort::EnSendingQueue(const OnivFrame &of)
{
    return sq.enqueue(of);
}

int OnivPort::EventHandle() const
{
    return sq.EventHandle();
}
