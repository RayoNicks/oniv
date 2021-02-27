#include "onivport.h"
#include "onivframe.h"

OnivPort::OnivPort(int mtu, uint32_t vni) : mtu(mtu), vni(vni)
{
    event = eventfd(0, 0);
}

OnivPort::~OnivPort()
{
    close(event);
}

int OnivPort::MTU() const
{
    return mtu;
}

uint32_t OnivPort::BroadcastDomain() const
{
    return vni;
}

void OnivPort::EnSendingQueue(const OnivFrame &frame)
{
    sq.enqueue(frame);
    NotifySendingQueue();
}

void OnivPort::EnSendingQueue(const vector<OnivFrame> &frames)
{
    for(const OnivFrame &frame : frames)
    {
        sq.enqueue(frame);
    }
    NotifySendingQueue();
}

void OnivPort::NotifySendingQueue()
{
    mtx.lock();
    eventfd_write(event, 1);
    mtx.unlock();
}

void OnivPort::BlockSendingQueue()
{
    mtx.lock();
    eventfd_read(event, nullptr);
    mtx.unlock();
}

int OnivPort::EventHandle() const
{
    return event;
}
