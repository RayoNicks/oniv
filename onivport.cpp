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
    eventfd_write(event, 1);
}

void OnivPort::BlockSendingQueue()
{
    eventfd_read(event, nullptr);
}

int OnivPort::EventHandle() const
{
    return event;
}
