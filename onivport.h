#ifndef _ONIV_PORT_H_
#define _ONIV_PORT_H_

// #include <arpa/inet.h>
#include <sys/eventfd.h>

#include "oniverr.h"
#include "onivqueue.h"

class OnivFrame;

class OnivPort
{
protected:
    int mtu;
    uint32_t vni;
    OnivSendingQueue sq;
    int event;
    mutex mtx;
public:
    OnivPort(const int mtu, const uint32_t vni);
    OnivPort() = delete;
    OnivPort(const OnivPort &port) = delete;
    OnivPort& operator=(const OnivPort &port) = delete;
    virtual ~OnivPort();
    virtual OnivErr send() = 0;
    uint32_t BroadcastDomain() const;
    int MTU() const;
    void EnSendingQueue(const OnivFrame &frame);
    void EnSendingQueue(const vector<OnivFrame> &frames);
    void NotifySendingQueue();
    void BlockSendingQueue();
    int EventHandle() const;
};

#endif
