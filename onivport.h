#ifndef _ONIV_PORT_H_
#define _ONIV_PORT_H_

// #include <arpa/inet.h>

#include "oniverr.h"
#include "onivqueue.h"

class OnivFrame;

class OnivPort
{
protected:
    int mtu;
    uint32_t vni;
    OnivQueue sq;
public:
    OnivPort(const int mtu, const uint32_t vni = 0, const OnivQueue &sq = OnivQueue());
    OnivPort(const OnivPort &port);
    OnivPort& operator=(const OnivPort &port);
    virtual ~OnivPort();
    virtual OnivErr send() = 0;
    virtual OnivErr send(const OnivFrame &of) = 0;
    virtual OnivErr recv(OnivFrame &of) = 0;
    uint32_t BroadcastID() const;
    int MTU() const;
    void EnSendingQueue(const OnivFrame &of);
    int EventHandle() const;
};

#endif
