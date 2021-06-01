#ifndef _ONIV_PORT_H_
#define _ONIV_PORT_H_

#include <mutex>
#include <vector>

#include "oniverr.h"
#include "onivqueue.h"

class OnivFrame;

class OnivPort
{
protected:
    int mtu;
    uint32_t bdi;
    OnivSendingQueue sq;
    int event;
    std::mutex mtx;
public:
    OnivPort(const int mtu, const uint32_t bdi);
    OnivPort() = delete;
    OnivPort(const OnivPort &port) = delete;
    OnivPort& operator=(const OnivPort &port) = delete;
    virtual ~OnivPort();
    virtual OnivErr send() = 0;
    uint32_t BroadcastDomain() const;
    int MTU() const;
    void EnSendingQueue(const OnivFrame &frame);
    void EnSendingQueue(const std::vector<OnivFrame> &frames);
    void NotifySendingQueue();
    void BlockSendingQueue();
    int EventHandle() const;
};

#endif
