#ifndef _ONIV_QUEUE_H_
#define _ONIV_QUEUE_H_

#include <list>
#include <mutex>
#include <queue>
#include <vector>

#include "onivframe.h"

using std::list;
using std::mutex;
using std::queue;
using std::vector;

class OnivSendingQueue
{
private:
    queue<OnivFrame> qf;
    mutex mtx;
public:
    OnivSendingQueue();
    OnivSendingQueue(const OnivSendingQueue &q) = delete;
    OnivSendingQueue& operator=(const OnivSendingQueue &q) = delete;
    ~OnivSendingQueue();
    void enqueue(const OnivFrame &frame);
    void dequeue(OnivFrame &frame);
};

class OnivBlockingQueue
{
private:
    list<OnivFrame> lf;
    mutex mtx;
public:
    OnivBlockingQueue();
    OnivBlockingQueue(const OnivBlockingQueue &q) = delete;
    OnivBlockingQueue& operator=(const OnivBlockingQueue &q) = delete;
    ~OnivBlockingQueue();
    void enqueue(const OnivFrame &frame);
    vector<OnivFrame> ConditionDequeue(in_addr_t address);
};

#endif
