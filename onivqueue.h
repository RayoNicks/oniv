#ifndef _ONIV_QUEUE_H_
#define _ONIV_QUEUE_H_

#include <list>
#include <mutex>
#include <queue>
#include <vector>

#include <netinet/in.h>

class OnivFrame;

class OnivSendingQueue
{
private:
    std::queue<OnivFrame> qf;
    std::mutex mtx;
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
    std::list<OnivFrame> lf;
    std::mutex mtx;
public:
    OnivBlockingQueue();
    OnivBlockingQueue(const OnivBlockingQueue &q) = delete;
    OnivBlockingQueue& operator=(const OnivBlockingQueue &q) = delete;
    ~OnivBlockingQueue();
    void enqueue(const OnivFrame &frame);
    std::vector<OnivFrame> ConditionDequeue(in_addr_t address);
};

#endif
