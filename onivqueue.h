#ifndef _ONIV_QUEUE_H_
#define _ONIV_QUEUE_H_

#include <mutex>
#include <queue>

#include <sys/eventfd.h>
#include <unistd.h>

#include "onivframe.h"

using std::mutex;
using std::queue;

class OnivQueue
{
private:
    queue<OnivFrame> df;
    mutex mtx;
    int event;
public:
    OnivQueue();
    OnivQueue(const OnivQueue &q) = delete;
    OnivQueue& operator=(const OnivQueue &q) = delete;
    ~OnivQueue();
    void enqueue(const OnivFrame &of);
    void dequeue(OnivFrame &of);
    int EventHandle() const;
};

#endif
