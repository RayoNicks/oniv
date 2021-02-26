#ifndef _ONIV_QUEUE_H_
#define _ONIV_QUEUE_H_

#include <mutex>
#include <queue>

#include <unistd.h>

#include "onivframe.h"

using std::mutex;
using std::queue;

class OnivQueue
{
private:
    queue<OnivFrame> qf;
    mutex mtx;
public:
    OnivQueue();
    OnivQueue(const OnivQueue &q) = delete;
    OnivQueue& operator=(const OnivQueue &q) = delete;
    ~OnivQueue();
    void enqueue(const OnivFrame &frame);
    void dequeue(OnivFrame &frame);
};

#endif
