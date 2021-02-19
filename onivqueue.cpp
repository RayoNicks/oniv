#include "onivqueue.h"

OnivQueue::OnivQueue()
{
    event = eventfd(0, 0);
}

OnivQueue::OnivQueue(const OnivQueue &q) : df(q.df)
{
    event = eventfd(0, 0);
}

OnivQueue& OnivQueue::operator=(const OnivQueue &q)
{
    df = q.df;
    event = eventfd(0, 0);
    return *this;
}

OnivQueue::~OnivQueue()
{
    close(event);
}

void OnivQueue::enqueue(const OnivFrame &of)
{
    mtx.lock();
    df.push(of);
    mtx.unlock();
    eventfd_write(event, 1);
}

void OnivQueue::dequeue(OnivFrame &of)
{
    mtx.lock();
    if(!df.empty()){
        of = df.front();
        df.pop();
    }
    else{
        of = OnivFrame();
    }
    mtx.unlock();
}

int OnivQueue::EventHandle() const
{
    return event;
}
