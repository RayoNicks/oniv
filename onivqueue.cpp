#include "onivqueue.h"

OnivQueue::OnivQueue()
{
    event = eventfd(0, 0);
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
        eventfd_read(event, nullptr);
    }
    mtx.unlock();
}

int OnivQueue::EventHandle() const
{
    return event;
}
