#include "onivqueue.h"

OnivQueue::OnivQueue()
{
    // event = eventfd(0, 0);
}

OnivQueue::~OnivQueue()
{
    // close(event);
}

void OnivQueue::enqueue(const OnivFrame &frame)
{
    mtx.lock();
    df.push(frame);
    mtx.unlock();
    // eventfd_write(event, 1);
}

void OnivQueue::dequeue(OnivFrame &frame)
{
    mtx.lock();
    if(!df.empty()){
        frame = df.front();
        df.pop();
    }
    else{
        frame = OnivFrame();
        // eventfd_read(event, nullptr);
    }
    mtx.unlock();
}

// int OnivQueue::EventHandle() const
// {
//     return event;
// }
