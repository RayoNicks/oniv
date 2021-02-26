#include "onivqueue.h"

OnivQueue::OnivQueue()
{

}

OnivQueue::~OnivQueue()
{

}

void OnivQueue::enqueue(const OnivFrame &frame)
{
    mtx.lock();
    qf.push(frame);
    mtx.unlock();
}

void OnivQueue::dequeue(OnivFrame &frame)
{
    mtx.lock();
    if(!qf.empty()){
        frame = qf.front();
        qf.pop();
    }
    else{
        frame = OnivFrame();
    }
    mtx.unlock();
}
