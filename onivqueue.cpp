#include "onivqueue.h"

OnivSendingQueue::OnivSendingQueue()
{

}

OnivSendingQueue::~OnivSendingQueue()
{

}

void OnivSendingQueue::enqueue(const OnivFrame &frame)
{
    mtx.lock();
    qf.push(frame);
    mtx.unlock();
}

void OnivSendingQueue::dequeue(OnivFrame &frame)
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

OnivBlockingQueue::OnivBlockingQueue()
{

}

OnivBlockingQueue::~OnivBlockingQueue()
{

}

void OnivBlockingQueue::enqueue(const OnivFrame &frame)
{
    mtx.lock();
    lf.push_back(frame);
    mtx.unlock();
}

vector<OnivFrame> OnivBlockingQueue::ConditionDequeue(in_addr_t address)
{
    vector<OnivFrame> vf;
    mtx.lock();
    auto iter = lf.begin();
    while(iter != lf.end()){
        if(iter->DestIPAddr() == address){
            vf.push_back(*iter);
            iter = lf.erase(iter);
        }
        else{
            iter++;
        }
    }
    mtx.unlock();
    return vf;
}
