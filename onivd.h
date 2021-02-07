#ifndef _ONIVD_H_
#define _ONIVD_H_

#include <cstdio>
#include <cstring>
#include <deque>
// #include <list>
#include <string>

#include <arpa/inet.h>
#include <err.h>
#include <asm-generic/errno.h>
#include <linux/un.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "onivcmd.h"
#include "oniverr.h"
#include "onivglobal.h"

using std::deque;
using std::string;

class WorkerQueue
{
private:
    deque<int> ReadyFileDescriptor;
    pthread_mutex_t mtx;
    pthread_cond_t cond;
public:
    WorkerQueue()
    {
        pthread_mutex_init(&mtx, NULL);
        pthread_cond_init(&cond, NULL);
    }
    int lock()
    {
        return pthread_mutex_lock(&mtx);
    }
    int unlock()
    {
        return pthread_mutex_unlock(&mtx);
    }
    int signal()
    {
        return pthread_cond_signal(&cond);
    }
    int wait()
    {
        return pthread_cond_wait(&cond, &mtx);
    }
    int front()
    {
        return ReadyFileDescriptor.front();
    }
    void PushFront(int fd)
    {
        return ReadyFileDescriptor.push_front(fd);
    }
    void Dequeue()
    {
        return ReadyFileDescriptor.pop_front();
    }
    int back()
    {
        return ReadyFileDescriptor.back();
    }
    void Enqueue(int fd)
    {
        return ReadyFileDescriptor.push_back(fd);
    }
    void PopBack()
    {
        return ReadyFileDescriptor.pop_back();
    }
    bool IsEmpty()
    {
        return ReadyFileDescriptor.empty();
    }
};

class ThreadPool
{
    
};

class Onivd
{
private:
    WorkerQueue wq;
    pthread_t ServerThreadID;
    int ListenSocket, epfd;

    static void* OnivSwitcherServerThread(void* para);
    static void* Worker(void* para);
    OnivErr CreateSwitcherServerSocket(const string &ControllerSocketPath);
    OnivErr ProcessCommand(const char* CmdBuf, size_t BufSize);
    OnivErr CreateSwitcherServer();
    OnivErr CreateThreadPool();
public:
    Onivd();
    void DispatchIO();
};

#endif
