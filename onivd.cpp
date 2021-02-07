#include "onivd.h"

void* Onivd::OnivSwitcherServerThread(void* para)
{
    Onivd* object = (Onivd*)para;
    OnivErr oe = object->CreateSwitcherServerSocket(OnivGlobal::SwitcherServerTmpPath);
    if(oe.occured()){
        err(EXIT_FAILURE, "%s", oe.ErrMsg().c_str());
    }
    while(1){
        int AcceptSocket, ReadNumber;
        char CmdBuf[OnivGlobal::SwitcherServerCmdBufSize] = { 0 };
        AcceptSocket = accept(object->ListenSocket, NULL, NULL);
        if(AcceptSocket == -1){
            err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_ACCEPT_CONTROLLER_CONNECTION).ErrMsg().c_str());
        }
        if((ReadNumber = read(AcceptSocket, CmdBuf, sizeof(CmdBuf))) > 0){
            oe = object->ProcessCommand(CmdBuf, ReadNumber);
            if(oe.occured()){

            }
        }
        else{
            warn("%s", OnivErr(OnivErrCode::ERROR_READ_CONTROLLER_CMD).ErrMsg().c_str());
        }
        // if(shutdown(AcceptSocket, SHUT_RDWR) == -1){
        //     warn("Shutdown accepting socket failed");
        // }
        if(close(AcceptSocket) == -1){
            warn("%s", OnivErr(OnivErrCode::ERROR_CLOSE_CONTROLLER_CONNECTION).ErrMsg().c_str());
        }
    }
}

void* Onivd::Worker(void* para)
{
    Onivd* object = (Onivd*)para;
    while(1){
        int fd, ret;
        char FrameBuffer[OnivGlobal::OverlayNetworkMTU] = { 0 };
        object->wq.lock();
        while(object->wq.IsEmpty()){
            object->wq.wait();
        }
        fd = object->wq.front();
        object->wq.Dequeue();
        object->wq.unlock();
        // 处理数据包
        ret = read(fd, FrameBuffer, OnivGlobal::OverlayNetworkMTU);
        if(ret <= 0){
            continue;
        }

    }
    
}

OnivErr Onivd::CreateSwitcherServerSocket(const string &SwitcherServerSocketPath)
{
    struct sockaddr_un ServerAddress;

    if((ListenSocket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
        return OnivErr(OnivErrCode::ERROR_CREATE_SERVER_SOCKET);
    }

    if(remove(SwitcherServerSocketPath.c_str()) == -1 && errno != ENOENT){
        return OnivErr(OnivErrCode::ERROR_REMOVE_SERVER_SOCKET);
    }

    memset(&ServerAddress, 0, sizeof(struct sockaddr_un));
    ServerAddress.sun_family = AF_UNIX;
    strncpy(ServerAddress.sun_path, SwitcherServerSocketPath.c_str(), UNIX_PATH_MAX - 1);

    if(bind(ListenSocket, (const struct sockaddr*)&ServerAddress, sizeof(struct sockaddr_un)) == -1){
        return OnivErr(OnivErrCode::ERROR_BIND_SERVER_SOCKET);
    }

    if(listen(ListenSocket, 1) == -1){
        return OnivErr(OnivErrCode::ERROR_LISTEN_SERVER_SOCKET);
    }

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::ProcessCommand(const char* CmdBuf, size_t BufSize)
{
    printf("BufSize=%ld\n", BufSize);
    u_int8_t cmd = *CmdBuf, len;
    OnivErr ParseCmdError(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    switch(cmd)
    {
    case COMMAND_ADD_DEV:
        if(BufSize == 1 || BufSize != 2 + *(CmdBuf + 1)){
            return ParseCmdError;
        }
        // len = *(CmdBuf + 1);
        printf("add-dev %s\n", CmdBuf + 2);
        break;
    case COMMAND_DEL_DEV:
        if(BufSize == 1 || BufSize != 2 + *(CmdBuf + 1)){
            return ParseCmdError;
        }
        // len = *(CmdBuf + 1);
        printf("del-dev %s\n", CmdBuf + 2);
        break;
    case COMMAND_CLR_DEV:
        if(BufSize != 1){
            return ParseCmdError;
        }
        printf("clr-dev %s\n", CmdBuf + 2);
        break;
    case COMMAND_ADD_TUN:
        if(BufSize == 1 || BufSize != 2 + *(CmdBuf + 1) + 1 + 4){
            return ParseCmdError;
        }
        len = *(CmdBuf + 1);
        printf("add-tun %s %x\n", CmdBuf + 2, *(in_addr_t*)(CmdBuf + 2 + len + 1));
        break;
    case COMMAND_DEL_TUN:
        if(BufSize == 1 || BufSize != 2 + *(CmdBuf + 1)){
            return ParseCmdError;
        }
        printf("del-tun %s\n", CmdBuf + 2);
        break;
    case COMMAND_CLR_TUN:
        if(BufSize != 1){
            return ParseCmdError;
        }
        printf("clr-tun %s\n", CmdBuf + 2);
        break;
    case COMMAND_STOP:
        if(BufSize != 1){
            return ParseCmdError;
        }
        printf("stop\n");
        pthread_exit(NULL);
        break;
    default:
        return ParseCmdError;
    }
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::CreateSwitcherServer()
{
    if(pthread_create(&ServerThreadID, NULL, OnivSwitcherServerThread, this) != 0){
        return OnivErr(OnivErrCode::ERROR_CREATE_SERVER_THREAD);
    }
}

OnivErr Onivd::CreateThreadPool()
{
    int i, ret;
    for(i = 0; i < OnivGlobal::MaxEpollEvents; i++)
    {
        if(pthread_create(NULL, NULL, Worker, this) != 0){
            err(EXIT_FAILURE, "Create worker threads failed");
        }
    }
    // TODO
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

Onivd::Onivd()
{
    OnivErr oe;
    if((epfd = epoll_create(6))== -1){
        err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_CREATE_EPOLL_INSTANCE).ErrMsg().c_str());
    }
    oe = CreateSwitcherServer();
    if(oe.occured()){
        err(EXIT_FAILURE, "%s", oe.ErrMsg().c_str());
    }
    oe = CreateThreadPool();
    if(oe.occured()){
        err(EXIT_FAILURE, "%s", oe.ErrMsg().c_str());
    }
}

void Onivd::DispatchIO()
{
    int epfd, ready, i;
    struct epoll_event evlist[OnivGlobal::MaxEpollEvents];
    while(1){
        ready = epoll_wait(epfd, evlist, OnivGlobal::MaxEpollEvents, -1);
        if(ready == -1){
            if(errno == EINTR){
                continue;
            }
            else{
                err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_WAIT_EPOLL).ErrMsg().c_str());
            }
        }
        wq.lock();
        for(i = 0; i < ready; i++)
        {
            if(evlist[i].events & EPOLLIN){
                wq.Enqueue(evlist[i].data.fd);
            }
        }
        wq.unlock();
        wq.signal();
    }
    close(epfd);
}
