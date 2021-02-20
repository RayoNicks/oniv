#include "onivd.h"

void* Onivd::SwitchServerThread(void* para)
{
    Onivd* object = (Onivd*)para;
    OnivErr oe;
    while(1){
        int AcceptSocket, ReadNumber;
        char cmd[OnivGlobal::SwitchServerCmdBufSize] = { 0 };
        AcceptSocket = accept(object->ListenSocket, NULL, NULL);
        if(AcceptSocket == -1){
            continue;
            err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_ACCEPT_CONTROLLER_CONNECTION).ErrMsg().c_str());
        }
        if((ReadNumber = read(AcceptSocket, cmd, sizeof(cmd))) > 0){
            oe = object->ProcessCommand(cmd, ReadNumber);
            if(oe.occured()){
                warn("%s", oe.ErrMsg().c_str());
            }
        }
        else{
            warn("%s", OnivErr(OnivErrCode::ERROR_READ_CONTROLLER_CMD).ErrMsg().c_str());
        }
        close(AcceptSocket);
    }
}

void* Onivd::AdapterThread(void* para)
{
    Onivd* oniv = (Onivd*)para;
    int ready, i;
    struct epoll_event evlist[OnivGlobal::MaxEpollEvents];
    while(1){
        ready = epoll_wait(oniv->EpollAdapter, evlist, OnivGlobal::MaxEpollEvents, -1);
        if(ready == -1){
            if(errno == EINTR){
                continue;
            }
            else{
                err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_WAIT_EPOLL).ErrMsg().c_str());
            }
        }
        for(i = 0; i < ready; i++)
        {
            if(evlist[i].events & EPOLLIN){
                OnivErr oe;
                OnivAdapter* adapter = (OnivAdapter*)evlist[i].data.ptr;
                OnivFrame frame;
                oe = adapter->recv(frame);
                if(oe.occured()){
                    continue;
                }
                if(!frame.ARP() && !frame.IP()){
                    continue;
                }
                frame.dump();
                if(frame.IsBroadcast()){ // 从广播域内的隧道发送
                    for(TunnelIter iter = ++oniv->tunnels.begin(); iter != oniv->tunnels.end(); iter++)
                    {
                        if(iter->BroadcastID() == adapter->BroadcastID()){
                            iter->EnSendingQueue(frame); // 唤醒发送线程
                        }
                    }
                    oniv->fdb.update(frame); // 更新转发表
                }
                else{
                    // 查找密钥表，封装第一种身份信息
                    const OnivEntry* ent = oniv->fdb.search(frame);
                    if(ent == nullptr){
                        continue;
                    }
                    ent->egress->EnSendingQueue(frame);
                    // 唤醒发送线程
                    // 更新转发表
                    oniv->fdb.update(frame);
                }
            }
        }
    }
}

void* Onivd::TunnelThread(void* para)
{
    Onivd* oniv = (Onivd*)para;
    int ready, i;
    struct epoll_event evlist[OnivGlobal::MaxEpollEvents];
    while(1){
        ready = epoll_wait(oniv->EpollTunnel, evlist, OnivGlobal::MaxEpollEvents, -1);
        if(ready == -1){
            if(errno == EINTR){
                continue;
            }
            else{
                err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_WAIT_EPOLL).ErrMsg().c_str());
            }
        }
        for(i = 0; i < ready; i++)
        {
            if(evlist[i].events & EPOLLIN){
                OnivErr oe;
                OnivTunnel *ListenTunnel = (OnivTunnel*)evlist[i].data.ptr, *AcceptTunnel;
                OnivPacket packet;
                oe = ListenTunnel->recv(packet);
                if(oe.occured()){
                    continue;
                }
                TunnelIter iter = find_if(oniv->tunnels.begin(), oniv->tunnels.end(),
                [&packet](const OnivTunnel &tunnel)
                {
                    return packet.belong(tunnel);
                }
                );
                if(iter == oniv->tunnels.end()){
                    oe = oniv->AuxAddTunnel(packet.RemoteIPAddress(), packet.RemotePortNo(), packet.BroadcastID(), OnivGlobal::TunnelMTU);
                    if(oe.occured()){
                        continue;
                    }
                    AcceptTunnel = &oniv->tunnels.back();
                }
                else{
                    AcceptTunnel = &*iter;
                }
                packet.ResetIngressTunnel(AcceptTunnel);
                OnivFrame frame(packet);
                if(frame.IsBroadcast()){ // 发送到广播域
                    for(AdapterIter iter = oniv->adapters.begin(); iter != oniv->adapters.end(); iter++)
                    {
                        if(iter->BroadcastID() == packet.BroadcastID()){
                            iter->EnSendingQueue(frame); // 唤醒发送线程
                        }
                    }
                    for(TunnelIter iter = ++oniv->tunnels.begin(); iter != oniv->tunnels.end(); iter++)
                    {
                        if(AcceptTunnel != &(*iter) && iter->BroadcastID() == packet.BroadcastID()){
                            iter->EnSendingQueue(frame); // 唤醒发送线程
                        }
                    }
                    oniv->fdb.update(frame); // 更新转发表
                }
                else{
                    const OnivEntry* ent = oniv->fdb.search(frame);
                    if(ent == nullptr){
                        continue;
                    }
                    ent->egress->EnSendingQueue(frame); // 唤醒发送线程
                    oniv->fdb.update(frame); // 更新转发表
                }
            }
        }
    }
}

void* Onivd::EgressThread(void* para)
{
    Onivd* object = (Onivd*)para;

    int ready, i;
    struct epoll_event evlist[OnivGlobal::MaxEpollEvents];
    while(1){
        ready = epoll_wait(object->EpollEgress, evlist, OnivGlobal::MaxEpollEvents, -1);
        if(ready == -1){
            if(errno == EINTR){
                continue;
            }
            else{
                err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_WAIT_EPOLL).ErrMsg().c_str());
            }
        }
        for(i = 0; i < ready; i++)
        {
            if(evlist[i].events & EPOLLIN){
                // TODO
                OnivPort *port = (OnivPort*)evlist[i].data.ptr;
                port->send();
            }
        }
    }
}

/*
    主线程监听所有的虚拟网卡和隧道的读事件，放入WorkQueue中
    工作线程在WorkQueue上睡眠
    从网卡读取数据帧后，
        1. 首先查找转发表，确定发送隧道
            - 如果不需要封装身份信息，则放入发送队列
            - 如果需要封装身份信息
                - 如果没有会话密钥，则将密钥协商信息放入发送队列，数据帧放入阻塞队列
                - 如果有会话密钥，则封装身份信息，放入发送队列（对数据帧进行分片，放入发送队列）
        2. 首先查找密钥表，再查找转发表
            - 如果不需要封装身份信息，则查找转发表，放入发送队列
            - 如果需要封装身份信息，
                - 如果没有会话密钥，则查找转发表，将密钥协商信息放入发送队列，数据帧放入阻塞队列
                - 如果有会话秘钥，则封装身份信息，查找转发表，放入发送队列
        3. 对比来看，先匹配转发表，再匹配密钥表较为简便
    从隧道读取数据包后，脱掉第二种身份信息，或者处理隧道密钥协商消息
        1. 首先查找转发表，确定转发的文件描述符
            - 如果文件描述符为隧道，则放入发送队列
            - 如果文件描述符为网卡，则通过密钥表脱掉身份信息，放入发送队列（发送网卡的发送队列）
    主线程执行所有的读操作，查找转发表，并将数据帧放入网卡或者隧道的相应队列中

    读取后的处理逻辑：
        线程从网卡读取数据帧后，查找转发表
            - 如果不需要封装身份信息，则注册写事件
            - 如果没有会话秘钥，则注册密钥协商请求消息写事件，并阻塞数据帧
            - 如果有会话密钥，则封装身份信息，注册数据包写事件
        线程从隧道读取数据包后，
            - 如果是密钥协商请求消息，则注册密钥协商响应消息写事件
            - 如果是密钥协商响应消息，则封装身份信息，并注册之前阻塞的数据帧写事件
            - 如果转发到隧道，则注册写事件
            - 如果转发到网卡，则解封装身份信息，注册数据包写事件

    读取后处理的逻辑较为复杂，需要根据文件描述符类型来决定处理逻辑，不便于确定线程的数量，无法平衡IO
    因此创建三种类型的线程：
        - 一种类型的线程处理所有的写操作
        - 一种类型的线程读取并处理网卡的数据帧
        - 一种类型的线程读取并处理隧道的数据包
*/

OnivErr Onivd::CreateSwitchServerSocket(const string &SwitchServerSocketPath)
{
    struct sockaddr_un ServerAddress;

    if((ListenSocket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
        return OnivErr(OnivErrCode::ERROR_CREATE_SERVER_SOCKET);
    }

    if(remove(SwitchServerSocketPath.c_str()) == -1 && errno != ENOENT){
        return OnivErr(OnivErrCode::ERROR_REMOVE_SERVER_SOCKET);
    }

    memset(&ServerAddress, 0, sizeof(struct sockaddr_un));
    ServerAddress.sun_family = AF_UNIX;
    strncpy(ServerAddress.sun_path, SwitchServerSocketPath.c_str(), UNIX_PATH_MAX - 1);

    if(bind(ListenSocket, (const struct sockaddr*)&ServerAddress, sizeof(struct sockaddr_un)) == -1){
        return OnivErr(OnivErrCode::ERROR_BIND_SERVER_SOCKET);
    }

    if(listen(ListenSocket, 1) == -1){
        return OnivErr(OnivErrCode::ERROR_LISTEN_SERVER_SOCKET);
    }

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::AuxAddAdapter(const string &name, in_addr_t address, uint32_t vni, int mtu)
{
    adapters.emplace_back(name, address, vni, mtu);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = &adapters.back();
    if(epoll_ctl(EpollAdapter, EPOLL_CTL_ADD, adapters.back().handle(), &ev) == -1){
        return OnivErr(OnivErrCode::ERROR_ADD_ADAPTER);
    }

    ev.events = EPOLLIN;
    ev.data.ptr = &adapters.back();
    if(epoll_ctl(EpollEgress, EPOLL_CTL_ADD, adapters.back().EventHandle(), &ev) == -1){
        return OnivErr(OnivErrCode::ERROR_ADD_ADAPTER);
    };

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::AddAdapter(const char* cmd, size_t length)
{
    if(length != IFNAMSIZ + sizeof(in_addr_t) + sizeof(uint32_t) + sizeof(int)){
        return OnivErr(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    }

    string AdapterName(cmd, IFNAMSIZ);
    in_addr_t AdapterAddress = *(in_addr_t*)(cmd + IFNAMSIZ);
    uint32_t vni = *(uint32_t*)(cmd + IFNAMSIZ + sizeof(in_addr_t));
    int mtu = *(int*)(cmd + IFNAMSIZ + sizeof(in_addr_t) + sizeof(uint32_t));

    AdapterIter iter = find_if(adapters.begin(), adapters.end(),
            [AdapterName](const OnivAdapter &adapter)
            {
                return adapter.name() == AdapterName;
            }
            );
    if(iter != adapters.end()){
        return OnivErr(OnivErrCode::ERROR_ADAPTER_EXISTS);
    }
    else{
        return AuxAddAdapter(AdapterName, AdapterAddress, vni, mtu);
    }
}

OnivErr Onivd::DelAdapter(const char* cmd, size_t length)
{
    if(length != IFNAMSIZ){
        return OnivErr(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    }

    string name(cmd, length);
    adapters.remove_if(
        [&name](const OnivAdapter &adapter)
        {
            return adapter.name() == name;
        }
    );

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::ClrAdapter()
{
    adapters.clear();
}

OnivErr Onivd::AuxAddTunnel(in_addr_t address, in_port_t PortNo, uint32_t vni, int mtu)
{
    tunnels.emplace_back(address, PortNo, vni, mtu);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = &tunnels.back();
    if(epoll_ctl(EpollEgress, EPOLL_CTL_ADD, tunnels.back().EventHandle(), &ev) == -1){
        return OnivErr(OnivErrCode::ERROR_CREATE_TUNNEL);
    };

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::AddTunnel(const char* cmd, size_t length)
{
    if(length != sizeof(in_addr_t) + sizeof(uint32_t)){
        return OnivErr(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    }

    in_addr_t address = *(in_addr_t*)(cmd);
    uint32_t vni = *(uint32_t*)(cmd + sizeof(in_addr_t));

    TunnelIter iter = find_if(tunnels.begin(), tunnels.end(),
                [address, vni](const OnivTunnel &tunnel)
                {
                    return tunnel.RemotePortNo() == htons(OnivGlobal::TunnelPortNo)
                        && tunnel.RemoteIPAddress() == address;
                }
                );
    if(iter != tunnels.end()){
        return OnivErr(OnivErrCode::ERROR_TUNNEL_EXISTS);
    }
    else{
        return AuxAddTunnel(address, htons(OnivGlobal::TunnelPortNo), vni, OnivGlobal::TunnelMTU);
    }
}

OnivErr Onivd::DelTunnel(const char* cmd, size_t length)
{
    if(length != sizeof(in_addr_t)){
        return OnivErr(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    }

    in_addr_t address = *(in_addr_t*)(cmd);
    tunnels.remove_if(
        [address](const OnivTunnel &tunnel)
        {
            return tunnel.RemoteIPAddress() == address;
        }
    );

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::ClrTunnel()
{
    tunnels.clear();
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::ProcessCommand(const char* cmd, size_t length)
{
    printf("length=%ld\n", length);
    u_int8_t type = *cmd, len;
    OnivErr ParseCmdError(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    switch(type)
    {
    case COMMAND_ADD_ADP:
        if(length != 1 && length == 2 + *(cmd + 1)){
            printf("add-adp\n");
            return AddAdapter(cmd + 2, *(cmd + 1));
        }
        break;
    case COMMAND_DEL_ADP:
        if(length != 1 && length == 2 + *(cmd + 1)){
            printf("del-adp\n");
            return DelAdapter(cmd + 2, *(cmd + 1));
        }
        break;
    case COMMAND_CLR_ADP:
        if(length == 1){
            printf("clr-adp\n");
            return ClrAdapter();
        }
        break;
    case COMMAND_ADD_TUN:
        if(length != 1 && length == 2 + *(cmd + 1)){
            printf("add-tun\n");
            return AddTunnel(cmd + 2, *(cmd + 1));
        }
        break;
    case COMMAND_DEL_TUN:
        if(length != 1 && length == 2 + *(cmd + 1)){
            printf("del-tun\n");
            return DelTunnel(cmd + 2, *(cmd + 1));
        }
        break;
    case COMMAND_CLR_TUN:
        if(length == 1){
            printf("clr-tun\n");
            return ClrTunnel();
        }
        break;
    case COMMAND_STOP:
        if(length == 1){
            printf("stop\n");
            // pthread_cancel();
            exit(EXIT_SUCCESS);
        }
        break;
    default:
        break;
    }
    return ParseCmdError;
}

OnivErr Onivd::CreateSwitchServer()
{
    OnivErr oe = CreateSwitchServerSocket(OnivGlobal::SwitchServerTmpPath);
    if(oe.occured()){
        return oe;
    }
    if(pthread_create(&ServerThreadID, NULL, SwitchServerThread, this) != 0){
        return OnivErr(OnivErrCode::ERROR_CREATE_SERVER_THREAD);
    }
}

OnivErr Onivd::CreateAdapterThread()
{
    if((EpollAdapter = epoll_create(6)) == -1){
        return OnivErr(OnivErrCode::ERROR_CREATE_EPOLL_INSTANCE);
    }
    if(pthread_create(&AdapterThreadID, NULL, AdapterThread, this) != 0){
        return OnivErr(OnivErrCode::ERROR_CREATE_ADAPTER_THREAD);
    }
}

OnivErr Onivd::CreateTunnelThread(const string &TunnelAdapterName)
{
    OnivErr oe;
    if((EpollTunnel = epoll_create(1)) == -1){
        return OnivErr(OnivErrCode::ERROR_CREATE_EPOLL_INSTANCE);
    }

    tunnels.emplace_back(TunnelAdapterName, htons(OnivGlobal::TunnelPortNo), OnivGlobal::TunnelMTU);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = &tunnels.back();
    if(epoll_ctl(EpollTunnel, EPOLL_CTL_ADD, tunnels.back().handle(), &ev) == -1){
        return OnivErr(OnivErrCode::ERROR_EPOLL_TUNNEL);
    }
    
    if(pthread_create(&TunnelThreadID, NULL, TunnelThread, this) != 0){
        return OnivErr(OnivErrCode::ERROR_CREATE_TUNNEL_THREAD);
    }

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::CreateEgressThread()
{
    if((EpollEgress = epoll_create(6)) == -1){
        err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_CREATE_EPOLL_INSTANCE).ErrMsg().c_str());
    }
    if(pthread_create(&EgressThreadID, NULL, EgressThread, this) != 0){
        return OnivErr(OnivErrCode::ERROR_CREATE_TUNNEL_THREAD);
    }
}

Onivd::Onivd(const string &TunnelAdapterName)// : tunnel(TunnelAdapterName)
{
    OnivErr oe;
    oe = CreateSwitchServer();
    if(oe.occured()){
        err(EXIT_FAILURE, "%s", oe.ErrMsg().c_str());
    }
    oe = CreateAdapterThread();
    if(oe.occured()){
        err(EXIT_FAILURE, "%s", oe.ErrMsg().c_str());
    }
    oe = CreateTunnelThread(TunnelAdapterName);
    if(oe.occured()){
        err(EXIT_FAILURE, "%s", oe.ErrMsg().c_str());
    }
    oe = CreateEgressThread();
    if(oe.occured()){
        err(EXIT_FAILURE, "%s", oe.ErrMsg().c_str());
    }
}

void Onivd::run()
{
    pthread_join(ServerThreadID, NULL);
    pthread_join(AdapterThreadID, NULL);
    pthread_join(TunnelThreadID, NULL);
    pthread_join(EgressThreadID, NULL);
}
