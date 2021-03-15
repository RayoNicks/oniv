#include "onivd.h"

void* Onivd::SwitchServerThread(void *para)
{
    Onivd *oniv = (Onivd*)para;
    OnivErr oe;
    while(1){
        int AcceptSocket, ReadNumber;
        char cmd[OnivGlobal::SwitchServerCmdBufSize] = { 0 };
        AcceptSocket = accept(oniv->ListenSocket, NULL, NULL);
        if(AcceptSocket == -1){
            continue;
            err(EXIT_FAILURE, "%s", OnivErr(OnivErrCode::ERROR_ACCEPT_CONTROLLER_CONNECTION).ErrMsg().c_str());
        }
        if((ReadNumber = read(AcceptSocket, cmd, sizeof(cmd))) > 0){
            oe = oniv->ProcessCommand(cmd, ReadNumber);
            if(oe.occured()){
                warn("%s", oe.ErrMsg().c_str());
                // write(AcceptSocket, oe.ErrMsg().c_str(), oe.ErrMsg().length());
            }
            else{
                write(AcceptSocket, "success", strlen("success"));
            }
        }
        else{
            warn("%s", OnivErr(OnivErrCode::ERROR_READ_CONTROLLER_CMD).ErrMsg().c_str());
        }
        close(AcceptSocket);
    }
}

/*
    创建三种类型的线程：
        - 一种类型的线程处理所有的写操作
        - 一种类型的线程读取并处理网卡的数据帧
        - 一种类型的线程读取并处理隧道的数据包
*/

void* Onivd::AdapterThread(void *para)
{
    Onivd *oniv = (Onivd*)para;
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
                OnivAdapter *adapter = (OnivAdapter*)evlist[i].data.ptr;
                OnivFrame frame;
                oe = adapter->recv(frame);
                if(oe.occured()){
                    continue;
                }
                if(!frame.IsARP() && !frame.IsIP()){
                    continue;
                }
                // frame.dump();
                if(frame.IsBroadcast()){ // 发送到广播域
                    for(TunnelIter iter = ++oniv->tunnels.begin(); iter != oniv->tunnels.end(); iter++)
                    {
                        if(iter->BroadcastDomain() == adapter->BroadcastDomain()){
                            iter->EnSendingQueue(frame); // 唤醒发送线程
                        }
                    }
                    oniv->fdb.update(frame); // 更新转发表
                }
                else{
                    const OnivForwardingEntry *forent = oniv->fdb.search(frame);
                    if(forent == nullptr){
                        continue;
                    }
                    // TODO 新的判断链路起点的逻辑
                    AdapterIter iter = find_if(oniv->adapters.begin(), oniv->adapters.end(), [&frame](const OnivAdapter &adapter)
                    {
                        // 根据IP地址判断链路起点
                        return adapter.address() == frame.SrcIPAddr();
                    }
                    );
                    if(iter != oniv->adapters.end()){ // 链路起点
                        OnivKeyEntry *keyent = oniv->kdb.SearchTo(frame.DestIPAddr());
                        if(keyent == nullptr){
                            OnivLnkReq req(frame); // 根据要发送的数据帧构造链路密钥协商请求
                            forent->egress->EnSendingQueue(req.request()); // 唤醒发送线程
                            oniv->bq.enqueue(frame);
                        }
                        else{
                            OnivLnkRecord rec(frame, keyent);
                            forent->egress->EnSendingQueue(rec.record());
                            keyent->UpdateOnSend();
                        }
                    }
                    else{
                        forent->egress->EnSendingQueue(frame);
                    }
                    oniv->fdb.update(frame); // 更新转发表
                }
            }
        }
    }
}

void* Onivd::TunnelThread(void *para)
{
    Onivd *oniv = (Onivd*)para;
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
                OnivTunnel *ListenTunnel = (OnivTunnel*)evlist[i].data.ptr;
                OnivPacket packet;
                oe = ListenTunnel->recv(packet);
                if(oe.occured()){
                    continue;
                }
                // packet.dump();
                switch(packet.type())
                {
                case OnivPacketType::TUN_KA_REQ:
                    oniv->ProcessTunKeyAgrReq(packet);
                    break;
                case OnivPacketType::TUN_KA_RES:
                    oniv->ProcessTunKeyAgrRes(packet);
                    break;
                case OnivPacketType::TUN_KA_FIN:
                    break;
                case OnivPacketType::TUN_KA_FAIL:
                    break;
                case OnivPacketType::TUN_IV_ERR:
                    break;
                case OnivPacketType::ONIV_RECORD:
                    oniv->ProcessTunRecord(packet);
                    break;
                default:
                    break;
                }
            }
        }
    }
}

void* Onivd::EgressThread(void *para)
{
    Onivd *oniv = (Onivd*)para;

    int ready, i;
    struct epoll_event evlist[OnivGlobal::MaxEpollEvents];
    while(1){
        ready = epoll_wait(oniv->EpollEgress, evlist, OnivGlobal::MaxEpollEvents, -1);
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
                OnivPort *port = (OnivPort*)evlist[i].data.ptr;
                port->send();
            }
        }
    }
}

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

OnivErr Onivd::AuxAddAdapter(const string &name, in_addr_t address, in_addr_t mask, uint32_t bdi, int mtu)
{
    adapters.emplace_back(name, address, mask, bdi, mtu);
    if(!adapters.back().IsUp()){
        return OnivErr(OnivErrCode::ERROR_CREATE_ADAPTER);
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = &adapters.back();
    if(epoll_ctl(EpollAdapter, EPOLL_CTL_ADD, adapters.back().handle(), &ev) == -1){
        return OnivErr(OnivErrCode::ERROR_EPOLL_ADAPTER);
    }

    ev.events = EPOLLIN;
    ev.data.ptr = &adapters.back();
    if(epoll_ctl(EpollEgress, EPOLL_CTL_ADD, adapters.back().EventHandle(), &ev) == -1){
        return OnivErr(OnivErrCode::ERROR_EPOLL_ADAPTER);
    };

    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::AddAdapter(const char *cmd, size_t length)
{
    if(length != IFNAMSIZ + sizeof(in_addr_t) * 2 + sizeof(uint32_t) + sizeof(int)){
        return OnivErr(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    }

    string name(cmd, IFNAMSIZ);
    in_addr_t address = *(in_addr_t*)(cmd + IFNAMSIZ);
    in_addr_t mask = *(in_addr_t*)(cmd + IFNAMSIZ + sizeof(in_addr_t));
    uint32_t bdi = ntohl(*(uint32_t*)(cmd + IFNAMSIZ + sizeof(in_addr_t) * 2));
    int mtu = *(int*)(cmd + IFNAMSIZ + sizeof(in_addr_t) * 2 + sizeof(uint32_t));

    AdapterIter iter = find_if(adapters.begin(), adapters.end(),
            [&name](const OnivAdapter &adapter)
            {
                return adapter.name() == name;
            }
            );
    if(iter != adapters.end()){
        return OnivErr(OnivErrCode::ERROR_ADAPTER_EXISTS);
    }
    else{
        return AuxAddAdapter(name, address, mask, bdi, mtu);
    }
}

OnivErr Onivd::DelAdapter(const char *cmd, size_t length)
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
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::AuxAddTunnel(in_addr_t address, in_port_t PortNo, uint32_t bdi, int mtu)
{
    tunnels.emplace_back(address, PortNo, bdi, mtu);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = &tunnels.back();
    if(epoll_ctl(EpollEgress, EPOLL_CTL_ADD, tunnels.back().EventHandle(), &ev) == -1){
        return OnivErr(OnivErrCode::ERROR_CREATE_TUNNEL);
    };
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::AddTunnel(const char *cmd, size_t length)
{
    if(length != sizeof(in_addr_t) + sizeof(uint32_t)){
        return OnivErr(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    }

    in_addr_t address = *(in_addr_t*)(cmd);
    uint32_t bdi = ntohl(*(uint32_t*)(cmd + sizeof(in_addr_t)));

    TunnelIter iter = find_if(tunnels.begin(), tunnels.end(),
                [address, bdi](const OnivTunnel &tunnel)
                {
                    return tunnel.RemotePortNo() == htons(OnivGlobal::OnivPort)
                        && tunnel.RemoteIPAddress() == address;
                }
                );
    if(iter != tunnels.end()){
        return OnivErr(OnivErrCode::ERROR_TUNNEL_EXISTS);
    }
    else{
        return AuxAddTunnel(address, htons(OnivGlobal::OnivPort), bdi, OnivGlobal::TunnelMTU);
    }
}

OnivErr Onivd::DelTunnel(const char *cmd, size_t length)
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

OnivErr Onivd::ManipulateRoute(in_addr_t dest, in_addr_t mask, in_addr_t gateway, const string &name)
{
    struct rtentry rt;
    struct sockaddr_in *sa;
    unsigned long request = gateway != 0 ? SIOCADDRT : SIOCDELRT;
    char device[IFNAMSIZ];

    strncpy(device, name.c_str(), IFNAMSIZ);
    memset(&rt, 0, sizeof(struct rtentry));

    rt.rt_flags = RTF_UP;
    // 地址
    sa = (struct sockaddr_in*)&rt.rt_dst;
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = dest;
    // 掩码
    sa = (struct sockaddr_in*)&rt.rt_genmask;
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = mask;
    // 网关
    if(gateway != 0){
        sa = (struct sockaddr_in*)&rt.rt_gateway;
        sa->sin_family = AF_INET;
        sa->sin_addr.s_addr = gateway;
        rt.rt_flags |= RTF_GATEWAY;
    }
    // 接口
    rt.rt_dev = device;

    int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(udpfd, request, &rt) < 0){
        if(request == SIOCADDRT){
            return OnivErr(OnivErrCode::ERROR_ADD_ROUTE);
        }
        else{
            return OnivErr(OnivErrCode::ERROR_DEL_ROUTE);
        }
    }
    else{
        return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
    }
}

OnivErr Onivd::AddRoute(const char *cmd, size_t length)
{
    if(length != sizeof(in_addr_t) * 3 + IFNAMSIZ){
        return OnivErr(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    }

    in_addr_t dest = *(in_addr_t*)cmd;
    in_addr_t mask = *(in_addr_t*)(cmd + sizeof(in_addr_t));
    in_addr_t gateway = *(in_addr_t*)(cmd + sizeof(in_addr_t) * 2);
    string name(cmd + sizeof(in_addr_t) * 3, IFNAMSIZ);

    AdapterIter iter = find_if(adapters.begin(), adapters.end(),
            [&name](const OnivAdapter &adapter)
            {
                return adapter.name() == name;
            }
            );
    if(iter == adapters.end()){
        return OnivErr(OnivErrCode::ERROR_UNKNOWN_ADAPTER);
    }
    else{
        return ManipulateRoute(dest, mask, gateway, name);
    }
}

OnivErr Onivd::DelRoute(const char *cmd, size_t length)
{
    if(length != sizeof(in_addr_t) * 2 + IFNAMSIZ){
        return OnivErr(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    }

    in_addr_t dest = *(in_addr_t*)cmd;
    in_addr_t mask = *(in_addr_t*)(cmd + sizeof(in_addr_t));
    string name(cmd + sizeof(in_addr_t) * 2, IFNAMSIZ);

    AdapterIter iter = find_if(adapters.begin(), adapters.end(),
            [&name](const OnivAdapter &adapter)
            {
                return adapter.name() == name;
            }
            );
    if(iter == adapters.end()){
        return OnivErr(OnivErrCode::ERROR_UNKNOWN_ADAPTER);
    }
    else{
        return ManipulateRoute(dest, mask, 0, name);
    }
}

OnivErr Onivd::ProcessCommand(const char *cmd, size_t length)
{
    u_int8_t type = *cmd;
    OnivErr ParseCmdError(OnivErrCode::ERROR_PARSE_CONTROLLER_CMD);
    switch(type)
    {
    case COMMAND_STOP:
        if(length == 1){
            printf("stop\n");
            // pthread_cancel();
            exit(EXIT_SUCCESS);
        }
        break;
    case COMMAND_ADD_ADP:
        if(length != 1 && length == static_cast<size_t>(2 + *(cmd + 1))){
            return AddAdapter(cmd + 2, *(cmd + 1));
        }
        break;
    case COMMAND_DEL_ADP:
        if(length != 1 && length == static_cast<size_t>(2 + *(cmd + 1))){
            return DelAdapter(cmd + 2, *(cmd + 1));
        }
        break;
    case COMMAND_CLR_ADP:
        if(length == 1){
            return ClrAdapter();
        }
        break;
    case COMMAND_ADD_TUN:
        if(length != 1 && length == static_cast<size_t>(2 + *(cmd + 1))){
            return AddTunnel(cmd + 2, *(cmd + 1));
        }
        break;
    case COMMAND_DEL_TUN:
        if(length != 1 && length == static_cast<size_t>(2 + *(cmd + 1))){
            return DelTunnel(cmd + 2, *(cmd + 1));
        }
        break;
    case COMMAND_CLR_TUN:
        if(length == 1){
            return ClrTunnel();
        }
        break;
    case COMMAND_ADD_ROU:
        if(length != 1 && length == static_cast<size_t>(2 + *(cmd + 1))){
            return AddRoute(cmd + 2, *(cmd + 1));
        }
        break;
    case COMMAND_DEL_ROU:
        break;
    default:
        break;
    }
    return ParseCmdError;
}

OnivErr Onivd::ProcessTunKeyAgrReq(const OnivPacket &packet)
{
    // TODO 处理重复的隧道密钥协商请求消息
    OnivErr oe;
    OnivTunnel *AcceptTunnel;
    TunnelIter iter = find_if(tunnels.begin(), tunnels.end(), [&packet](const OnivTunnel &tunnel)
    {
        return tunnel.RemotePortNo() == packet.RemotePortNo()
            && tunnel.RemoteIPAddress() == packet.RemoteIPAddress();
    }
    );
    if(iter == tunnels.end()){ // 没有找到反向隧道
        oe = AuxAddTunnel(packet.RemoteIPAddress(), packet.RemotePortNo(), packet.BroadcastDomain(), OnivGlobal::TunnelMTU);
        if(oe.occured()){
            return oe;
        }
        AcceptTunnel = &tunnels.back();
    }
    else{ // 找到了反向隧道
        AcceptTunnel = &*iter;
    }
    oe = AcceptTunnel->VerifySignature(packet);
    if(oe.occured()){
        return oe;
    }
    AcceptTunnel->NotifySendingQueue(); // 唤醒发送线程，发送数据帧或者隧道密钥协商失败消息
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::ProcessTunKeyAgrRes(const OnivPacket &packet)
{
    // TODO 处理重复的隧道密钥协商响应消息
    OnivErr oe;
    OnivTunnel *AcceptTunnel;
    TunnelIter iter = find_if(tunnels.begin(), tunnels.end(), [&packet](const OnivTunnel &tunnel)
    {
        return tunnel.RemotePortNo() == packet.RemotePortNo()
            && tunnel.RemoteIPAddress() == packet.RemoteIPAddress();
    }
    );
    if(iter == tunnels.end()){
        return OnivErr(OnivErrCode::ERROR_UNKNOWN);
    }
    AcceptTunnel = &*iter;
    oe = AcceptTunnel->VerifySignature(packet);
    if(oe.occured()){
        return oe;
    }
    AcceptTunnel->NotifySendingQueue(); // 唤醒发送线程，发送数据帧或者隧道密钥协商失败消息
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::ProcessTunRecord(OnivPacket &packet)
{
    OnivTunnel *AcceptTunnel;
    TunnelIter iter = find_if(tunnels.begin(), tunnels.end(), [&packet](const OnivTunnel &tunnel)
    {
        // 在接收数据之前一定已经进行了隧道密钥协商，可以根据身份标识区分隧道
        return tunnel.RemoteID() == packet.SenderID();
    }
    );
    if(iter == tunnels.end()){
        return OnivErr(OnivErrCode::ERROR_UNKNOWN);
    }
    AcceptTunnel = &*iter;
    packet.DiapatchIngressTunnel(AcceptTunnel); // 设置数据包的接收隧道
    AcceptTunnel->UpdateSocket(packet); // 更新隧道地址

    OnivKeyEntry *keyent = AcceptTunnel->KeyEntry();
    OnivTunRecord rec(packet); // 隧道身份验证
    keyent->UpdateOnRecvTunRec(rec);
    if(!rec.VerifyIdentity(keyent)){
        // 构造隧道身份验证失败报文，添加到发送队列
        return OnivErr(OnivErrCode::ERROR_TUNNEL_VERIFICATION);
    }
    OnivFrame frame(rec.frame(), rec.FrameSize(), packet.IngressPort());
    if(frame.IsBroadcast()){ // 发送到广播域
        for(AdapterIter iter = adapters.begin(); iter != adapters.end(); iter++)
        {
            if(iter->BroadcastDomain() == packet.BroadcastDomain()){
                iter->EnSendingQueue(frame); // 唤醒发送线程
            }
        }
        for(TunnelIter iter = ++tunnels.begin(); iter != tunnels.end(); iter++)
        {
            if(AcceptTunnel != &(*iter) && iter->BroadcastDomain() == packet.BroadcastDomain()){
                iter->EnSendingQueue(frame); // 唤醒发送线程
            }
        }
        fdb.update(frame); // 更新转发表
    }
    else{
        if(!frame.IsLayer4Oniv()){
            return OnivErr(OnivErrCode::ERROR_UNKNOWN);
        }
        // TODO 新的判断链路终点逻辑
        AdapterIter iter = find_if(adapters.begin(), adapters.end(), [&frame](const OnivAdapter &adapter)
        {
            // 根据IP地址判断链路终点
            return adapter.address() == frame.DestIPAddr();
        }
        );
        if(iter != adapters.end()){ // 链路终点为本机
            switch(frame.type())
            {
            case OnivPacketType::LNK_KA_REQ:
                ProcessLnkKeyAgrReq(frame);
                break;
            case OnivPacketType::LNK_KA_RES:
                ProcessLnkKeyAgrRes(frame);
                break;
            case OnivPacketType::LNK_KA_FIN:
                break;
            case OnivPacketType::LNK_KA_FAIL:
                break;
            case OnivPacketType::LNK_IV_ERR:
                break;
            case OnivPacketType::ONIV_RECORD:
                ProcessLnkRecord(frame);
                break;
            default:
                break;
            }
        }
        else{ // 链路终点不是本机
            const OnivForwardingEntry *forent = fdb.search(frame);
            if(forent == nullptr){
                return OnivErr(OnivErrCode::ERROR_NO_FORWARD_ENTRY);
            }
            forent->egress->EnSendingQueue(frame); // 唤醒发送线程
        }
        fdb.update(frame); // 更新转发表
    }
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::ProcessLnkKeyAgrReq(const OnivFrame &frame)
{
    OnivFragementEntry *frgent = rdb.AddFragement(frame);
    if(frgent == nullptr){
        return OnivErr(OnivErrCode::ERROR_NO_FRAGEMENT_ENTRY);
    }
    if(!frgent->completed()){
        return OnivErr(OnivErrCode::ERROR_REASSEMBLING_FRAGEMENTS);
    }
    OnivLnkReq req(frgent->OnivHdr(), frgent->OnivSize());
    rdb.RemoveFragement(frgent);
    if(req.VerifySignature()){
        const OnivKeyEntry *keyent = kdb.update(frame, req);
        if(keyent != nullptr){
            OnivLnkRes res(frame, keyent); // 只从frame中取地址信息
            frame.IngressPort()->EnSendingQueue(res.response()); // 唤醒发送线程
        }
        else{
            return OnivErr(OnivErrCode::ERROR_NO_KEY_ENTRY);
        }
    }
    else{
        // 发送链路密钥协商失败消息
    }
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::ProcessLnkKeyAgrRes(const OnivFrame &frame)
{
    OnivFragementEntry *frgent = rdb.AddFragement(frame);
    if(frgent == nullptr){
        return OnivErr(OnivErrCode::ERROR_NO_FRAGEMENT_ENTRY);
    }
    if(!frgent->completed()){
        return OnivErr(OnivErrCode::ERROR_REASSEMBLING_FRAGEMENTS);
    }
    OnivLnkRes res(frgent->OnivHdr(), frgent->OnivSize());
    rdb.RemoveFragement(frgent);
    if(res.VerifySignature()){
        OnivKeyEntry *keyent = kdb.update(frame, res);
        if(keyent != nullptr){ // 发送阻塞队列中的数据帧
            vector<OnivFrame> BlockingFrames = bq.ConditionDequeue(keyent->RemoteAddress);
            for(const OnivFrame &bf: BlockingFrames)
            {
                OnivLnkRecord rec(bf, keyent);
                frame.IngressPort()->EnSendingQueue(rec.record());
                keyent->UpdateOnSend();
            }
        }
        else{
            return OnivErr(OnivErrCode::ERROR_NO_KEY_ENTRY);
        }
    }
    else{
        // 发送链路密钥协商失败消息
    }
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::ProcessLnkRecord(const OnivFrame &frame)
{
    const OnivForwardingEntry *forent = fdb.search(frame);
    if(forent == nullptr){
        return OnivErr(OnivErrCode::ERROR_NO_FORWARD_ENTRY);
    }

    OnivLnkRecord rec(frame);
    OnivKeyEntry *keyent = kdb.SearchFrom(string((char*)rec.common.UUID, sizeof(rec.common.UUID)));
    if(keyent != nullptr){
        keyent->UpdateOnRecvLnkRec(rec);
        if(rec.VerifyIdentity(keyent)){
            forent->egress->EnSendingQueue(rec.frame()); // 唤醒发送线程
            fdb.update(frame); // 更新转发表
            return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
        }
        else{
            // 构造隧道身份验证失败报文，添加到发送队列
            return OnivErr(OnivErrCode::ERROR_LINK_VERIFICATION);
        }
    }
    else{
        return OnivErr(OnivErrCode::ERROR_NO_KEY_ENTRY);
    }
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
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::CreateAdapterThread()
{
    if((EpollAdapter = epoll_create(6)) == -1){
        return OnivErr(OnivErrCode::ERROR_CREATE_EPOLL_INSTANCE);
    }
    if(pthread_create(&AdapterThreadID, NULL, AdapterThread, this) != 0){
        return OnivErr(OnivErrCode::ERROR_CREATE_ADAPTER_THREAD);
    }
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

OnivErr Onivd::CreateTunnelThread(const string &TunnelAdapterName)
{
    OnivErr oe;
    if((EpollTunnel = epoll_create(1)) == -1){
        return OnivErr(OnivErrCode::ERROR_CREATE_EPOLL_INSTANCE);
    }

    tunnels.emplace_back(TunnelAdapterName, htons(OnivGlobal::OnivPort), OnivGlobal::TunnelMTU);

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
    return OnivErr(OnivErrCode::ERROR_SUCCESSFUL);
}

Onivd::Onivd(const string &TunnelAdapterName, const string &HostName)
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
