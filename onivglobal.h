#ifndef _ONIV_GLOBAL_H_
#define _ONIV_GLOBAL_H_

#include <string>

using std::string;

// 单例模式
class OnivGlobal
{
public:
    static const string SwitcherServerPath;
    static const string SwitcherServerTmpPath;
    static const size_t SwitcherServerCmdBufSize;
    static const size_t MaxEpollEvents;
    static const size_t OverlayNetworkMTU = 1500;
};

#endif
