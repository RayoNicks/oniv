#ifndef _ONIV_GLOBAL_H_
#define _ONIV_GLOBAL_H_

#include <string>

using std::string;

// 单例模式
class OnivGlobal
{
public:
    static const string SwitchServerPath;
    static const string SwitchServerTmpPath;
    static const size_t SwitchServerCmdBufSize;
    static const size_t MaxEpollEvents;
    static const int AdapterExtraMTU;
    static const int TunnelMTU;
    static const uint16_t TunnelPortNo;
    static const uint16_t OnivType;
};

#endif
