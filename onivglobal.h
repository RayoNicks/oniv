#ifndef _ONIV_GLOBAL_H_
#define _ONIV_GLOBAL_H_

#include <string>

using std::string;

class OnivGlobal
{
public:
    static const string SwitchServerPath;
    static const string SwitchServerTmpPath;
    static const size_t SwitchServerCmdBufSize;
    static const size_t MaxEpollEvents;
    static const int LinkExtra;
    static const int AdapterMTU;
    static const int AdapterExtraMTU;
    static const int TunnelMTU;
    static const uint16_t OnivPort;
    static const uint16_t KeyAgrBufSize;
};

#endif
