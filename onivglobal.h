#ifndef _ONIV_GLOBAL_H_
#define _ONIV_GLOBAL_H_

#include <map>
#include <set>
#include <string>
#include <vector>

class OnivGlobal
{
private:
    static std::map<std::string, std::string> config;
    static const std::set<std::string> keywords;
    static bool EnableLinkVerification, EnableTunnelVerification;
public:
    static const std::string SwitchServerPath;
    static const size_t SwitchServerCmdBufSize;
    static const size_t MaxEpollEvents;
    static const int LinkExtra;
    static const int AdapterMinMTU, AdapterMaxMTU;
    static const int AdapterExtraMTU;
    static const int TunnelMTU;
    static const uint16_t OnivPort;
    static const uint16_t KeyAgrBufSize;
    static bool LoadConfiguration(const std::string &file);
    static std::string GetConfig(const std::string &key);
    static std::vector<std::string> CertsFile();
    static bool EnableLnk();
    static bool EnableTun();
};

#endif
