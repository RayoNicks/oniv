#ifndef _ONIV_GLOBAL_H_
#define _ONIV_GLOBAL_H_

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using std::map;
using std::set;
using std::string;
using std::vector;

class OnivGlobal
{
private:
    static map<string, string> config;
    static const set<string> keywords;
    static bool EnableLinkVerification, EnableTunnelVerification;
public:
    static const string SwitchServerPath;
    static const size_t SwitchServerCmdBufSize;
    static const size_t MaxEpollEvents;
    static const int LinkExtra;
    static const int AdapterMinMTU, AdapterMaxMTU;
    static const int AdapterExtraMTU;
    static const int TunnelMTU;
    static const uint16_t OnivPort;
    static const uint16_t KeyAgrBufSize;
    static bool LoadConfiguration(const string &file);
    static string GetConfig(const string &key);
    static vector<string> CertsFile();
    static bool EnableLnk();
    static bool EnableTun();
};

#endif
