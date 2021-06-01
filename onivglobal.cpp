#include "onivglobal.h"

#include <sstream>
#include <iostream>
#include <fstream>

using std::ifstream;
using std::istringstream;
using std::map;
using std::set;
using std::string;
using std::vector;

bool OnivGlobal::LoadConfiguration(const string &file)
{
    ifstream conf(file, ifstream::in);
    string line, key, value;
    if(!conf){
        return false;
    }
    while(getline(conf, line)){
        if(line.empty() || line[0] == '#'){
            continue;
        }
        size_t pos = line.find('=');
        if(pos == string::npos){
            continue;
        }
        else{
            line[pos] = ' ';
        }
        istringstream iss(line);
        iss >> key >> value;
        if(keywords.find(key) == keywords.end()){
            continue;
        }
        config[key] = value;
    }
    conf.close();
    if(config.find("link_verification") != config.end()){
        if(config.at("link_verification") == "true"){
            EnableLinkVerification = true;
        }
    }
    if(config.find("tunnel_verification") != config.end()){
        if(config.at("tunnel_verification") == "true"){
            EnableTunnelVerification = true;
        }
    }
    return true;
}

string OnivGlobal::GetConfig(const string &key)
{
    if(keywords.find(key) != keywords.end()){
        return config.at(key);
    }
    else{
        return string();
    }
}

vector<string> OnivGlobal::CertsFile()
{
    vector<string> files;
    string value = GetConfig("cert_chain"), file;
    size_t pos = 0;
    while((pos = value.find('/', pos)) != string::npos){
        value[pos] = ' ';
    }
    istringstream iss(value);
    while(iss >> file){
        files.push_back(GetConfig("cert_path"));
        files.back().push_back('/');
        files.back().append(file);
    }
    return files;
}

bool OnivGlobal::EnableLnk()
{
    return EnableLinkVerification;
}

bool OnivGlobal::EnableTun()
{
    return EnableTunnelVerification;
}

map<string, string> OnivGlobal::config;
const set<string> OnivGlobal::keywords = { 
    "link_verification", "tunnel_verification",
    "private_key_file", "cert_path", "cert_chain",
    "verification_algorithm", "key_agreement_algorithm",
    "tunnel_interface",
    };
bool OnivGlobal::EnableLinkVerification = false;
bool OnivGlobal::EnableTunnelVerification = false;

const string OnivGlobal::SwitchServerPath("/var/run/oniv");
const size_t OnivGlobal::SwitchServerCmdBufSize = 1024;
const size_t OnivGlobal::MaxEpollEvents = 32;
const int OnivGlobal::LinkExtra = 300; // 第一种身份信息占用的报文空间
const int OnivGlobal::AdapterMinMTU = 600;
const int OnivGlobal::AdapterMaxMTU = 1300;
const int OnivGlobal::AdapterExtraMTU = 14; // mtu不包含以太网头部
const int OnivGlobal::TunnelMTU = 1458; // 1500 - 14 - 20 - 8
const uint16_t OnivGlobal::OnivPort = 8888;
const uint16_t OnivGlobal::KeyAgrBufSize = 8 * 1024;
