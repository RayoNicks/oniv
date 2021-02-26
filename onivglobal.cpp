#include "onivglobal.h"

const string OnivGlobal::SwitchServerPath("/var/run/oniv");
const string OnivGlobal::SwitchServerTmpPath("/tmp/oniv");
const size_t OnivGlobal::SwitchServerCmdBufSize = 1024;
const size_t OnivGlobal::MaxEpollEvents = 32;
const int OnivGlobal::AdapterExtraMTU = 14; // mtu不包含以太网头部
const int OnivGlobal::TunnelMTU = 1500 - 14 - 20 - 8; // 1458
const uint16_t OnivGlobal::TunnelPortNo = 8888;
const uint16_t OnivGlobal::OnivType = OnivGlobal::TunnelPortNo;
