#include "onivglobal.h"

const string OnivGlobal::SwitcherServerPath("/var/run/oniv");
const string OnivGlobal::SwitcherServerTmpPath("/tmp/oniv");
const size_t OnivGlobal::SwitcherServerCmdBufSize = 1024;
const size_t OnivGlobal::MaxEpollEvents = 5;
