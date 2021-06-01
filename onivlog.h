#ifndef _ONIV_LOG_
#define _ONIV_LOG_

#include <string>

#include <netinet/in.h>
#include <syslog.h>

#include "oniverr.h"

class OnivFrame;
class OnivKeyEntry;

enum class OnivKeyAgrType
{
    LNK_KA,
    TUN_KA,
};

class OnivLog
{
private:
    static char* Net2Asc(in_addr_t address);
    static std::string Str2Hex(const std::string &str);
    static std::string Str2Hex(const char *p, size_t len);
public:
    static void InitLogSystem();
    static void ExitLogSystem();
    static void log(const std::string &log, int priority = LOG_INFO);
    static void LogOnivErr(OnivErr oe);
    static void LogFrameLatency(const OnivFrame &frame);
    static void LogLnkReq(in_addr_t address); // 发送方日志函数
    static void LogLnkReq(const OnivKeyEntry &keyent); // 接收方日志函数
    static void LogTunReq(const OnivKeyEntry &keyent);

    static void LogRes(const OnivKeyEntry &keyent, OnivKeyAgrType type);
    static void LogUpd(const OnivKeyEntry &keyent, OnivKeyAgrType type);
    static void LogAck(const OnivKeyEntry &keyent, OnivKeyAgrType type);
};

#endif
