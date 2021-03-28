#ifndef _ONIV_SECOND_H_
#define _ONIV_SECOND_H_

#include <chrono>
#include <string>
#include <vector>

#include "oniv.h"
#include "onivcrypto.h"
#include "onivframe.h"
#include "onivpacket.h"

using std::chrono::system_clock;
using std::string;
using std::vector;

class OnivKeyEntry;

struct OnivTunCommon
{
    OnivCommon common;
    uint32_t bdi; // broadcast domain identifier
    void linearization(uint8_t *p);
    size_t structuration(const uint8_t *p);
    static size_t LinearSize();
};

class OnivTunReq
{
private:
    uint8_t *buf;
public:
    OnivTunCommon tc;
    time_point<system_clock> tp;
    OnivVerifyAlg PreVerifyAlg;
    OnivIDSet<OnivVerifyAlg> SupVerifyAlgSet;
    OnivKeyAgrAlg PreKeyAgrAlg;
    OnivIDSet<OnivKeyAgrAlg> SupKeyAgrAlgSet;
    OnivSigAlg SigAlg;
    OnivVariableData signature;
    OnivCertChain certs;
    OnivTunReq(uint32_t bdi); // 发送方构造函数
    OnivTunReq(const OnivPacket &packet); // 接收方构造函数
    OnivTunReq(const OnivTunReq &req) = delete;
    OnivTunReq& operator=(const OnivTunReq &req) = delete;
    ~OnivTunReq();
    bool VerifySignature();
    const uint8_t* request();
    size_t size();
};

class OnivTunRes
{
private:
    uint8_t *buf;
public:
    OnivTunCommon tc;
    time_point<system_clock> ReqTp, ResTp;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    OnivSigAlg SigAlg;
    OnivVariableData pk, signature;
    OnivCertChain certs;
    OnivTunRes(uint32_t bdi, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivTunRes(const OnivPacket &packet); // 接收方构造函数
    OnivTunRes(const OnivTunRes &res) = delete;
    OnivTunRes& operator=(const OnivTunRes &res) = delete;
    ~OnivTunRes();
    bool VerifySignature();
    const uint8_t* response();
    size_t size();
};

class OnivTunRecord
{
private:
    uint8_t *buf;
public:
    OnivTunCommon tc;
    time_point<system_clock> UpdTp, AckTp;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    OnivVariableData pk, code;
    string data;
    OnivTunRecord(uint32_t bdi, const OnivFrame &frame, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivTunRecord(const OnivPacket &packet); // 接收方构造函数
    OnivTunRecord(const OnivTunRecord &rec) = delete;
    OnivTunRecord& operator=(const OnivTunRecord &rec) = delete;
    ~OnivTunRecord();
    bool VerifyIdentity(const OnivKeyEntry *keyent);
    const uint8_t* record();
    const char* frame();
    size_t size();
    size_t FrameSize();
};

#endif
