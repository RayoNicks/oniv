#ifndef _ONIV_SECOND_H_
#define _ONIV_SECOND_H_

#include <chrono>
#include <string>
#include <vector>

#include "oniv.h"
#include "onivcrypto.h"
#include "oniventry.h"
#include "onivframe.h"
#include "onivpacket.h"

using std::chrono::system_clock;
using std::string;
using std::vector;

class OnivTunReq
{
private:
    uint8_t *buf;
public:
    OnivCommon common;
    uint32_t bdi; // broadcast domain identifier
    uint64_t ts;
    OnivVerifyAlg PreVerifyAlg;
    OnivIDSet<OnivVerifyAlg> SupVerifyAlgSet;
    OnivKeyAgrAlg PreKeyAgrAlg;
    OnivIDSet<OnivKeyAgrAlg> SupKeyAgrAlgSet;
    OnivSigAlg SigAlg;
    string signature;
    OnivCertChain certs;
    OnivTunReq(uint32_t vni); // 发送方构造函数
    OnivTunReq(const OnivPacket &packet); // 接收方构造函数
    OnivTunReq(const OnivTunReq &req) = delete;
    OnivTunReq& operator=(const OnivTunReq &req) = delete;
    ~OnivTunReq();
    bool VerifySignature();
    const char* request();
    size_t size();
};

class OnivTunRes
{
private:
    uint8_t *buf;
public:
    OnivCommon common;
    uint32_t bdi; // broadcast domain identifier
    uint64_t ReqTs, ResTs;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    OnivSigAlg SigAlg;
    string pk, signature;
    OnivCertChain certs;
    OnivTunRes(uint32_t vni, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivTunRes(const OnivPacket &packet); // 接收方构造函数
    OnivTunRes(const OnivTunRes &res) = delete;
    OnivTunRes& operator=(const OnivTunRes &res) = delete;
    ~OnivTunRes();
    bool VerifySignature();
    const char* response();
    size_t size();
};

class OnivTunRecord
{
private:
    uint8_t *buf;
public:
    OnivCommon common;
    uint32_t bdi; // broadcast domain identifier
    uint64_t UpdTs, AckTs;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    string pk, code, data;
    OnivPort *ingress;
    OnivTunRecord(uint32_t vni, const OnivFrame &frame, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivTunRecord(const OnivPacket &packet); // 接收方构造函数
    OnivTunRecord(const OnivTunRecord &rec) = delete;
    OnivTunRecord& operator=(const OnivTunRecord &rec) = delete;
    ~OnivTunRecord();
    bool UpdSend();
    bool AckSend();
    bool VerifyIdentity(const OnivKeyEntry *keyent);
    const char* record();
    const char* frame();
    size_t size();
    size_t FrameSize();
};

#endif
