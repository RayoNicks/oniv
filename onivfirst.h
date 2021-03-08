#ifndef _ONIV_FIRST_H_
#define _ONIV_FIRST_H_

#include <chrono>
#include <string>
#include <vector>

#include "oniv.h"
#include "onivcrypto.h"
#include "onivframe.h"

using std::chrono::system_clock;
using std::vector;

class OnivKeyEntry;

class OnivLnkReq
{
private:
    uint8_t *hdr, *buf;
    size_t HdrSize;
public:
    OnivCommon common;
    uint64_t ts;
    OnivVerifyAlg PreVerifyAlg;
    OnivIDSet<OnivVerifyAlg> SupVerifyAlgSet;
    OnivKeyAgrAlg PreKeyAgrAlg;
    OnivIDSet<OnivKeyAgrAlg> SupKeyAgrAlgSet;
    OnivSigAlg SigAlg;
    string signature;
    OnivCertChain certs;
    OnivLnkReq(const OnivFrame &frame); // 发送方构造函数
    OnivLnkReq(const char *OnivHdr, size_t OnivSize); // 接收方构造函数
    OnivLnkReq(const OnivLnkReq &req) = delete;
    OnivLnkReq& operator=(const OnivLnkReq &req) = delete;
    ~OnivLnkReq();
    bool VerifySignature();
    OnivFrame request();
    size_t size();
};

class OnivLnkRes
{
private:
    uint8_t *hdr, *buf;
    size_t HdrSize;
public:
    OnivCommon common;
    uint64_t ReqTs, ResTs;
    uint16_t RmdTp, AppTp;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    OnivSigAlg SigAlg;
    string pk, signature;
    OnivCertChain certs;
    OnivLnkRes(const OnivFrame &LnkReqFrame, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivLnkRes(const OnivFrame &frame); // 接收方构造函数
    OnivLnkRes(const OnivLnkRes &res) = delete;
    OnivLnkRes& operator=(const OnivLnkRes &res) = delete;
    ~OnivLnkRes();
    bool VerifySignature();
    OnivFrame response();
    size_t size();
};

class OnivLnkRecord
{
private:
    uint8_t *hdr, *buf;
    size_t HdrSize;
public:
    OnivCommon common;
    uint64_t UpdTs, AckTs;
    uint16_t OriginProtocol;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    string pk, code, trustee, escrow, data;
    OnivLnkRecord(const OnivFrame &frame, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivLnkRecord(const OnivFrame &frame); // 接收方构造函数
    OnivLnkRecord(const OnivLnkRecord &rec) = delete;
    OnivLnkRecord& operator=(const OnivLnkRecord &rec) = delete;
    ~OnivLnkRecord();
    bool VerifyIdentity(const OnivKeyEntry *keyent);
    OnivFrame record();
    OnivFrame frame();
    size_t size();
};

#endif
