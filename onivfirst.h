#ifndef _ONIV_FIRST_H_
#define _ONIV_FIRST_H_

#include <ctime>
#include <vector>

#include "oniv.h"
#include "onivcrypto.h"
#include "oniventry.h"
#include "onivframe.h"

using std::vector;

class OnivLnkReq
{
private:
    uint8_t *hdr, *buf;
    size_t HdrSize;
    void ConstructRequest(const OnivFrame &frame);
    void ParseRequest(const OnivFrame &frame);
public:
    OnivCommon common;
    uint16_t PreVerifyAlg, SupVerifyAlg;
    uint16_t PreKeyAgrAlg, SupKeyAgrAlg;
    uint64_t ts;
    vector<string> CertChain;
    string signature;
    OnivLnkReq(const OnivFrame &frame);
    OnivLnkReq(const OnivLnkReq &req) = delete;
    OnivLnkReq& operator=(const OnivLnkReq &req) = delete;
    ~OnivLnkReq();
    bool VerifySignature();
    // 暂不考虑链路密钥协商过大导致的分片问题
    // vector<OnivFrame> request();
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
    uint16_t VerifyAlg, KeyAgrAlg;
    uint16_t RmdTp, AppTp;
    uint64_t ReqTs, ResTs;
    vector<string> CertChain;
    string pk;
    string signature;
    OnivLnkRes(const OnivFrame &LnkReqFrame, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivLnkRes(const OnivFrame &frame); // 接收方构造函数
    OnivLnkRes(const OnivLnkRes &res) = delete;
    OnivLnkRes& operator=(const OnivLnkRes &res) = delete;
    ~OnivLnkRes();
    bool VerifySignature();
    // vector<OnivFrame> response();
    OnivFrame response();
    size_t size();
};

class OnivLnkRecord
{
private:
    uint8_t *hdr, *buf;
    size_t HdrSize;
    void ConstructRecord(const OnivFrame &frame, OnivKeyEntry *keyent);
    void ParseRecord(const OnivFrame &frame, OnivKeyEntry *keyent);
public:
    OnivCommon common;
    uint64_t UpdTs, AckTs;
    uint16_t OriginProtocol;
    string pk, code, escrow, data;
    OnivLnkRecord(const OnivFrame &frame, OnivKeyEntry *keyent);
    OnivLnkRecord(const OnivLnkRecord &rec) = delete;
    OnivLnkRecord& operator=(const OnivLnkRecord &rec) = delete;
    ~OnivLnkRecord();
    OnivFrame record();
    OnivFrame frame();
    size_t size();
};

#endif
