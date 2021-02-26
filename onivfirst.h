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
    char *hdr, *buf;
    size_t HdrSize;
    void ConstructRequest(const OnivFrame &frame);
    void ParseRequest(const OnivFrame &frame);
public:
    OnivCommon common;
    uint16_t PreVerifyAlg, SupVerifyAlg;
    uint16_t PreKeyAgrAlg, SupKeyAgrAlg;
    time_t ts;
    vector<string> CertChain;
    string signature;
    OnivLnkReq(const OnivFrame &frame);
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
    char *hdr, *buf;
    size_t HdrSize;
public:
    OnivCommon common;
    uint16_t VerifyAlg, KeyAgrAlg;
    uint16_t RmdTp, AppTp;
    time_t ReqTs, ResTs;
    vector<string> CertChain;
    string pk;
    string signature;
    OnivLnkRes(const OnivFrame &LnkReqFrame, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivLnkRes(const OnivFrame &frame); // 接收方构造函数
    ~OnivLnkRes();
    bool VerifySignature();
    // vector<OnivFrame> response();
    OnivFrame response();
    size_t size();
};

class OnivLnkRecord
{
private:
    char *hdr, *buf;
    size_t HdrSize;
    void ConstructRecord(const OnivFrame &frame, const OnivKeyEntry *keyent);
    void ParseRecord(const OnivFrame &frame, const OnivKeyEntry *keyent);
public:
    OnivCommon common;
    time_t UpdTs, AckTs;
    uint16_t OriginProtocol, OriginLength, OriginChecksum;
    string pk, code, escrow, data;
    OnivLnkRecord(const OnivFrame &frame, const OnivKeyEntry *keyent);
    ~OnivLnkRecord();
    // vector<OnivFrame> record();
    OnivFrame record();
    OnivFrame frame();
    size_t size();
};

#endif
