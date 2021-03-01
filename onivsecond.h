#ifndef _ONIV_SECOND_H_
#define _ONIV_SECOND_H_

#include <ctime>

#include "oniv.h"
#include "onivcrypto.h"
#include "onivframe.h"
#include "onivpacket.h"
#include "onivtunnel.h"

class OnivTunReq
{
private:
    uint8_t *buf;
public:
    OnivCommon common;
    uint32_t bdi; // broadcast domain identifier
    uint16_t PreVerifyAlg, SupVerifyAlg;
    uint16_t PreKeyAgrAlg, SupKeyAgrAlg;
    uint64_t ts;
    vector<string> CertChain;
    string signature;
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
    uint16_t VerifyAlg, KeyAgrAlg;
    uint64_t ReqTs, ResTs;
    vector<string> CertChain;
    string pk;
    string signature;
    OnivTunRes(uint32_t vni, OnivVerifyAlg VerifyAlg, OnivKeyAgrAlg KeyAgrAlg); // 发送方构造函数
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
    string pk, code, data;
    OnivPort *ingress;
    OnivTunRecord(uint32_t vni, const OnivFrame &frame, OnivKeyEntry *keyent); // 发送方构造函数
    OnivTunRecord(const OnivPacket &packet, OnivKeyEntry *keyent); // 接收方构造函数
    OnivTunRecord(const OnivTunRecord &rec) = delete;
    OnivTunRecord& operator=(const OnivTunRecord &rec) = delete;
    ~OnivTunRecord();
    const char* record();
    const char* frame();
    size_t size();
    size_t FrameSize();
};

#endif
