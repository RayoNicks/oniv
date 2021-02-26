#ifndef _ONIV_SECOND_H_
#define _ONIV_SECOND_H_

#include <ctime>

#include "oniv.h"
#include "onivcrypto.h"
#include "onivpacket.h"

class OnivTunReq
{
private:
    char *buf;
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
    char* request();
    size_t size();
};

class OnivTunRes
{
private:
    char *buf;
public:
    OnivCommon common;
    uint32_t bdi; // broadcast domain identifier
    uint16_t VerifyAlg, KeyAgrAlg;
    uint64_t ReqTs, ResTs;
    vector<string> CertChain;
    string pk;
    string signature;
    OnivTunRes(uint32_t bdi, OnivVerifyAlg VerifyAlg, OnivKeyAgrAlg KeyAgrAlg); // 发送方构造函数
    OnivTunRes(const OnivPacket &packet); // 接收方构造函数
    bool VerifySignature();
    char* response();
    size_t size();
};



#endif
