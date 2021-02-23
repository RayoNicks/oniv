#ifndef _ONIV_SECOND_H_
#define _ONIV_SECOND_H_

#include "oniv.h"
#include "onivcrypto.h"
#include "onivpacket.h"

class OnivTunReq
{
private:
    char* buf;
public:
    OnivCommon common;
    uint16_t PreVerifyAlg, SupVerifyAlg;
    uint16_t PreKeyAgrAlg, SupKeyAgrAlg;
    uint64_t ts;
    vector<string> CertChain;
    string signature;
    OnivTunReq(); // 发送方构造函数
    OnivTunReq(const OnivPacket &packet); // 接收方构造函数
    ~OnivTunReq();
    bool AuthCert();
    char* request();
    size_t size();
};

class OnivTunRes
{
private:
    char *buf;
public:
    OnivCommon common;
    uint16_t VerifyAlg, KeyAgrAlg;
    uint64_t ReqTs, ResTs;
    vector<string> CertChain;
    string signature;
    string pk;
    OnivTunRes(uint16_t va, uint16_t kaa); // 发送方构造函数
    OnivTunRes(const OnivPacket &packet); // 接收方构造函数
    bool AuthCert();
    char* response();
    size_t size();
};



#endif
