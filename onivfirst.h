#ifndef _ONIV_FIRST_H_
#define _ONIV_FIRST_H_

#include <chrono>
#include <string>
#include <vector>

#include "oniv.h"
#include "onivframe.h"

class OnivKeyEntry;

struct OnivLnkKA
{
    OnivCommon common;
    /*
        密钥协商消息中会传输的证书、签名和公钥会导致无法在一个报文中发送全部信息，因此需要进行分片
        size表示OnivKACommon之后的密钥协商数据大小
        total表示完整的密钥协商消息大小
        offset表示OnivKACommon之后的数据在完整的密钥协商消息中的偏移
        total和offset是为了在密钥协商消息的接收方重组密钥协商消息而添加的
    */
    uint16_t total, FrgSize, offset;
    void linearization(uint8_t *p);
    size_t structuration(const uint8_t *p);
    static size_t LinearSize();
};

class OnivLnkReq
{
private:
    uint8_t *buf;
    std::vector<OnivFrame> frames;
public:
    OnivLnkKA lka;
    std::chrono::time_point<std::chrono::system_clock> tp;
    OnivVerifyAlg PreVerifyAlg;
    OnivIDSet<OnivVerifyAlg> SupVerifyAlgSet;
    OnivKeyAgrAlg PreKeyAgrAlg;
    OnivIDSet<OnivKeyAgrAlg> SupKeyAgrAlgSet;
    OnivSigAlg SigAlg;
    OnivVariableData signature;
    OnivCertChain certs;
    OnivLnkReq(const OnivFrame &frame); // 发送方构造函数
    OnivLnkReq(const char *OnivHdr, size_t OnivSize); // 接收方构造函数
    OnivLnkReq(const OnivLnkReq &req) = delete;
    OnivLnkReq& operator=(const OnivLnkReq &req) = delete;
    ~OnivLnkReq();
    bool VerifySignature();
    std::vector<OnivFrame> request();
};

class OnivLnkRes
{
private:
    uint8_t *buf;
    std::vector<OnivFrame> frames;
public:
    OnivLnkKA lka;
    std::chrono::time_point<std::chrono::system_clock> ReqTp, ResTp;
    uint16_t RmdTp, AppTp;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    OnivSigAlg SigAlg;
    OnivVariableData pk, signature;
    OnivCertChain certs;
    OnivLnkRes(const OnivFrame &frame, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivLnkRes(const char *OnivHdr, size_t OnivSize); // 接收方构造函数
    OnivLnkRes(const OnivLnkRes &res) = delete;
    OnivLnkRes& operator=(const OnivLnkRes &res) = delete;
    ~OnivLnkRes();
    bool VerifySignature();
    std::vector<OnivFrame> response();
};

class OnivLnkRec
{
private:
    uint8_t *buf;
    OnivFrame output;
public:
    OnivCommon common;
    std::chrono::time_point<std::chrono::system_clock> UpdTp, AckTp;
    uint16_t OriginProtocol;
    OnivVerifyAlg VerifyAlg;
    OnivKeyAgrAlg KeyAgrAlg;
    OnivVariableData pk, code, trustee, escrow;
    std::string data;
    OnivLnkRec(const OnivFrame &frame, const OnivKeyEntry *keyent); // 发送方构造函数
    OnivLnkRec(const OnivFrame &frame); // 接收方构造函数
    OnivLnkRec(const OnivLnkRec &rec) = delete;
    OnivLnkRec& operator=(const OnivLnkRec &rec) = delete;
    ~OnivLnkRec();
    bool VerifyIdentity(const OnivKeyEntry *keyent);
    OnivFrame record();
    OnivFrame frame();
};

#endif
