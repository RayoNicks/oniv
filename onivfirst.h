#ifndef _ONIV_FIRST_H_
#define _ONIV_FIRST_H_

#include "oniv.h"

struct OnivLnkReq
{
    OnivCommon common;
    string UUID;
    uint16_t PreVerifyAlg, SupVerifyAlg;
    uint16_t PreKeyAgrAlg, SupKeyAgrAlg;
    time_t ts;
    uint16_t CertNum;
    uint16_t CertLengths[1];
    // 之后是每一个证书
    // 最后是签名
};

struct OnivLnkRes
{
    OnivCommon common;
    uint8_t UUID;
    uint16_t VerifyAlg, KeyAgrAlg;
    uint16_t RmdTp, AppTp;
    time_t ReqTs, ResTs;
    uint16_t CertNum;
    uint16_t CertLengths[1];
    // 之后是每一个证书
    // 证书后面是签名
    // 最后是密钥协商参数的公钥
};

#endif
