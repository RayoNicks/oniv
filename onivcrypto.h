#ifndef _ONIV_CRYPTO_H_
#define _ONIV_CRYPTO_H_

#include <string>
#include <vector>

using std::string;
using std::vector;

class OnivCrypto
{
    // static string uuid;
public:
    static string UUID();
    static uint16_t VerifyAlgSet();
    static uint16_t KeyAgrAlgSet();
    static vector<string> CertChain();
    static string GenSignature();
    static string GetPublicKey(uint16_t KeyAgrAlg);
};

#endif
