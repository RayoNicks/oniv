#ifndef _ONIV_CRYPTO_H_
#define _ONIV_CRYPTO_H_

#include <string>
#include <vector>

using std::string;
using std::vector;

enum class OnivVerifyAlg : uint16_t
{
    NONE = 0x00,
    IV_SIMPLE_XOR = 0x01,
    ALL = IV_SIMPLE_XOR,
};

enum class OnivKeyAgrAlg : uint16_t
{
    NONE = 0x00,
    KA_SIMPLE_XOR = 0x01,
    ALL = KA_SIMPLE_XOR,
};

class OnivCrypto
{
    // static string uuid;
public:
    static string UUID();
    static OnivVerifyAlg VerifyAlgSet();
    static OnivKeyAgrAlg KeyAgrAlgSet();
    static vector<string> CertChain();
    static string GenSignature(const string &data);
    static string AcqPriKey(OnivKeyAgrAlg KeyAgrAlg);
    static string AcqPubKey(OnivKeyAgrAlg KeyAgrAlg);
    static string GenPriKey(OnivKeyAgrAlg KeyAgrAlg);
    static string GenPubKey(OnivKeyAgrAlg KeyAgrAlg, const string &PubKey);
    static string ComputeSessionKey(OnivKeyAgrAlg KeyAgrAlg, const string &PubKey, const string &PriKey);
    static string MsgAuthCode(OnivVerifyAlg VerifyAlg, const string &SK, const string &UserData);
    static size_t PubKeySize(OnivKeyAgrAlg KeyAgrAlg);
    static size_t MsgAuthCodeSize(OnivVerifyAlg VerifyAlg);
};

#endif
