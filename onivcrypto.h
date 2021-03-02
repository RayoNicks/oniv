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
private:
    static string uuid;
    static vector<string> crts;
public:
    static string UUID();
    static OnivVerifyAlg VerifyAlgSet();
    static OnivKeyAgrAlg KeyAgrAlgSet();
    static OnivVerifyAlg SelectVerifyAlg(OnivVerifyAlg pre, OnivVerifyAlg sup);
    static OnivKeyAgrAlg SelectKeyAgrAlg(OnivKeyAgrAlg pre, OnivKeyAgrAlg sup);
    static vector<string> CertChain();
    static string GenSignature(const string &data);
    static string AcqPriKey(OnivKeyAgrAlg KeyAgrAlg);
    static string AcqPubKey(OnivKeyAgrAlg KeyAgrAlg);
    static string GenPriKey(OnivKeyAgrAlg KeyAgrAlg);
    static string GenPubKey(OnivKeyAgrAlg KeyAgrAlg, const string &PubKey);
    static string ComputeSessionKey(OnivKeyAgrAlg KeyAgrAlg, const string &PubKey, const string &PriKey);
    static string MsgAuthCode(OnivVerifyAlg VerifyAlg, const string &SK, const string &UserData);
    static string GenEscrowData(const string &Pk3rd, OnivVerifyAlg VerifyAlg, const string &SK);
    static bool VerifySignature(const vector<string> CertChain, const string &signature);
    static size_t PubKeySize(OnivKeyAgrAlg KeyAgrAlg);
    static size_t MsgAuthCodeSize(OnivVerifyAlg VerifyAlg);
    static size_t EscrowDataSize(const string &Pk3rd, OnivVerifyAlg VerifyAlg, const string &SK);

    static void LoadCrt(const string &HostName);
};

#endif
