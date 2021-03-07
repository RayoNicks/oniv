#ifndef _ONIV_CRYPTO_H_
#define _ONIV_CRYPTO_H_

#include <initializer_list>
#include <string>
#include <vector>

#include "oniv.h"

using std::initializer_list;
using std::string;
using std::vector;

class OnivCrypto
{
private:
    static string uuid;
    static vector<string> crts;
public:
    static string UUID();
    static OnivVerifyAlg PreVerifyAlg();
    static OnivKeyAgrAlg PreKeyAgrAlg();
    static OnivSigAlg PreSigAlg();
    static initializer_list<OnivVerifyAlg> ListVerifyAlg();
    static initializer_list<OnivKeyAgrAlg> ListKeyAgrAlg();
    static OnivVerifyAlg SelectVerifyAlg(OnivVerifyAlg pre, const OnivIDSet<OnivVerifyAlg> &sup);
    static OnivKeyAgrAlg SelectKeyAgrAlg(OnivKeyAgrAlg pre, const OnivIDSet<OnivKeyAgrAlg> &sup);

    static vector<string> CertChain();

    static string GenSignature(const string &data, OnivSigAlg SigAlg);

    static string AcqPriKey(OnivKeyAgrAlg KeyAgrAlg);
    static string AcqPubKey(OnivKeyAgrAlg KeyAgrAlg);
    static string GenPriKey(OnivKeyAgrAlg KeyAgrAlg);
    static string GenPubKey(OnivKeyAgrAlg KeyAgrAlg, const string &PubKey);
    static string ComputeSessionKey(OnivKeyAgrAlg KeyAgrAlg, const string &PubKey, const string &PriKey);

    static string MsgAuthCode(OnivVerifyAlg VerifyAlg, const string &SK, const string &UserData);
    static string GenEscrowData(const string &Pk3rd, OnivVerifyAlg VerifyAlg, const string &SK);
    static bool VerifySignature(const vector<string> &CertChain, const string &signature);

    static size_t SignatureSize(OnivSigAlg SigAlg);
    static size_t PubKeySize(OnivKeyAgrAlg KeyAgrAlg);
    static size_t MsgAuthCodeSize(OnivVerifyAlg VerifyAlg);
    static size_t EscrowDataSize(const string &Pk3rd, OnivVerifyAlg VerifyAlg, const string &SK);

    static void LoadCrt(const string &HostName);
};

#endif
