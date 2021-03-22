#ifndef _ONIV_CRYPTO_H_
#define _ONIV_CRYPTO_H_

#include <initializer_list>
#include <fstream>
#include <string>
#include <vector>

#include "oniv.h"

using std::initializer_list;
using std::string;
using std::vector;

class OnivCrypto
{
private:
    static string uuid, sk, dhsk, dhpk;
    static OnivVerifyAlg VerifyAlg;
    static OnivKeyAgrAlg KeyAgrAlg;
    static vector<string> crts;
    static string ReadFile(const string &subject, int type);
public:
    static const string& UUID();
    static OnivVerifyAlg PreVerifyAlg();
    static OnivKeyAgrAlg PreKeyAgrAlg();
    static OnivSigAlg SigAlg();
    static initializer_list<OnivVerifyAlg> ListVerifyAlg();
    static initializer_list<OnivKeyAgrAlg> ListKeyAgrAlg();
    static OnivVerifyAlg SelectVerifyAlg(OnivVerifyAlg pre, const OnivIDSet<OnivVerifyAlg> &sup);
    static OnivKeyAgrAlg SelectKeyAgrAlg(OnivKeyAgrAlg pre, const OnivIDSet<OnivKeyAgrAlg> &sup);
    static string SelectTrusteeCert(uint16_t pre, uint16_t app);

    static const vector<string>& CertChain();

    static string GenSignature(const string &data);
    static bool VerifySignature(const vector<string> &CertChain, const string &data, const string &signature);

    static string GenPriKey(OnivKeyAgrAlg KeyAgrAlg);
    static string GenPubKey(const string &PrivateKey);
    static string ComputeSessionKey(const string &PublibKey, const string &PrivateKey);

    static string MsgAuthCode(OnivVerifyAlg VerifyAlg,
                            const string &SessionKey, string &UserData,
                            const string &InitVector, const string &AssData);
    static size_t MsgAuchCodeSize();
    static string GenEscrowData(const string &cert, const string &SessionKey, const string &aux);

    static string GetSubject(const string &cert);
    static string GetCertFromSubject(const string &subject);

    static bool LoadIdentity();
};

#endif
