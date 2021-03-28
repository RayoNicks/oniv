#ifndef _ONIV_CRYPTO_H_
#define _ONIV_CRYPTO_H_

#include <algorithm>
#include <initializer_list>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "oniv.h"

using std::initializer_list;
using std::string;
using std::vector;
using std::unordered_map;

class OnivCrypto
{
private:
    static unordered_map<string, OnivVerifyAlg> VerifyAlgs;
    static unordered_map<string, OnivKeyAgrAlg> KeyAgrAlgs;
    static unordered_map<string, OnivSigAlg> SigAlgs;
    static OnivVerifyAlg PreVerifyAlg;
    static OnivKeyAgrAlg PreKeyAgrAlg;
    static string uuid, sk;
    static vector<string> crts;
    static string ReadFile(const string &subject, int type);
    template<typename T> static string AuxConvAlgNum(const unordered_map<string, T> &algs, T num);
    template<typename T> static T AuxConvAlgName(const unordered_map<string, T> &algs, const string &name);
public:
    static const string& UUID();

    template<typename T> static string ConvAlgNum(T num);
    template<typename T> static T ConvAlgName(const string &name);
    template<typename T> static T LocalAlg();
    template<typename T> static initializer_list<T> ListAlg();
    template<typename T> static T SelectAlg(T pre, const OnivIDSet<T> &sups);

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
    static size_t MsgAuthCodeSize();
    static string GenEscrowData(const string &cert, const string &SessionKey, const string &aux);

    static string GetSubject(const string &cert);
    static string GetCertFromSubject(const string &subject);

    static bool LoadIdentity();
};

#endif
