#ifndef _ONIV_CRYPTO_H_
#define _ONIV_CRYPTO_H_

#include <initializer_list>
#include <string>
#include <unordered_map>
#include <vector>

#include "oniv.h"

class OnivCrypto
{
private:
    static std::unordered_map<std::string, OnivVerifyAlg> VerifyAlgs;
    static std::unordered_map<std::string, OnivKeyAgrAlg> KeyAgrAlgs;
    static std::unordered_map<std::string, OnivSigAlg> SigAlgs;
    static OnivVerifyAlg PreVerifyAlg;
    static OnivKeyAgrAlg PreKeyAgrAlg;
    static std::string uuid, sk;
    static std::vector<std::string> crts;
    static std::string ReadFile(const std::string &subject, int type);
    template<typename T> static std::string AuxConvAlgNum(const std::unordered_map<std::string, T> &algs, T num);
    template<typename T> static T AuxConvAlgName(const std::unordered_map<std::string, T> &algs, const std::string &name);
public:
    static const std::string& LocalUUID();

    template<typename T> static std::string ConvAlgNum(T num);
    template<typename T> static T ConvAlgName(const std::string &name);
    template<typename T> static T LocalAlg();
    template<typename T> static std::initializer_list<T> ListAlg();
    template<typename T> static T SelectAlg(T pre, const OnivIDSet<T> &sups);

    static std::string SelectTrusteeCert(uint16_t pre, uint16_t app);

    static const std::vector<std::string>& CertChain();

    static std::string GenSignature(const std::string &data);
    static bool VerifySignature(const std::vector<std::string> &CertChain, const std::string &data, const std::string &signature);

    static std::string GenPriKey(OnivKeyAgrAlg KeyAgrAlg);
    static std::string GetPubKeyFromPriKey(const std::string &PrivateKey);
    static std::string ComputeSessionKey(const std::string &PublibKey, const std::string &PrivateKey);

    static std::string MsgAuthCode(OnivVerifyAlg VerifyAlg,
                            const std::string &SessionKey, std::string &UserData,
                            const std::string &InitVector, const std::string &AssData);
    static size_t MsgAuthCodeSize();
    static std::string GenEscrowData(const std::string &cert, const std::string &SessionKey, const std::string &aux);

    static const std::string GetSubject(const std::string &cert);

    static const std::string GetUUID(const std::string &cert);
    static const std::string GetCertFromUUID(const std::string &uuid);

    static bool LoadIdentity();
};

#endif
