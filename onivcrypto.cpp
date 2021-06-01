#include "onivcrypto.h"

#include <algorithm>
#include <fstream>

#include "libonivcrypto/libonivcrypto.h"
#include "onivglobal.h"

using namespace libonivcrypto;
using std::initializer_list;
using std::ifstream;
using std::string;
using std::transform;
using std::unordered_map;
using std::vector;

string OnivCrypto::ReadFile(const string &subject, int type)
{
    ifstream ifs(subject, ifstream::in);
    string pem, der, line;
    size_t DerSize;
    if(!ifs){
        return string();
    }
    while(getline(ifs, line)){
        pem.append(line);
        pem.push_back('\n');
    }
    pem.pop_back();
    ifs.close();
    der.resize(pem.length());
    DerSize = PEM2DER(type, pem.c_str(), pem.length(), const_cast<char*>(der.c_str()), der.size());
    der.resize(DerSize);
    return der;
}

const string& OnivCrypto::LocalUUID()
{
    return uuid;
}

template<typename T> string OnivCrypto::AuxConvAlgNum(const unordered_map<string, T> &algs, T num)
{
    for(auto iter = algs.begin(); iter != algs.end(); iter++)
    {
        if(iter->second == num){
            return iter->first;
        }
    }
    return string();
}

template<typename T> T OnivCrypto::AuxConvAlgName(const unordered_map<string, T> &algs, const string &name)
{
    string LowerName(name.size(), '\0');
    transform(name.begin(), name.end(), LowerName.begin(), [](const char c){ return tolower(c); });
    auto iter = algs.find(LowerName);
    if(iter != algs.end()){
        return iter->second;
    }
    else{
        return CastFrom16<T>(0);
    }
}

template<> string OnivCrypto::ConvAlgNum(OnivVerifyAlg num)
{
    return AuxConvAlgNum(VerifyAlgs, num);
}

template<> string OnivCrypto::ConvAlgNum(OnivKeyAgrAlg num)
{
    return AuxConvAlgNum(KeyAgrAlgs, num);
}

template<> string OnivCrypto::ConvAlgNum(OnivSigAlg num)
{
    return AuxConvAlgNum(SigAlgs, num);
}

template<> OnivVerifyAlg OnivCrypto::ConvAlgName(const string &name)
{
    return AuxConvAlgName(VerifyAlgs, name);
}

template<> OnivKeyAgrAlg OnivCrypto::ConvAlgName(const string &name)
{
    return AuxConvAlgName(KeyAgrAlgs, name);
}

template<> OnivSigAlg OnivCrypto::ConvAlgName(const string &name)
{
    return AuxConvAlgName(SigAlgs, name);
}

template<> OnivVerifyAlg OnivCrypto::LocalAlg()
{
    return OnivCrypto::PreVerifyAlg;
}

template<> OnivKeyAgrAlg OnivCrypto::LocalAlg()
{
    return OnivCrypto::PreKeyAgrAlg;
}

template<> OnivSigAlg OnivCrypto::LocalAlg()
{
    const char *name = GetCurveName(crts.back().c_str(), crts.back().length(), FORMAT_ASN1);
    if(string(name) == "secp384r1"){
        return OnivSigAlg::ECDSA_SECP384R1_SHA384;
    }
    else if(string(name) == "secp521r1"){
        return OnivSigAlg::ECDSA_SECP521R1_SHA512;
    }
    else{
        return OnivSigAlg::UNKNOWN;
    }
}

template<> initializer_list<OnivVerifyAlg> OnivCrypto::ListAlg()
{
    return {
            OnivVerifyAlg::IV_AES_128_GCM_SHA256,
            OnivVerifyAlg::IV_AES_256_GCM_SHA384,
            OnivVerifyAlg::IV_AES_128_CCM_SHA256 };
}

template<> initializer_list<OnivKeyAgrAlg> OnivCrypto::ListAlg()
{
    return { OnivKeyAgrAlg::KA_SECP384R1, OnivKeyAgrAlg::KA_SECP521R1 };
}

template<> OnivVerifyAlg OnivCrypto::SelectAlg(OnivVerifyAlg pre, const OnivIDSet<OnivVerifyAlg> &sups)
{
    return pre;
}

template<> OnivKeyAgrAlg OnivCrypto::SelectAlg(OnivKeyAgrAlg pre, const OnivIDSet<OnivKeyAgrAlg> &sups)
{
    return pre;
}

string OnivCrypto::SelectTrusteeCert(uint16_t pre, uint16_t app)
{
    if(pre >= crts.size()){
        return string();
    }
    else{
        return crts[pre];
    }
}

const vector<string>& OnivCrypto::CertChain()
{
    return crts;
}

string OnivCrypto::GenSignature(const string &data)
{
    char signature[256] = { 0 };
    size_t SignatureSize = 0;
    SignatureSize = sign(sk.c_str(), sk.length(), data.c_str(), data.length(), signature, sizeof(signature), FORMAT_ASN1);
    return string(signature, SignatureSize);
}

string OnivCrypto::GenPriKey(OnivKeyAgrAlg KeyAgrAlg)
{
    char PrivateKey[512] = { 0 };
    int size = 0;
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP384R1){
        size = GenECPrivateKey("secp384r1", PrivateKey, sizeof(PrivateKey), FORMAT_ASN1);
        return string(PrivateKey, size);
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP521R1){
        size = GenECPrivateKey("secp521r1", PrivateKey, sizeof(PrivateKey), FORMAT_ASN1);
        return string(PrivateKey, size);
    }
    else{
        return string();
    }
}

string OnivCrypto::GetPubKeyFromPriKey(const string &PrivateKey)
{
    char PublicKey[256] = { 0 };
    int size = GetECPublicKey(PrivateKey.c_str(), PrivateKey.length(), PublicKey, sizeof(PublicKey), FORMAT_ASN1);
    return string(PublicKey, size);
}

string OnivCrypto::ComputeSessionKey(const string &PublicKey, const string &PrivateKey)
{
    char SessionKey[128] = { 0 }; // 大一点的缓冲区保证可以得到16字节的密钥
    ComputeSK(PrivateKey.c_str(), PrivateKey.length(), PublicKey.c_str(), PublicKey.length(),
                        SessionKey, sizeof(SessionKey), FORMAT_ASN1);
    return string(SessionKey, 16);
}

string OnivCrypto::MsgAuthCode(OnivVerifyAlg VerifyAlg,
                            const string &SessionKey, string &UserData,
                            const string &InitVector, const string &AssData)
{
    // 只认证，不加密
    char cipher[UserData.length()] = { 0 }, tag[16] = { 0 };
    if(VerifyAlg == OnivVerifyAlg::IV_AES_128_GCM_SHA256){
        GCMEncryption("aes-128-gcm", SessionKey.c_str(), SessionKey.length(),
                    UserData.c_str(), UserData.length(),
                    InitVector.c_str(), InitVector.length(),
                    AssData.c_str(), AssData.length(), cipher, UserData.length(),
                    tag, sizeof(tag));
        return string(tag, MsgAuthCodeSize());
    }
    else if(VerifyAlg == OnivVerifyAlg::IV_AES_256_GCM_SHA384){
        GCMEncryption("aes-256-gcm", SessionKey.c_str(), SessionKey.length(),
                    UserData.c_str(), UserData.length(),
                    InitVector.c_str(), InitVector.length(),
                    AssData.c_str(), AssData.length(), cipher, UserData.length(),
                    tag, sizeof(tag));
        return string(tag, MsgAuthCodeSize());
    }
    else if(VerifyAlg == OnivVerifyAlg::IV_AES_128_CCM_SHA256){
        CCMEncryption(SessionKey.c_str(), SessionKey.length(),
                    UserData.c_str(), UserData.length(),
                    InitVector.c_str(), InitVector.length(),
                    AssData.c_str(), AssData.length(), cipher, UserData.length(),
                    tag, sizeof(tag));
        return string(tag, MsgAuthCodeSize());
    }
    else{
        return string();
    }
}

size_t OnivCrypto::MsgAuthCodeSize()
{
    return 16;
}

string OnivCrypto::GenEscrowData(const string &cert, const string &SessionKey, const string &aux)
{
    char cipher[512] = { 0 };
    size_t size = encrypt(cert.c_str(), cert.length(), SessionKey.c_str(), SessionKey.length(),
            cipher, sizeof(cipher), FORMAT_ASN1);
    return string(cipher, size);
}

bool OnivCrypto::VerifySignature(const vector<string> &CertChain, const string &data, const string &signature)
{
    const string &user = CertChain.back();
    string ca;
    bool ValidChain = false, ValidSignature = false;
    for(auto iter = CertChain.begin(); iter != CertChain.end() - 1; iter++)
    {
        char pem[2048];
        int size = DER2PEM(OBJECT_ECC_509, iter->c_str(), iter->length(), pem, sizeof(pem));
        ca.append(pem, size);
    }
    ValidChain = CheckCertificate(ca.c_str(), ca.length(),
                                user.c_str(), user.length(), FORMAT_ASN1) == 1;
    ValidSignature = verify(user.c_str(), user.length(), data.c_str(), data.length(),
                        signature.c_str(), signature.length(), FORMAT_ASN1) == 1;
    return ValidChain && ValidSignature;
}

const string OnivCrypto::GetSubject(const string &cert)
{
    char subject[512] = { 0 };
    int size = GetSubjectName(cert.c_str(), cert.length(), subject, sizeof(subject), FORMAT_ASN1);
    return string(subject, size);
}

const string OnivCrypto::GetUUID(const string &cert)
{
    char buf[16] = { 0 };
    if(!uuid5(cert.c_str(), cert.length(), buf, sizeof(buf), FORMAT_ASN1)){
        return string();
    }
    return string(buf, sizeof(buf));
}

const string OnivCrypto::GetCertFromUUID(const string &uuid)
{
    for(const string &cert : crts)
    {
        if(uuid == GetUUID(cert)){
            return cert;
        }
    }
    return string();
}

bool OnivCrypto::LoadIdentity()
{
    LoadAlgorithms();

    vector<string> CertFile(OnivGlobal::CertsFile());
    for(const string &file : CertFile)
    {
        crts.push_back(ReadFile(file, OBJECT_ECC_509));
        if(crts.back().empty()){
            return false;;
        }
    }

    uuid = GetUUID(crts.back());
    if(uuid.empty()){
        return false;
    }

    sk = ReadFile(OnivGlobal::GetConfig("private_key_file"), OBJECT_ECC_PRI);
    if(sk.empty()){
        return false;
    }

    string AlgName;
    AlgName = OnivGlobal::GetConfig("verification_algorithm");
    PreVerifyAlg = ConvAlgName<OnivVerifyAlg>(AlgName);
    if(PreVerifyAlg == OnivVerifyAlg::UNKNOWN){
        PreVerifyAlg = OnivVerifyAlg::IV_AES_128_GCM_SHA256;
    }

    AlgName = OnivGlobal::GetConfig("key_agreement_algorithm");
    PreKeyAgrAlg = ConvAlgName<OnivKeyAgrAlg>(AlgName);
    if(PreKeyAgrAlg == OnivKeyAgrAlg::UNKNOWN){
        PreKeyAgrAlg = OnivKeyAgrAlg::KA_SECP384R1;
    }

    return true;
}

unordered_map<string, OnivVerifyAlg> OnivCrypto::VerifyAlgs = {
    { "aes-128-gcm-sha256", OnivVerifyAlg::IV_AES_128_GCM_SHA256 },
    { "aes-256-gcm-sha384", OnivVerifyAlg::IV_AES_256_GCM_SHA384 },
    { "aes-128-ccm-sha256", OnivVerifyAlg::IV_AES_128_CCM_SHA256 },
};
unordered_map<string, OnivKeyAgrAlg> OnivCrypto::KeyAgrAlgs = {
    { "ecdhe-secp384r1" , OnivKeyAgrAlg::KA_SECP384R1 },
    { "ecdhe-secp521r1" , OnivKeyAgrAlg::KA_SECP521R1 },
};
unordered_map<string, OnivSigAlg> OnivCrypto::SigAlgs = {
    { "ecdsa-secp384R1-sha384", OnivSigAlg::ECDSA_SECP384R1_SHA384 },
    { "ecdsa-secp521R1-sha512", OnivSigAlg::ECDSA_SECP521R1_SHA512 },
};
OnivVerifyAlg OnivCrypto::PreVerifyAlg;
OnivKeyAgrAlg OnivCrypto::PreKeyAgrAlg;
string OnivCrypto::uuid;
string OnivCrypto::sk;
vector<string> OnivCrypto::crts;
