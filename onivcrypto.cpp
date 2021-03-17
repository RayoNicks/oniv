#include "onivcrypto.h"
#include "libonivcrypto/libonivcrypto.h"

using namespace libonivcrypto;

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

const string& OnivCrypto::UUID()
{
    return uuid;
}

OnivVerifyAlg OnivCrypto::PreVerifyAlg()
{
    return OnivVerifyAlg::IV_AES_128_GCM_SHA256;
}

OnivKeyAgrAlg OnivCrypto::PreKeyAgrAlg()
{
    return OnivKeyAgrAlg::KA_SECP384R1;
}

OnivSigAlg OnivCrypto::SigAlg()
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

initializer_list<OnivVerifyAlg> OnivCrypto::ListVerifyAlg()
{
    return {
            OnivVerifyAlg::IV_AES_128_GCM_SHA256,
            OnivVerifyAlg::IV_AES_256_GCM_SHA384,
            OnivVerifyAlg::IV_AES_128_CCM_SHA256 };
}

initializer_list<OnivKeyAgrAlg> OnivCrypto::ListKeyAgrAlg()
{
    return { OnivKeyAgrAlg::KA_SECP384R1, OnivKeyAgrAlg::KA_SECP521R1 };
}

OnivVerifyAlg OnivCrypto::SelectVerifyAlg(OnivVerifyAlg pre, const OnivIDSet<OnivVerifyAlg> &sup)
{
    return pre;
}

OnivKeyAgrAlg OnivCrypto::SelectKeyAgrAlg(OnivKeyAgrAlg pre, const OnivIDSet<OnivKeyAgrAlg> &sup)
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

string OnivCrypto::AcqPriKey(OnivKeyAgrAlg KeyAgrAlg)
{
    return dhsk;
}

string OnivCrypto::AcqPubKey(OnivKeyAgrAlg KeyAgrAlg)
{
    return dhpk;
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

string OnivCrypto::GenPubKey(const string &PrivateKey)
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
        return string(tag, MsgAuchCodeSize());
    }
    else if(VerifyAlg == OnivVerifyAlg::IV_AES_256_GCM_SHA384){
        GCMEncryption("aes-256-gcm", SessionKey.c_str(), SessionKey.length(),
                    UserData.c_str(), UserData.length(),
                    InitVector.c_str(), InitVector.length(),
                    AssData.c_str(), AssData.length(), cipher, UserData.length(),
                    tag, sizeof(tag));
        return string(tag, MsgAuchCodeSize());
    }
    else if(VerifyAlg == OnivVerifyAlg::IV_AES_128_CCM_SHA256){
        CCMEncryption(SessionKey.c_str(), SessionKey.length(),
                    UserData.c_str(), UserData.length(),
                    InitVector.c_str(), InitVector.length(),
                    AssData.c_str(), AssData.length(), cipher, UserData.length(),
                    tag, sizeof(tag));
        return string(tag, MsgAuchCodeSize());
    }
    else{
        return string();
    }
}

size_t OnivCrypto::MsgAuchCodeSize()
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

string OnivCrypto::GetSubject(const string &cert)
{
    char subject[512] = { 0 };
    int size = GetSubjectName(cert.c_str(), cert.length(), subject, sizeof(subject), FORMAT_ASN1);
    return string(subject, size);
}

string OnivCrypto::GetCertFromSubject(const string &subject)
{
    for(const string &cert : crts)
    {
        char subject[512] = { 0 };
        int size = GetSubjectName(cert.c_str(), cert.length(), subject, sizeof(subject), FORMAT_ASN1);
        if(string(subject, size) == subject){
            return cert;
        }
    }
    return string();
}

bool OnivCrypto::LoadIdentity(const string &subject)
{
    LoadAlgorithms();

    crts.push_back(ReadFile("certs/ecc/root-ecc.crt", OBJECT_ECC_509));
    crts.push_back(ReadFile("certs/ecc/second-ecc.crt", OBJECT_ECC_509));
    crts.push_back(ReadFile("certs/ecc/" + subject + "-ecc.crt", OBJECT_ECC_509));
    for(const string cert : crts)
    {
        if(crts.back().empty()){
            return false;;
        }
    }

    char buf[16] = { '\0' };
    if(!uuid5(crts.back().c_str(), crts.back().length(), buf, sizeof(buf), FORMAT_ASN1)){
        return false;
    }
    uuid.assign(buf, sizeof(buf));

    sk = ReadFile("certs/ecc/" + subject + "-ecc-sk.pem", OBJECT_ECC_PRI);
    if(sk.empty()){
        return false;
    }

    dhsk = GenPriKey(PreKeyAgrAlg());
    dhpk = GenPubKey(dhsk);

    return true;
}

string OnivCrypto::uuid;
string OnivCrypto::sk;
string OnivCrypto::dhsk;
string OnivCrypto::dhpk;
vector<string> OnivCrypto::crts;
