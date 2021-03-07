#include "onivcrypto.h"

string OnivCrypto::UUID()
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

initializer_list<OnivVerifyAlg> OnivCrypto::ListVerifyAlg()
{
    return { OnivVerifyAlg::IV_AES_128_GCM_SHA256, OnivVerifyAlg::IV_AES_128_CCM_SHA256 };
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

vector<string> OnivCrypto::CertChain()
{
    return crts;
}

OnivSigAlg OnivCrypto::PreSigAlg()
{
    return OnivSigAlg::RSA_PKCS1_SHA256;
}

string OnivCrypto::GenSignature(const string &data, OnivSigAlg SigAlg)
{
    // TODO
    return string(256, 'S');
    return string("signature");
}

string OnivCrypto::AcqPriKey(OnivKeyAgrAlg KeyAgrAlg)
{
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        return string("testing  private  key");
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP384R1){
        return string("SECP384R1 PriKey");
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP521R1){
        return string("SECP521R1 PriKey");
    }
    else{
        return string();
    }
}

string OnivCrypto::AcqPubKey(OnivKeyAgrAlg KeyAgrAlg)
{
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        return string("testing  public  key");
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP384R1){
        return string("SECP384R1 PubKey");
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP521R1){
        return string("SECP521R1 PubKey");
    }
    else{
        return string();
    }
}

string OnivCrypto::GenPriKey(OnivKeyAgrAlg KeyAgrAlg)
{
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        return string("generated private key");
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP384R1){
        return string("SECP384R1 PriKey");
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP521R1){
        return string("SECP521R1 PriKey");
    }
    else{
        return string();
    }
}

string OnivCrypto::GenPubKey(OnivKeyAgrAlg KeyAgrAlg, const string &PubKey)
{
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        return string("generated public key");
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP384R1){
        return string("SECP384R1 PubKey");
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP521R1){
        return string("SECP521R1 PubKey");
    }
    else{
        return string();
    }
}

string OnivCrypto::ComputeSessionKey(OnivKeyAgrAlg KeyAgrAlg, const string &PubKey, const string &PriKey)
{
    string key;
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        for(size_t i = 0; i < PubKey.length() && PriKey.length(); i++)
        {
            key.push_back(PubKey[i] ^ PriKey[i]);
        }
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP384R1){
        key.assign("SECP 384 R1   SK");
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP521R1){
        key.assign("SECP 521 R1   SK");
    }
    return key;
}

string OnivCrypto::MsgAuthCode(OnivVerifyAlg VerifyAlg, const string &SK, const string &UserData)
{
    if(VerifyAlg == OnivVerifyAlg::IV_SIMPLE_XOR){
        return string("xor xor xor xor.");
    }
    else if(VerifyAlg == OnivVerifyAlg::IV_AES_128_GCM_SHA256){
        return string("AES128GCM SHA256");
    }
    else if(VerifyAlg == OnivVerifyAlg::IV_AES_128_CCM_SHA256){
        return string("AES128CCM SHA256");
    }
    else{
        return string();
    }
}

string OnivCrypto::GenEscrowData(const string &Pk3rd, OnivVerifyAlg VerifyAlg, const string &SK)
{
    // 使用Pk3rd加密会话密钥
    return SK;
}

bool OnivCrypto::VerifySignature(const vector<string> &CertChain, const string &signature)
{
    return true;
}

size_t OnivCrypto::SignatureSize(OnivSigAlg SigAlg)
{
    switch (SigAlg)
    {
    case OnivSigAlg::RSA_PKCS1_SHA256:
    case OnivSigAlg::RSA_PKCS1_SHA384:
    case OnivSigAlg::RSA_PKCS1_SHA512:
        return 256;
    case OnivSigAlg::ECDSA_SECP384R1_SHA384:
    case OnivSigAlg::ECDSA_SECP521R1_SHA512:
        // TODO
        return 0;
    default:
        return 0;
    }
}

size_t OnivCrypto::PubKeySize(OnivKeyAgrAlg KeyAgrAlg)
{
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        return string("generated public key").length();
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP384R1){
        return 16;
    }
    else if(KeyAgrAlg == OnivKeyAgrAlg::KA_SECP521R1){
        return 16;
    }
    else{
        return 0;
    }
}

size_t OnivCrypto::MsgAuthCodeSize(OnivVerifyAlg VerifyAlg)
{
    if(VerifyAlg == OnivVerifyAlg::IV_SIMPLE_XOR){
        return 16;
    }
    else if(VerifyAlg == OnivVerifyAlg::IV_AES_128_GCM_SHA256){
        return 16;
    }
    else if(VerifyAlg == OnivVerifyAlg::IV_AES_128_CCM_SHA256){
        return 16;
    }
    else{
        return 0;
    }
}

size_t OnivCrypto::EscrowDataSize(const string &Pk3rd, OnivVerifyAlg VerifyAlg, const string &SK)
{
    // TODO
    return SK.length();
}

void OnivCrypto::LoadCrt(const string &HostName)
{
    crts.push_back("root");
    crts.push_back(HostName + HostName);
    while(uuid.size() < 16){
        uuid.append(HostName);
    }
    uuid.resize(16);
}

string OnivCrypto::uuid;
vector<string> OnivCrypto::crts;
