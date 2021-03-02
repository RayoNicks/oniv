#include "onivcrypto.h"

string OnivCrypto::UUID()
{
    return uuid;
}

OnivVerifyAlg OnivCrypto::VerifyAlgSet()
{
    return OnivVerifyAlg::ALL;
}

OnivKeyAgrAlg OnivCrypto::KeyAgrAlgSet()
{
    return OnivKeyAgrAlg::ALL;
}

OnivVerifyAlg OnivCrypto::SelectVerifyAlg(OnivVerifyAlg pre, OnivVerifyAlg sup)
{
    return pre;
}

OnivKeyAgrAlg OnivCrypto::SelectKeyAgrAlg(OnivKeyAgrAlg pre, OnivKeyAgrAlg sup)
{
    return pre;
}

vector<string> OnivCrypto::CertChain()
{
    return crts;
}

string OnivCrypto::GenSignature(const string &data)
{
    return string("signature");
}

string OnivCrypto::AcqPriKey(OnivKeyAgrAlg KeyAgrAlg)
{
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        return string("testing  private  key");
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
    else{
        return string();
    }
}

string OnivCrypto::GenPriKey(OnivKeyAgrAlg KeyAgrAlg)
{
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        return string("generated private key");
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
    return key;
}

string OnivCrypto::MsgAuthCode(OnivVerifyAlg VerifyAlg, const string &SK, const string &UserData)
{
    string code;
    if(VerifyAlg == OnivVerifyAlg::IV_SIMPLE_XOR){
        return string("xor xor xor xor.");
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

bool OnivCrypto::VerifySignature(const vector<string> CertChain, const string &signature)
{
    return true;
}

size_t OnivCrypto::PubKeySize(OnivKeyAgrAlg KeyAgrAlg)
{
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        return string("generated public key").length();
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
    else{
        return 0;
    }
}

size_t OnivCrypto::EscrowDataSize(const string &Pk3rd, OnivVerifyAlg VerifyAlg, const string &SK)
{
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
