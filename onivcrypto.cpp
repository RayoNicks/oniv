#include "onivcrypto.h"

string OnivCrypto::UUID()
{
    return string();
}

OnivVerifyAlg OnivCrypto::VerifyAlgSet()
{
    return OnivVerifyAlg::ALL;
}

OnivKeyAgrAlg OnivCrypto::KeyAgrAlgSet()
{
    return OnivKeyAgrAlg::ALL;
}

vector<string> OnivCrypto::CertChain()
{
    return vector<string>();
}

string OnivCrypto::GenSignature(const string &data)
{
    return string();
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
        for(size_t i = 0; i < PubKey.size() && PriKey.size(); i++)
        {
            key.push_back(PubKey[i] ^ PriKey[i]);
        }
    }
    else{
        return key;
    }
}

string OnivCrypto::MsgAuthCode(OnivVerifyAlg VerifyAlg, const string &SK, const string &UserData)
{
    string code;
    if(VerifyAlg == OnivVerifyAlg::IV_SIMPLE_XOR){
        size_t i = 0;
        while(i < UserData.length()){
            for(size_t j = 0; j < SK.length(); j++)
            {
                code.push_back(0x00);
            }
        }
        return code;
    }
    else{
        return string();
    }
}

size_t OnivCrypto::PubKeySize(OnivKeyAgrAlg KeyAgrAlg)
{
    if(KeyAgrAlg == OnivKeyAgrAlg::KA_SIMPLE_XOR){
        return sizeof("generated public key");
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
