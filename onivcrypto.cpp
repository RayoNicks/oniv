#include "onivcrypto.h"

string OnivCrypto::UUID()
{
    return string();
}

uint16_t OnivCrypto::VerifyAlgSet()
{
    return 0xFFFF;
}

uint16_t OnivCrypto::KeyAgrAlgSet()
{
    return 0xFFFF;
}

vector<string> OnivCrypto::CertChain()
{
    return vector<string>();
}

string OnivCrypto::GenSignature()
{
    return string();
}

string OnivCrypto::GetPublicKey(uint16_t KeyAgrAlg)
{
    return string();
}
