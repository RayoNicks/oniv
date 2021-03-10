#ifndef _LIB_ONIV_CRYPTO_H_
#define _LIB_ONIV_CRYPTO_H_

namespace libonivcrypto
{
#ifdef __cplusplus
    extern "C" {
#endif

enum FORMAT
{
    FORMAT_UND, FORMAT_PEM, FORMAT_ASN1
};

enum OBJECT
{
    OBJECT_UND,
    OBJECT_ECC_PRI, OBJECT_ECC_PUB, OBJECT_ECC_509,
    OBJECT_RSA_PRI, OBJECT_RSA_PUB, OBJECT_RSA_509
};

size_t sign(const char *PrivateKey, size_t PrivateKeyLen,
            const char *data, size_t DataLen,
            char *signature, size_t SigLen, int format);

int verify(const char *certificate, size_t CertLen,
            const char *data, size_t DataLen,
            const char *signature, size_t SigLen, int format);

#ifdef __cplusplus
    }
#endif
}

#endif
