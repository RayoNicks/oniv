#ifndef _LIB_ONIV_CRYPTO_H_
#define _LIB_ONIV_CRYPTO_H_

#include <cstddef>

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

void LoadAlgorithms();

int DER2PEM(int object, const char *in, size_t InLen, char *out, size_t OutLen);

int PEM2DER(int object, const char *in, size_t InLen, char *out, size_t OutLen);

size_t sign(const char *PrivateKey, size_t PrivateKeyLen,
            const char *data, size_t DataLen,
            char *signature, size_t SigLen, int format);

int verify(const char *cert, size_t CertLen,
        const char *data, size_t DataLen,
        const char *signature, size_t SigLen, int format);

int CheckCertificate(const char *CACerts, size_t CALength,
                    const char *UserCert, size_t UserLen, int UserFormat);

int GenECPrivateKey(const char *name, char *PrivateKey, size_t PrivateKeyLen, int format);

int GetECPublicKey(const char *PrivateKey, size_t PrivateKeyLen,
                    char *PublicKey, size_t PublicKeyLen, int format);

int ComputeSK(const char *PrivateKey, size_t PrivateKeyLen,
                const char *PublicKey, size_t PublicKeyLen,
                char *SessionKey, size_t SessionKeyLen, int format);

size_t encrypt(const char *cert, size_t CertLen,
            const char *plain, size_t PlainLen,
            char *cipher, size_t CipherLen, int format);

size_t decrypt(const char *PrivateKey, size_t PrivateKeyLen,
            const char *cipher, size_t CipherLen,
            char *plain, size_t PlainLen, int format);

int uuid5(const char *cert, size_t CertLen, char *uuid, size_t len, int format);

size_t GetSubjectName(const char *cert, size_t CertLen, char *subject, size_t len, int format);

const char* GetCurveName(const char *cert, size_t CertLen, int format);

size_t GCMEncryption(const char *name,
                    const char *key, size_t KeyLen, 
                    const char *plain, size_t PlainLen,
                    const char *InitVector, size_t InitVectorLen,
                    const char *AssData, size_t AssDataLen,
                    char *cipher, size_t CipherLen,
                    char *tag, size_t TagLen);

int GCMDecryption(const char *name,
                const char *key, size_t KeyLen, 
                const char *cipher, size_t CipherLen,
                const char *InitVector, size_t InitVectorLen,
                const char *AssData, size_t AssDataLen,
                char *plain, size_t PlainLen,
                char *tag, size_t TagLen);

size_t CCMEncryption(const char *key, size_t KeyLen, 
                    const char *plain, size_t PlainLen,
                    const char *InitVector, size_t InitVectorLen,
                    const char *AssData, size_t AssDataLen,
                    char *cipher, size_t CipherLen,
                    char *tag, size_t TagLen);

int CCMDecryption(const char *key, size_t KeyLen, 
            const char *cipher, size_t CipherLen,
            const char *InitVector, size_t InitVectorLen,
            const char *AssData, size_t AssDataLen,
            char *plain, size_t PlainLen,
            char *tag, size_t TagLen);

#ifdef __cplusplus
    }
#endif
}

#endif
