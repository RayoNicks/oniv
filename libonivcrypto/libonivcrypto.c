#include <string.h>

#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <openssl/err.h>

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

void* LoadPem(const char *p, size_t len, int object)
{
    BIO *bp = NULL;
    EC_KEY *eckey = NULL;
    X509 *x = NULL;
    RSA *rsa = NULL;
    bp = BIO_new(BIO_s_mem());
    if(bp == NULL){
        return NULL;
    }
    BIO_write(bp, p, len);
    switch(object)
    {
    case OBJECT_ECC_PRI:
        eckey = PEM_read_bio_ECPrivateKey(bp, NULL, NULL, NULL);
        BIO_free(bp);
        return eckey;
    case OBJECT_ECC_PUB:
        eckey = PEM_read_bio_EC_PUBKEY(bp, NULL, NULL, NULL);
        BIO_free(bp);
        return eckey;
    case OBJECT_ECC_509:
        x = PEM_read_bio_X509_AUX(bp, NULL, NULL, NULL);
        BIO_free(bp);
        return x;
    case OBJECT_RSA_PRI:
        rsa = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL);
        BIO_free(bp);
        return rsa;
    case OBJECT_RSA_PUB:
        rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
        BIO_free(bp);
        return rsa;
    case OBJECT_RSA_509:
        x = PEM_read_bio_X509_AUX(bp, NULL, NULL, NULL);
        BIO_free(bp);
        return x;
    default:
        BIO_free(bp);
        return NULL;
    }
}

void* LoadAsn1(const char *p, size_t len, int object)
{
    BIO *bp = NULL;
    EC_KEY *eckey = NULL;
    X509 *x = NULL;
    RSA *rsa = NULL;
    bp = BIO_new(BIO_s_mem());
    if(bp == NULL){
        return NULL;
    }
    BIO_write(bp, p, len);
    switch(object)
    {
    case OBJECT_ECC_PRI:
        eckey = d2i_ECPrivateKey_bio(bp, NULL);
        BIO_free(bp);
        return eckey;
    case OBJECT_ECC_PUB:
        eckey = d2i_EC_PUBKEY_bio(bp, NULL);
        BIO_free(bp);
        return eckey;
    case OBJECT_ECC_509:
        x = d2i_X509_bio(bp, NULL);
        BIO_free(bp);
        return x;
    case OBJECT_RSA_PRI:
        rsa = d2i_RSAPrivateKey_bio(bp, NULL);
        BIO_free(bp);
        return rsa;
    case OBJECT_RSA_PUB:
        rsa = d2i_RSAPrivateKey_bio(bp, NULL);
        BIO_free(bp);
        return rsa;
    case OBJECT_RSA_509:
        x = d2i_X509_bio(bp, NULL);
        BIO_free(bp);
        return x;
    default:
        BIO_free(bp);
        return NULL;
    }
    
}

const EVP_MD* DigestFromEC(int nid)
{
    if(nid == NID_secp384r1){
        EVP_add_digest(EVP_sha384());
        return EVP_get_digestbyname("sha384");
    }
    else if(nid == NID_secp521r1){
        EVP_add_digest(EVP_sha512());
        return EVP_get_digestbyname("sha512");
    }
    else{
        return NULL;
    }
}

const EVP_MD* DigestFromRSA(int nid)
{
    if(nid == NID_sha256WithRSAEncryption){
        EVP_add_digest(EVP_sha256());
        return EVP_get_digestbyname("sha256");
    }
    else if(nid == NID_sha384WithRSAEncryption){
        EVP_add_digest(EVP_sha384());
        return EVP_get_digestbyname("sha384");
    }
    else if(nid == NID_sha512WithRSAEncryption){
        EVP_add_digest(EVP_sha512());
        return EVP_get_digestbyname("sha512");
    }
    else{
        return NULL;
    }
}

void LoadAsyKey(int format, int type, const char *buf, size_t len,
    void **object, EVP_PKEY **evpkey)
{
    EC_KEY **eckey;
    RSA ** rsa;
    X509 *x;

    if(object == NULL || evpkey == NULL){
        return;
    }
    if((*evpkey = EVP_PKEY_new()) == NULL){
        return;
    }
    if(type == OBJECT_ECC_PRI){
        eckey = (EC_KEY**)object;
        if(format == FORMAT_PEM){
            *eckey = (EC_KEY*)LoadPem(buf, len, type);
        }
        else if(format == FORMAT_ASN1){
            *eckey = (EC_KEY*)LoadAsn1(buf, len, type);
        }
        else{
            return;
        }
        if(*eckey == NULL){
            return;
        }
        EVP_PKEY_set1_EC_KEY(*evpkey, *eckey);
    }
    else if(type == OBJECT_ECC_509){
        eckey = (EC_KEY**)object;
        if(format == FORMAT_PEM){
            x = (X509*)LoadPem(buf, len, type);
        }
        else if(format == FORMAT_ASN1){
            x = (X509*)LoadAsn1(buf, len, type);;
        }
        else{
            return;
        }
        if(x == NULL){
            return;
        }
        *evpkey = X509_get_pubkey(x);
        *eckey = EVP_PKEY_get1_EC_KEY(*evpkey);
        X509_free(x);
    }
    else if(type == OBJECT_RSA_PRI){
        rsa = (RSA**)object;
        if(format == FORMAT_PEM){
            *rsa = (RSA*)LoadPem(buf, len, type);
        }
        else if(format == FORMAT_ASN1){
            *rsa = (RSA*)LoadAsn1(buf, len, type);
        }
        else{
            return;
        }
        if(*rsa == NULL){
            return;
        }
        EVP_PKEY_set1_RSA(*evpkey, *rsa);
    }
    else if(type == OBJECT_RSA_509){
        rsa = (RSA**)object;
        if(format == FORMAT_PEM){
            x = (X509*)LoadPem(buf, len, type);
        }
        else if(format == FORMAT_ASN1){
            x = (X509*)LoadAsn1(buf, len, type);;
        }
        else{
            return;
        }
        if(x == NULL){
            return;
        }
        *evpkey = X509_get_pubkey(x);
        *rsa = EVP_PKEY_get1_RSA(*evpkey);
        X509_free(x);
    }
    else{
        return;
    }
}

// 签名算法
size_t sign(const char *PrivateKey, size_t PrivateKeyLen,
            const char *data, size_t DataLen,
            char *signature, size_t SigLen, int format)
{
    EC_KEY *eckey = NULL;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = NULL;
    EVP_PKEY *evpkey = NULL;

    if(mdctx == NULL){
        goto err_sign;
    }

    LoadAsyKey(format, OBJECT_ECC_PRI, PrivateKey, PrivateKeyLen, (void**)&eckey, &evpkey);
    if(eckey == NULL || evpkey == NULL){
        printf("PrepareForSignAndVerify\n");
        goto err_sign;
    }

    if((md = DigestFromEC(EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)))) == NULL){
        goto err_sign;
    }

    if(SigLen < EVP_PKEY_size(evpkey)){
        printf("Signature buffer is too small\n");
        goto err_sign;
    }

    if(EVP_DigestSignInit(mdctx, NULL, md, NULL, evpkey) != 1){
        printf("Init\n");
        goto err_sign;
    }
    if(EVP_DigestSignUpdate(mdctx, data, DataLen) != 1){
        printf("Update\n");
        goto err_sign;
    }
    if(EVP_DigestSignFinal(mdctx, (unsigned char*)signature, &SigLen) != 1){
        printf("Final\n");
        goto err_sign;
    }
    return SigLen;

err_sign:
    EVP_PKEY_free(evpkey);
    EC_KEY_free(eckey);
    EVP_MD_CTX_destroy(mdctx);
    return 0;
}

int verify(const char *cert, size_t CertLen,
            const char *data, size_t DataLen,
            const char *signature, size_t SigLen, int format)
{
    EC_KEY *eckey = NULL;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = NULL;
    EVP_PKEY *evpkey = NULL;

    if(mdctx == NULL){
        goto err_verify;
    }

    LoadAsyKey(format, OBJECT_ECC_509, cert, CertLen, (void**)&eckey, &evpkey);
    if(eckey == NULL || evpkey == NULL){
        printf("PrepareForSignAndVerify\n");
        goto err_verify;
    }

    if((md = DigestFromEC(EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)))) == NULL){
        goto err_verify;
    }

    if(EVP_DigestVerifyInit(mdctx, NULL, md, NULL, evpkey) != 1){
        printf("Init\n");
        goto err_verify;
    }
    if(EVP_DigestVerifyUpdate(mdctx, data, DataLen) != 1){
        printf("Update\n");
        goto err_verify;
    }
    if(EVP_DigestVerifyFinal(mdctx, (const unsigned char*)signature, SigLen) != 1){
        printf("Final\n");
        ERR_print_errors_fp(stdout);
        goto err_verify;
    }
    return 1;

err_verify:
    EVP_PKEY_free(evpkey);
    EC_KEY_free(eckey);
    EVP_MD_CTX_destroy(mdctx);
    return 0;
}
