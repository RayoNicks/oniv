#include <string.h>

#include <openssl/asn1.h>
#include <openssl/ecdh.h>
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

void* LoadPem(const char *p, size_t len, int type)
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
    switch(type)
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

void LoadAlgorithms()
{
    EVP_add_digest(EVP_sha1());
    EVP_add_digest(EVP_sha384());
    EVP_add_digest(EVP_sha512());
    EVP_add_cipher(EVP_aes_128_gcm());
    EVP_add_cipher(EVP_aes_256_gcm());
    EVP_add_cipher(EVP_aes_128_ccm());
}

const EVP_MD* DigestFromCurve(int nid)
{
    if(nid == NID_secp384r1){
        return EVP_get_digestbyname("sha384");
    }
    else if(nid == NID_secp521r1){
        return EVP_get_digestbyname("sha512");
    }
    else{
        return NULL;
    }
}

void LoadObject(int format, int type, const char *buf, size_t len, void **object)
{
    EC_KEY **eckey;
    RSA ** rsa;
    X509 **x;

    if(object == NULL){
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
    }
    else if(type == OBJECT_ECC_PUB){
        eckey = (EC_KEY**)object;
        if(format == FORMAT_PEM){
            *eckey = (EC_KEY*)LoadPem(buf, len, type);
        }
        else if(format == FORMAT_ASN1){
            *eckey = (EC_KEY*)LoadAsn1(buf, len, type);;
        }
        else{
            return;
        }
        if(*eckey == NULL){
            return;
        }
    }
    else if(type == OBJECT_ECC_509){
        x = (X509**)object;
        if(format == FORMAT_PEM){
            *x = (X509*)LoadPem(buf, len, type);
        }
        else if(format == FORMAT_ASN1){
            *x = (X509*)LoadAsn1(buf, len, type);;
        }
        else{
            return;
        }
        if(*x == NULL){
            return;
        }
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
    }
    else if(type == OBJECT_RSA_509){
        x = (X509**)object;
        if(format == FORMAT_PEM){
            *x = (X509*)LoadPem(buf, len, type);
        }
        else if(format == FORMAT_ASN1){
            *x = (X509*)LoadAsn1(buf, len, type);;
        }
        else{
            return;
        }
        if(*x == NULL){
            return;
        }
    }
    else{
        return;
    }
}

int DER2PEM(int object, const char *in, size_t InLen, char *out, size_t OutLen)
{
    BIO *bp = NULL;
    EC_KEY *ecsk = NULL, *ecpk = NULL;
    X509 *x = NULL;
    int ret = 0;

    bp = BIO_new(BIO_s_mem());
    if(bp == NULL){
        goto err_d2p;
    }
    switch(object)
    {
    case OBJECT_ECC_PRI:
        LoadObject(FORMAT_ASN1, object, in, InLen, (void**)&ecsk);
        if(ecsk == NULL){
            goto err_d2p;
        }
        PEM_write_bio_ECPrivateKey(bp, ecsk, NULL, NULL, 0, NULL, NULL);
        break;
    case OBJECT_ECC_PUB:
        LoadObject(FORMAT_ASN1, object, in, InLen, (void**)&ecpk);
        if(ecpk == NULL){
            goto err_d2p;
        }
        PEM_write_bio_EC_PUBKEY(bp, ecpk);
        break;
    case OBJECT_ECC_509:
        LoadObject(FORMAT_ASN1, object, in, InLen, (void**)&x);
        if(x == NULL){
            goto err_d2p;
        }
        PEM_write_bio_X509(bp, x);
        break;
    default:
        goto err_d2p;
    }
    ret = BIO_read(bp, out, OutLen);
    if(ret == OutLen){
        ret = 0;
    }

err_d2p:
    BIO_free(bp);
    EC_KEY_free(ecsk);
    EC_KEY_free(ecpk);
    X509_free(x);
    return ret;
}

int PEM2DER(int object, const char *in, size_t InLen, char *out, size_t OutLen)
{
    BIO *bp = NULL;
    EC_KEY *ecsk = NULL, *ecpk = NULL;
    X509 *x = NULL;
    int ret = 0;

    bp = BIO_new(BIO_s_mem());
    if(bp == NULL){
        goto err_p2d;
    }
    switch(object)
    {
    case OBJECT_ECC_PRI:
        LoadObject(FORMAT_PEM, object, in, InLen, (void**)&ecsk);
        if(ecsk == NULL){
            goto err_p2d;
        }
        i2d_ECPrivateKey_bio(bp, ecsk);
        break;
    case OBJECT_ECC_PUB:
        LoadObject(FORMAT_PEM, object, in, InLen, (void**)&ecpk);
        if(ecpk == NULL){
            goto err_p2d;
        }
        i2d_EC_PUBKEY_bio(bp, ecpk);
        break;
    case OBJECT_ECC_509:
        LoadObject(FORMAT_PEM, object, in, InLen, (void**)&x);
        if(x == NULL){
            goto err_p2d;
        }
        i2d_X509_bio(bp, x);
        break;
    default:
        goto err_p2d;
    }
    ret = BIO_read(bp, out, OutLen);
    if(ret == OutLen){
        ret = 0;
    }

err_p2d:
    BIO_free(bp);
    EC_KEY_free(ecsk);
    EC_KEY_free(ecpk);
    X509_free(x);
    return ret;
}

size_t sign(const char *PrivateKey, size_t PrivateKeyLen,
            const char *data, size_t DataLen,
            char *signature, size_t SigLen, int format)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EC_KEY *eckey = NULL;
    EVP_PKEY *evpkey = NULL;
    const EVP_MD *md = NULL;
    size_t ret = 0;

    if(mdctx == NULL){
        goto err_sign;
    }

    LoadObject(format, OBJECT_ECC_PRI, PrivateKey, PrivateKeyLen, (void**)&eckey);
    if(eckey == NULL){
        goto err_sign;
    }

    evpkey = EVP_PKEY_new();
    if(evpkey == NULL){
        goto err_sign;
    }

    EVP_PKEY_set1_EC_KEY(evpkey, eckey);

    if((md = DigestFromCurve(EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)))) == NULL){
        goto err_sign;
    }

    if(SigLen < EVP_PKEY_size(evpkey)){
        goto err_sign;
    }

    if(EVP_DigestSignInit(mdctx, NULL, md, NULL, evpkey) != 1){
        goto err_sign;
    }
    if(EVP_DigestSignUpdate(mdctx, data, DataLen) != 1){
        goto err_sign;
    }
    if(EVP_DigestSignFinal(mdctx, (unsigned char*)signature, &SigLen) != 1){
        goto err_sign;
    }
    ret = SigLen;

err_sign:
    EVP_PKEY_free(evpkey);
    EC_KEY_free(eckey);
    EVP_MD_CTX_destroy(mdctx);
    return ret;
}

int verify(const char *cert, size_t CertLen,
        const char *data, size_t DataLen,
        const char *signature, size_t SigLen, int format)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    X509 *x = NULL;
    EVP_PKEY *evpkey = NULL;
    EC_KEY *eckey = NULL;
    const EVP_MD *md = NULL;
    int ret = 0;

    if(mdctx == NULL){
        goto err_verify;
    }

    LoadObject(format, OBJECT_ECC_509, cert, CertLen, (void**)&x);
    if(x == NULL){
        goto err_verify;
    }

    evpkey = X509_get_pubkey(x);
    if(evpkey == NULL){
        goto err_verify;
    }

    eckey = EVP_PKEY_get1_EC_KEY(evpkey);
    if(eckey == NULL){
        goto err_verify;
    }

    if((md = DigestFromCurve(EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)))) == NULL){
        goto err_verify;
    }

    if(EVP_DigestVerifyInit(mdctx, NULL, md, NULL, evpkey) != 1){
        goto err_verify;
    }
    if(EVP_DigestVerifyUpdate(mdctx, data, DataLen) != 1){
        goto err_verify;
    }
    if(EVP_DigestVerifyFinal(mdctx, (const unsigned char*)signature, SigLen) != 1){
        goto err_verify;
    }
    ret = 1;

err_verify:
    EC_KEY_free(eckey);
    EVP_PKEY_free(evpkey);
    X509_free(x);
    EVP_MD_CTX_destroy(mdctx);
    return ret;
}

int CheckCertificate(const char *CACerts, size_t CALength,
                    const char *UserCert, size_t UserLen, int UserFormat)
{
    X509_STORE_CTX *StoreCtx = NULL;
    X509_STORE *store = NULL;
    BIO *ca = NULL, *user = NULL;
    STACK_OF(X509_INFO) *InfoStack = NULL;
    X509 *x = NULL;
    X509_INFO *info = NULL;
    int i = 0, ret = 0;

    StoreCtx = X509_STORE_CTX_new();
    if(StoreCtx == NULL){
        goto err_check;
    }
    store = X509_STORE_new();
    if(store == NULL){
        goto err_check;
    }
    ca = BIO_new(BIO_s_mem());
    if(ca == NULL){
        goto err_check;
    }
    BIO_write(ca, CACerts, CALength);
    InfoStack = PEM_X509_INFO_read_bio(ca, NULL, NULL, NULL);
    if(InfoStack == NULL){
        goto err_check;
    }
    for (i = 0; i < sk_X509_INFO_num(InfoStack); i++) {
        info = sk_X509_INFO_value(InfoStack, i);
        if(info->x509) {
            X509_STORE_add_cert(store, info->x509);
        }
        if(info->crl) {
            X509_STORE_add_crl(store, info->crl);
        }
    }

    LoadObject(UserFormat, OBJECT_ECC_509, UserCert, UserLen, (void**)&x);
    if(x == NULL){
        goto err_check;
    }

    if(X509_STORE_CTX_init(StoreCtx, store, x, NULL) == 0){
        goto err_check;
    }
    if(X509_verify_cert(StoreCtx) == 1){
        ret = 1;
    }

err_check:
    X509_free(x);
    BIO_free(user);
    sk_X509_INFO_pop_free(InfoStack, X509_INFO_free);
    BIO_free(ca);
    X509_STORE_free(store);
    X509_STORE_CTX_free(StoreCtx);
    return ret;
}

int GenECPrivateKey(const char *name, char *PrivateKey, size_t PrivateKeyLen, int format)
{
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;
    BIO *pri = NULL, *pub = NULL;
    int ret = 0;

    eckey = EC_KEY_new();
    if(eckey == NULL){
        goto err_gen_ec_pri;
    }

    group = EC_GROUP_new_by_curve_name(OBJ_sn2nid(name));
    if(group == NULL){
        goto err_gen_ec_pri;
    }

    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
    EC_KEY_set_group(eckey, group);
    
    if(EC_KEY_generate_key(eckey) == 0){
        goto err_gen_ec_pri;
    }

    pri = BIO_new(BIO_s_mem());
    if(format == FORMAT_PEM){
        PEM_write_bio_ECPrivateKey(pri, eckey, NULL, NULL, 0, NULL, NULL);
    }
    else if(format == FORMAT_ASN1){
        i2d_ECPrivateKey_bio(pri, eckey);
    }
    else{
        goto err_gen_ec_pri;
    }

    ret = BIO_read(pri, PrivateKey, PrivateKeyLen);
    if(ret == PrivateKeyLen){
        ret = 0;
    }

err_gen_ec_pri:
    BIO_free(pub);
    BIO_free(pri);
    EC_GROUP_free(group);
    EC_KEY_free(eckey);
    return ret;
}

int GetECPublicKey(const char *PrivateKey, size_t PrivateKeyLen,
                    char *PublicKey, size_t PublicKeyLen, int format)
{
    EC_KEY *eckey = NULL;
    const EC_GROUP *group = NULL;
    int ret = 0;

    LoadObject(format, OBJECT_ECC_PRI, PrivateKey, PrivateKeyLen, (void**)&eckey);
    if(eckey == NULL){
        goto err_get_ec_pub;
    }

    group = EC_KEY_get0_group(eckey);
    if(group == NULL){
        goto err_get_ec_pub;
    }
    ret = EC_POINT_point2oct(group, EC_KEY_get0_public_key(eckey), POINT_CONVERSION_COMPRESSED, (unsigned char*)PublicKey, PublicKeyLen, NULL);

err_get_ec_pub:
    EC_KEY_free(eckey);
    return ret;
}

int ComputeSK(const char *PrivateKey, size_t PrivateKeyLen,
                const char *PublicKey, size_t PublicKeyLen,
                char *SessionKey, size_t SessionKeyLen, int format)
{
    EC_KEY *ecsk = NULL;
    const EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    int ret = 0;

    LoadObject(format, OBJECT_ECC_PRI, PrivateKey, PrivateKeyLen, (void**)&ecsk);
    if(ecsk == NULL){
        goto err_com_sk;
    }

    group = EC_KEY_get0_group(ecsk);
    if(group == NULL){
        goto err_com_sk;
    }

    point = EC_POINT_new(group);
    if(point == NULL){
        goto err_com_sk;
    }

    if(EC_POINT_oct2point(group, point, (unsigned char*)PublicKey, PublicKeyLen, NULL) == 0){
        goto err_com_sk;
    }

    ret = ECDH_compute_key(SessionKey, SessionKeyLen, point, ecsk, NULL);

err_com_sk:
    EC_POINT_free(point);
    EC_KEY_free(ecsk);
    return ret;
}

size_t encrypt(const char *cert, size_t CertLen,
            const char *plain, size_t PlainLen,
            char *cipher, size_t CipherLen, int format)
{
    X509 *x = NULL;
    EVP_PKEY *evpkey = NULL;
    EC_GROUP *group = NULL;
    EC_KEY *ecpk = NULL, *ecsk = NULL;
    char session[128] = { 0 }, pk[256] = { 0 };
    int size = 0, pklen = 0;
    size_t i, j;

    LoadObject(format, OBJECT_ECC_509, cert, CertLen, (void**)&x);
    if(x == NULL){
        goto err_encrypt;
    }

    evpkey = X509_get_pubkey(x);
    if(evpkey == NULL){
        goto err_encrypt;
    }

    ecpk = EVP_PKEY_get1_EC_KEY(evpkey);
    if(ecpk == NULL){
        goto err_encrypt;
    }

    ecsk = EC_KEY_new();
    if(ecsk == NULL){
        goto err_encrypt;
    }

    group = EC_GROUP_new_by_curve_name(EC_GROUP_get_curve_name(EC_KEY_get0_group(ecpk)));
    if(group == NULL){
        goto err_encrypt;
    }
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
    EC_KEY_set_group(ecsk, group);

    if(EC_KEY_generate_key(ecsk) == 0){
        goto err_encrypt;
    }

    size = ECDH_compute_key(session, sizeof(session), EC_KEY_get0_public_key(ecpk), ecsk, NULL);
    if(size == 0){
        goto err_encrypt;
    }

    pklen = EC_POINT_point2oct(group, EC_KEY_get0_public_key(ecsk), POINT_CONVERSION_COMPRESSED, (unsigned char*)pk, sizeof(pk), NULL);
    if(pklen == 0){
        goto err_encrypt;
    }

    if(CipherLen < 2 + pklen + PlainLen){
        goto err_encrypt;
    }

    *cipher = (pklen >> 16) & 0xFF;
    *(cipher + 1) = pklen & 0xFF;
    cipher += 2;
    memcpy(cipher, pk, pklen);
    cipher += pklen;

    for(i = 0, j = 0; i < PlainLen; i++, j++)
    {
        cipher[i] = plain[i] ^ session[j];
        if(j == size){
            j = 0;
        }
    }
    return 2 + pklen + PlainLen;

err_encrypt:
    EC_GROUP_free(group);
    EC_KEY_free(ecsk);
    EC_KEY_free(ecpk);
    EVP_PKEY_free(evpkey);
    X509_free(x);
    return 0;
}

size_t decrypt(const char *PrivateKey, size_t PrivateKeyLen,
            const char *cipher, size_t CipherLen,
            char *plain, size_t PlainLen, int format)
{
    EC_KEY *ecpk = NULL, *ecsk = NULL;
    const EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    char session[128] = { 0 };
    int size = 0, pklen = 0;
    size_t i, j;

    LoadObject(format, OBJECT_ECC_PRI, PrivateKey, PrivateKeyLen, (void**)&ecsk);
    if(ecsk == NULL){
        goto err_decrypt;
    }

    pklen = (((*cipher) << 16) & 0xFF00) | (*(cipher + 1) & 0xFF);

    group = EC_KEY_get0_group(ecsk);
    if(group == NULL){
        goto err_decrypt;
    }

    point = EC_POINT_new(group);
    if(point == NULL){
        goto err_decrypt;
    }

    if(EC_POINT_oct2point(group, point, (unsigned char*)cipher + 2, pklen, NULL) == 0){
        goto err_decrypt;
    }

    size = ECDH_compute_key(session, sizeof(session), point, ecsk, NULL);
    if(size == 0){
        goto err_decrypt;
    }

    cipher += 2 + pklen;
    CipherLen -= 2 + pklen;

    for(i = 0, j = 0; i < CipherLen; i++, j++)
    {
        plain[i] = cipher[i] ^ session[j];
        if(j == size){
            j = 0;
        }
    }
    return CipherLen;

err_decrypt:
    EC_KEY_free(ecsk);
    EC_POINT_free(point);
    EC_KEY_free(ecpk);
    return 0;
}

int uuid5(const char *cert, size_t CertLen, char *uuid, size_t len, int format)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    X509 *x = NULL;
    EVP_PKEY *evpkey = NULL;
    EC_KEY *ecpk = NULL;
    const EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;
    const EVP_MD *md = NULL;
    char pk[256] = { 0 }, sha1[20] = { 0 };
    int size = 0, ret = 0;

    if(mdctx == NULL){
        goto err_uuid5;
    }

    if(len < 16){
        goto err_uuid5;
    }

    LoadObject(format, OBJECT_ECC_509, cert, CertLen, (void**)&x);
    if(x == NULL){
        goto err_uuid5;
    }

    evpkey = X509_get_pubkey(x);
    if(evpkey == NULL){
        goto err_uuid5;
    }

    ecpk = EVP_PKEY_get1_EC_KEY(evpkey);
    if(ecpk == NULL){
        goto err_uuid5;
    }

    group = EC_KEY_get0_group(ecpk);
    point = EC_KEY_get0_public_key(ecpk);
    size = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)pk, sizeof(pk), NULL);
    if(size == 0){
        goto err_uuid5;
    }

    if((md = EVP_get_digestbyname("sha1")) == NULL){
        goto err_uuid5;
    }

    if(EVP_DigestInit(mdctx, md) != 1){
        goto err_uuid5;
    }
    if(EVP_DigestUpdate(mdctx, pk, size) != 1){
        goto err_uuid5;
    }
    if(EVP_DigestFinal(mdctx, (unsigned char*)sha1, (unsigned int*)&size) != 1){
        goto err_uuid5;
    }

    memcpy(uuid, sha1, 16);
    uuid[6] &= 0x0F;
    uuid[6] |= 0x50;
    uuid[8] &= 0x3F;
    uuid[8] |= 0x80;
    ret = 1;

err_uuid5:
    EVP_PKEY_free(evpkey);
    X509_free(x);
    EVP_MD_CTX_destroy(mdctx);
    return ret;
}

size_t GetSubjectName(const char *cert, size_t CertLen, char *subject, size_t len, int format)
{
    X509 *x = NULL;
    X509_NAME *name = NULL;
    BIO *bp = NULL;
    char *OneLine = NULL;
    size_t ret = 0;

    LoadObject(format, OBJECT_ECC_509, cert, CertLen, (void**)&x);
    if(x == NULL){
        goto err_get_subject;
    }
    name = X509_get_subject_name(x);
    if(name == NULL){
        goto err_get_subject;
    }
    bp = BIO_new(BIO_s_mem());
    if(bp == NULL){
        goto err_get_subject;
    }
    OneLine = X509_NAME_oneline(name, NULL, 0);
    if(strlen(OneLine) > len){
        goto err_get_subject;
    }
    memcpy(subject, OneLine, strlen(OneLine));
    ret = strlen(OneLine);

err_get_subject:
    OPENSSL_free(OneLine);
    X509_free(x);
    return ret;
}

const char* GetCurveName(const char *cert, size_t CertLen, int format)
{
    X509 *x = NULL;
    EVP_PKEY *evpkey = NULL;
    EC_KEY *ecpk = NULL;
    const char *ret = NULL;

    LoadObject(format, OBJECT_ECC_509, cert, CertLen, (void**)&x);
    if(x == NULL){
        goto err_curve_name;
    }
    evpkey = X509_get_pubkey(x);
    if(evpkey == NULL){
        goto err_curve_name;
    }
    ecpk = EVP_PKEY_get1_EC_KEY(evpkey);
    if(ecpk == NULL){
        goto err_curve_name;
    }
    ret = OBJ_nid2sn(EC_GROUP_get_curve_name(EC_KEY_get0_group(ecpk)));

err_curve_name:
    EC_KEY_free(ecpk);
    EVP_PKEY_free(evpkey);
    X509_free(x);
    return ret;
}

size_t GCMEncryption(const char *name,
                const char *key, size_t KeyLen, 
                const char *plain, size_t PlainLen,
                const char *InitVector, size_t InitVectorLen,
                const char *AssData, size_t AssDataLen,
                char *cipher, size_t CipherLen,
                char *tag, size_t TagLen)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    size_t ret = 0;

    if(CipherLen < PlainLen || TagLen != 16){
        goto err_gcm_enc;
    }

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        goto err_gcm_enc;
    }
    if(EVP_EncryptInit_ex(ctx, EVP_get_cipherbyname(name), NULL, NULL, NULL) != 1){
        goto err_gcm_enc;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, InitVectorLen, NULL) != 1){
        goto err_gcm_enc;
    }
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char*)key, (const unsigned char*)InitVector) != 1){
        goto err_gcm_enc;
    }
    if(EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char*)AssData, AssDataLen) != 1){
        goto err_gcm_enc;
    }
    if(EVP_EncryptUpdate(ctx, (unsigned char*)cipher, (int*)&CipherLen, (const unsigned char*)plain, PlainLen) != 1){
        goto err_gcm_enc;
    }
    if(EVP_EncryptFinal_ex(ctx, (unsigned char*)(cipher + CipherLen), &len) != 1){
        goto err_gcm_enc;
    }
    CipherLen += len;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TagLen, tag) != 1){
        goto err_gcm_enc;
    }
    ret = CipherLen;

err_gcm_enc:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int GCMDecryption(const char *name,
                const char *key, size_t KeyLen, 
                const char *cipher, size_t CipherLen,
                const char *InitVector, size_t InitVectorLen,
                const char *AssData, size_t AssDataLen,
                char *plain, size_t PlainLen,
                char *tag, size_t TagLen)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ret = 0;

    if(PlainLen < CipherLen || TagLen != 16){
        goto err_gcm_dec;
    }

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        goto err_gcm_dec;
    }
    if(EVP_DecryptInit_ex(ctx, EVP_get_cipherbyname(name), NULL, NULL, NULL) != 1){
        goto err_gcm_dec;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, InitVectorLen, NULL) != 1){
        goto err_gcm_dec;
    }
    if(EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char*)key, (const unsigned char*)InitVector) != 1){
        goto err_gcm_dec;
    }
    if(EVP_DecryptUpdate(ctx, NULL, &len, (const unsigned char*)AssData, AssDataLen) != 1){
        goto err_gcm_dec;
    }
    if(EVP_DecryptUpdate(ctx, (unsigned char*)plain, (int*)&PlainLen, (const unsigned char*)cipher, CipherLen) != 1){
        goto err_gcm_dec;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TagLen, tag) != 1){
        goto err_gcm_dec;
    }
    if(EVP_DecryptFinal_ex(ctx, (unsigned char*)(plain + PlainLen), &len) != 1){
        goto err_gcm_dec;
    }
    PlainLen += len;
    ret = 1;

err_gcm_dec:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

size_t CCMEncryption(const char *key, size_t KeyLen, 
                const char *plain, size_t PlainLen,
                const char *InitVector, size_t InitVectorLen,
                const char *AssData, size_t AssDataLen,
                char *cipher, size_t CipherLen,
                char *tag, size_t TagLen)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    size_t ret = 0;

    if(CipherLen < PlainLen || TagLen != 16){
        goto err_ccm_enc;
    }
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        goto err_ccm_enc;
    }
    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) != 1){
        goto err_ccm_enc;
    }
    // L长度默认为8，因此必须是15 - 8 = 7，可以通过EVP_CTRL_CCM_SET_L修改L
    // if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL) != 1){
    //     goto err_ccm_dec;
    // }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TagLen, NULL) != 1){
        goto err_ccm_enc;
    }
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char*)key, (const unsigned char*)InitVector) != 1){
        goto err_ccm_enc;
    }
    if(EVP_EncryptUpdate(ctx, NULL, &len, NULL, PlainLen) != 1){
        goto err_ccm_enc;
    }
    if(EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char*)AssData, AssDataLen) != 1){
        goto err_ccm_enc;
    }
    if(EVP_EncryptUpdate(ctx, (unsigned char*)cipher, (int*)&CipherLen, (const unsigned char*)plain, PlainLen) != 1){
        goto err_ccm_enc;
    }
    if(EVP_EncryptFinal_ex(ctx, (unsigned char*)(cipher + CipherLen), &len) != 1){
        goto err_ccm_enc;
    }
    CipherLen += len;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, TagLen, tag) != 1){
        goto err_ccm_enc;
    }
    ret = CipherLen;

err_ccm_enc:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int CCMDecryption(const char *key, size_t KeyLen, 
                const char *cipher, size_t CipherLen,
                const char *InitData, size_t InitDataLen,
                const char *AssData, size_t AssDataLen,
                char *plain, size_t PlainLen,
                char *tag, size_t TagLen)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ret = 0;

    if(PlainLen < CipherLen || TagLen != 16){
        goto err_ccm_dec;
    }

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        goto err_ccm_dec;
    }
    if(EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) != 1){
        goto err_ccm_dec;
    }
    // L长度默认为8，因此必须是15 - 8 = 7，可以通过EVP_CTRL_CCM_SET_L修改L
    // if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL) != 1){
    //     goto err_ccm_dec;
    // }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TagLen, tag) != 1){
        goto err_ccm_dec;
    }
    if(EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char*)key, (const unsigned char*)InitData) != 1){
        goto err_ccm_dec;
    }
    if(EVP_DecryptUpdate(ctx, NULL, &len, NULL, CipherLen) != 1){
        goto err_ccm_dec;
    }
    if(EVP_DecryptUpdate(ctx, NULL, &len, (const unsigned char*)AssData, AssDataLen) != 1){
        goto err_ccm_dec;
    }
    if(EVP_DecryptUpdate(ctx, (unsigned char*)plain, (int*)&PlainLen, (const unsigned char*)cipher, CipherLen) != 1){
        goto err_ccm_dec;
    }
    ret = 1;

err_ccm_dec:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
