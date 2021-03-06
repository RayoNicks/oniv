#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

typedef struct SimpleBuffer
{
    void *buf;
    int len;
} Buffer;

void ReadPemFile(Buffer *buffer, const char *FileName)
{
    FILE *file;
    size_t read;
    file = fopen(FileName, "r");
    if(file == NULL){
        return;
    }
    buffer->len = 4096;
    buffer->buf = OPENSSL_malloc(buffer->len);
    read = fread(buffer->buf, 1, buffer->len, file);
    if(read < 0){
        return;
    }
    buffer->len = read;
    fclose(file);
}

void WritePemFile(Buffer *buffer, const char *FileName)
{
    FILE *file;
    size_t written;
    file = fopen(FileName, "w");
    if(file == NULL){
        return;
    }
    written = fwrite(buffer->buf, 1, buffer->len, file);
    if(written < 0){
        return;
    }
    fclose(file);
}

void RSASignature()
{
    Buffer PrivateKey, data, signature;
    BIO *key = NULL, *out = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    int keysize, SigSize;

    ReadPemFile(&PrivateKey, "guest1.pem");
    data.len = strlen("0123456789abcdef");
    data.buf = OPENSSL_malloc(data.len);
    memcpy(data.buf, "0123456789abcdef", data.len);

    key = BIO_new(BIO_s_mem());
    if(key == NULL){
        return;
    }
    BIO_write(key, PrivateKey.buf, PrivateKey.len);
    pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
    if(pkey == NULL){
        return;
    }
    rsa = EVP_PKEY_get1_RSA(pkey);
    if(rsa == NULL){
        return;
    }
    keysize = RSA_size(rsa);
    signature.len = keysize;
    signature.buf = OPENSSL_malloc(keysize);
    signature.len = RSA_private_encrypt(data.len, data.buf, signature.buf, rsa, RSA_PKCS1_PADDING);

    WritePemFile(&signature, "guest1.sig");

    BIO_free(key);
    BIO_free(out);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    if(PrivateKey.buf){
        OPENSSL_free(PrivateKey.buf);
    }
    if(data.buf){
        OPENSSL_free(data.buf);
    }
    if(signature.buf){
        OPENSSL_free(signature.buf);
    }
    printf("Sign successfully\n");
}

void RSAVerificationByCert()
{
    Buffer PublicKey, signature, origin;
    BIO *cert = NULL;
    X509 *x = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    int keysize, OriginSize;

    ReadPemFile(&PublicKey, "guest1.crt");
    ReadPemFile(&signature, "guest1.sig");

    cert = BIO_new(BIO_s_mem());
    if(cert == NULL){
        return;
    }
    BIO_write(cert, PublicKey.buf, PublicKey.len);
    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    if(x == NULL){
        return;
    }
    pkey = X509_get_pubkey(x);
    if(pkey == NULL){
        return;
    }
    rsa = EVP_PKEY_get1_RSA(pkey);
    if(rsa == NULL){
        return;
    }
    keysize = RSA_size(rsa);
    origin.len = 128;
    origin.buf = OPENSSL_malloc(origin.len);
    origin.len = RSA_public_decrypt(signature.len, signature.buf, origin.buf, rsa, RSA_PKCS1_PADDING);

    WritePemFile(&origin, "guest1.dat");

    BIO_free(cert);
    X509_free(x);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    if(PublicKey.buf){
        OPENSSL_free(PublicKey.buf);
    }
    if(signature.buf){
        OPENSSL_free(signature.buf);
    }
    if(origin.buf){
        OPENSSL_free(origin.buf);
    }
    printf("Verify signature passed\n");
}

void RSASha256Signature()
{
    Buffer PrivateKey, data, signature;
    BIO *key = NULL;
    EVP_PKEY *sigkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    const EVP_MD *md = NULL;
    int keysize;

    ReadPemFile(&PrivateKey, "guest1.pem");
    data.len = strlen("0123456789abcdef");
    data.buf = OPENSSL_malloc(data.len);
    memcpy(data.buf, "0123456789abcdef", data.len);

    key = BIO_new(BIO_s_mem());
    if(key == NULL){
        return;
    }
    BIO_write(key, PrivateKey.buf, PrivateKey.len);
    sigkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
    if(sigkey == NULL){
        return;
    }
    mctx = EVP_MD_CTX_create();
    EVP_add_digest(EVP_sha256());
    md = EVP_get_digestbyname("sha256");
    if(md == NULL){
        printf("EVP_get_digestbyname\n");
        return;
    }
    keysize = EVP_PKEY_size(sigkey);
    signature.len = keysize;
    signature.buf = OPENSSL_malloc(signature.len);

    if(EVP_DigestSignInit(mctx, NULL, md, NULL, sigkey) == 0){
        printf("EVP_DigestSignInit\n");
        return;
    }
    if(EVP_DigestSignUpdate(mctx, data.buf, data.len) == 0){
        printf("EVP_DigestSignUpdate\n");
        return;
    }
    if(EVP_DigestSignFinal(mctx, signature.buf, (size_t*)&signature.len) == 0){
        printf("EVP_DigestSignFinal\n");
        return;
    }

    WritePemFile(&signature, "guest1.sig");

    BIO_free(key);
    EVP_PKEY_free(sigkey);
    EVP_MD_CTX_destroy(mctx);
    if(PrivateKey.buf){
        OPENSSL_free(PrivateKey.buf);
    }
    if(data.buf){
        OPENSSL_free(data.buf);
    }
    if(signature.buf){
        OPENSSL_free(signature.buf);
    }
    printf("Sign successfully\n");
}

void RSASha256VerifyByCert()
{
    Buffer PublicKey, signature, origin;
    BIO *cert = NULL;
    X509 *x = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    EVP_MD_CTX *mctx = NULL;
    const EVP_MD *md = NULL;
    int keysize, OriginSize;
    
    ReadPemFile(&PublicKey, "guest1.crt");
    ReadPemFile(&signature, "guest1.sig");

    cert = BIO_new(BIO_s_mem());
    if(cert == NULL){
        return;
    }
    BIO_write(cert, PublicKey.buf, PublicKey.len);
    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    if(x == NULL){
        return;
    }
    pkey = X509_get_pubkey(x);
    if(pkey == NULL){
        return;
    }
    rsa = EVP_PKEY_get1_RSA(pkey);
    if(rsa == NULL){
        return;
    }
    keysize = RSA_size(rsa);
    origin.len = strlen("0123456789abcdef");
    origin.buf = OPENSSL_malloc(origin.len);
    memcpy(origin.buf, "0123456789abcdef", origin.len);

    mctx = EVP_MD_CTX_create();
    EVP_add_digest(EVP_sha256());
    md = EVP_get_digestbyname("sha256");
    if(EVP_DigestVerifyInit(mctx, NULL, md, NULL, pkey) == 0){
        printf("EVP_DigestVerifyInit\n");
        return;
    }
    if(EVP_DigestVerifyUpdate(mctx, origin.buf, origin.len) == 0){
        printf("EVP_DigestVerifyUpdate\n");
        return;
    }
    if(EVP_DigestVerifyFinal(mctx, signature.buf, signature.len) == 0){
        printf("EVP_DigestVerifyFinal\n");
        return;
    }

    BIO_free(cert);
    X509_free(x);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    EVP_MD_CTX_destroy(mctx);
    if(PublicKey.buf){
        OPENSSL_free(PublicKey.buf);
    }
    if(signature.buf){
        OPENSSL_free(signature.buf);
    }
    if(origin.buf){
        OPENSSL_free(origin.buf);
    }
    printf("Verify signature passed\n");
}

void VerifyCerts()
{
    Buffer CACert, GuestCert;
    X509_STORE_CTX *csc = NULL;
    X509_STORE *cert_ctx = NULL;
    BIO *cert = NULL, *ca = NULL;
    X509 *x = NULL;
    STACK_OF(X509_INFO) *info = NULL;
    X509_INFO *itmp = NULL;
    int i;

    ReadPemFile(&CACert, "chain.crt");
    ReadPemFile(&GuestCert, "third.crt");

    csc = X509_STORE_CTX_new();
    if(csc == NULL) {
        return;
    }
    cert_ctx = X509_STORE_new();
    if(cert_ctx == NULL){
        return;
    }
    ca = BIO_new(BIO_s_mem());
    if(ca == NULL){
        return;
    }
    BIO_write(ca, CACert.buf, CACert.len);
    info = PEM_X509_INFO_read_bio(ca, NULL, NULL, NULL);
    if(info == NULL){
        return;
    }
    for (i = 0; i < sk_X509_INFO_num(info); i++) {
        itmp = sk_X509_INFO_value(info, i);
        if(itmp->x509) {
            X509_STORE_add_cert(cert_ctx, itmp->x509);
        }
        if(itmp->crl) {
            X509_STORE_add_crl(cert_ctx, itmp->crl);
        }
    }

    cert = BIO_new(BIO_s_mem());
    if(cert == NULL){
        return;
    }
    BIO_write(cert, GuestCert.buf, GuestCert.len);
    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    if(x == NULL){
        return;
    }
    if(X509_STORE_CTX_init(csc, cert_ctx, x, NULL) == 0){
        return;
    }
    i = X509_verify_cert(csc);
    if(i < 0){
        return;
    }
    X509_STORE_CTX_free(csc);
    X509_STORE_free(cert_ctx);
    BIO_free(cert);
    BIO_free(ca);
    X509_free(x);
    sk_X509_INFO_pop_free(info, X509_INFO_free);
    if(CACert.buf){
        OPENSSL_free(CACert.buf);
    }
    if(GuestCert.buf){
        OPENSSL_free(GuestCert.buf);
    }
    printf("Certificate verification passed\n");
}

void RSAEncryptionByCert()
{
    Buffer PublicKey, plain, cipher;
    BIO *cert = NULL;
    X509 *x = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    int keysize, OriginSize;

    ReadPemFile(&PublicKey, "third.crt");
    plain.len = strlen("0123456789abcdef");
    plain.buf = OPENSSL_malloc(plain.len);
    memcpy(plain.buf, "0123456789abcdef", plain.len);

    cert = BIO_new(BIO_s_mem());
    if(cert == NULL){
        return;
    }
    BIO_write(cert, PublicKey.buf, PublicKey.len);
    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    if(x == NULL){
        return;
    }
    pkey = X509_get_pubkey(x);
    if(pkey == NULL){
        return;
    }
    rsa = EVP_PKEY_get1_RSA(pkey);
    if(rsa == NULL){
        return;
    }
    keysize = RSA_size(rsa);
    cipher.len = keysize;
    cipher.buf = OPENSSL_malloc(cipher.len);
    cipher.len = RSA_public_encrypt(plain.len, plain.buf, cipher.buf, rsa, RSA_PKCS1_PADDING);

    WritePemFile(&cipher, "third.enc");

    BIO_free(cert);
    X509_free(x);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    if(PublicKey.buf){
        OPENSSL_free(PublicKey.buf);
    }
    if(plain.buf){
        OPENSSL_free(plain.buf);
    }
    if(cipher.buf){
        OPENSSL_free(cipher.buf);
    }
    printf("Encryption by certificate successful\n");
}

void RSADecryption()
{
    Buffer PrivateKey, cipher, plain;
    BIO *key = NULL, *out = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    int keysize;

    ReadPemFile(&PrivateKey, "third.pem");
    ReadPemFile(&cipher, "third.enc");

    key = BIO_new(BIO_s_mem());
    if(key == NULL){
        return;
    }
    BIO_write(key, PrivateKey.buf, PrivateKey.len);
    pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
    if(pkey == NULL){
        return;
    }
    rsa = EVP_PKEY_get1_RSA(pkey);
    if(rsa == NULL){
        return;
    }
    keysize = RSA_size(rsa);
    plain.len = keysize;
    plain.buf = OPENSSL_malloc(keysize);
    plain.len = RSA_private_decrypt(cipher.len, cipher.buf, plain.buf, rsa, RSA_PKCS1_PADDING);

    WritePemFile(&plain, "third.dec");

    BIO_free(key);
    BIO_free(out);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    if(PrivateKey.buf){
        OPENSSL_free(PrivateKey.buf);
    }
    if(cipher.buf){
        OPENSSL_free(cipher.buf);
    }
    if(plain.buf){
        OPENSSL_free(plain.buf);
    }
    printf("Decryption successful\n");
}

#define IV "0123456789ABCDEF0123456789ABCDEF"
#define AD "UUID-UUID-UUID-UUID"
#define KEY "0123456789abcdef"
#define PLAIN "0123456789abcdef0123456"

void EncAES128GCMSHA256()
{
    Buffer key, plain, cipher, tag;
    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    key.len = strlen(KEY);
    key.buf = OPENSSL_malloc(key.len);
    memcpy(key.buf, KEY, key.len);
    plain.len = strlen(PLAIN);
    plain.buf = OPENSSL_malloc(plain.len);
    memcpy(plain.buf, PLAIN, plain.len);
    cipher.len = 512;
    cipher.buf = OPENSSL_malloc(cipher.len);
    tag.len = 16; // 必须小于等于16
    tag.buf = OPENSSL_malloc(tag.len);

    ctx = EVP_CIPHER_CTX_new();
    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1){
        printf("EVP_EncryptInit_ex-1\n");
        return;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(IV), NULL) != 1){
        printf("EVP_CTRL_GCM_SET_IVLEN-2\n");
        return;
    }
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, key.buf, IV) != 1){
        printf("EVP_EncryptInit_ex-2\n");
        return;
    }
    if(EVP_EncryptUpdate(ctx, NULL, &len, AD, strlen(AD)) != 1){
        printf("EVP_EncryptUpdate-1\n");
        return;
    }
    if(EVP_EncryptUpdate(ctx, cipher.buf, &cipher.len, plain.buf, plain.len) != 1){
        printf("EVP_EncryptUpdate-2\n");
        return;
    }
    if(EVP_EncryptFinal_ex(ctx, cipher.buf + cipher.len, &len) != 1){
        printf("EVP_EncryptFinal_ex\n");
        return;
    }
    cipher.len += len;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.len, tag.buf) != 1){
        printf("EVP_CTRL_GCM_GET_TAG\n");
        return;
    }

    WritePemFile(&cipher, "aes-128-gcm-sha256.enc");
    WritePemFile(&tag, "aes-128-gcm-sha256.tag");

    EVP_CIPHER_CTX_free(ctx);
    if(key.buf){
        OPENSSL_free(key.buf);
    }
    if(plain.buf){
        OPENSSL_free(plain.buf);
    }
    if(cipher.buf){
        OPENSSL_free(cipher.buf);
    }
    printf("GCM Authenticated Encryption successful\n");
}

void DecAES128GCMSHA256()
{
    Buffer key, plain, cipher, tag;
    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    key.len = strlen(KEY);
    key.buf = OPENSSL_malloc(key.len);
    memcpy(key.buf, KEY, key.len);
    ReadPemFile(&cipher, "aes-128-gcm-sha256.enc");
    ReadPemFile(&tag, "aes-128-gcm-sha256.tag");
    plain.len = 512;
    plain.buf = OPENSSL_malloc(plain.len);

    ctx = EVP_CIPHER_CTX_new();
    if(EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1){
        printf("EVP_DecryptInit_ex-1\n");
        return;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(IV), NULL) != 1){
        printf("EVP_CTRL_GCM_SET_IVLEN\n");
        return;
    }
    if(EVP_DecryptInit_ex(ctx, NULL, NULL, key.buf, IV) != 1){
        printf("EVP_DecryptInit_ex-2\n");
        return;
    }
    if(EVP_DecryptUpdate(ctx, NULL, &len, AD, strlen(AD)) != 1){
        printf("EVP_DecryptUpdate-1\n");
        return;
    }
    if(EVP_DecryptUpdate(ctx, plain.buf, &plain.len, cipher.buf, cipher.len) != 1){
        printf("EVP_DecryptUpdate-2\n");
        return;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.len, tag.buf) != 1){
        printf("EVP_CTRL_GCM_SET_TAG\n");
        return;
    }
    if(EVP_DecryptFinal_ex(ctx, plain.buf + plain.len, &len) != 1){
        printf("EVP_DecryptFinal_ex\n");
        return;
    }
    plain.len += len;

    WritePemFile(&plain, "aes-128-gcm-sha256.dec");

    EVP_CIPHER_CTX_free(ctx);
    if(key.buf){
        OPENSSL_free(key.buf);
    }
    if(plain.buf){
        OPENSSL_free(plain.buf);
    }
    if(cipher.buf){
        OPENSSL_free(cipher.buf);
    }
    printf("GCM Authenticated Decryption successful\n");
}

void EncAES128CCMSHA256()
{
    Buffer key, plain, cipher, tag;
    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    key.len = strlen(KEY);
    key.buf = OPENSSL_malloc(key.len);
    memcpy(key.buf, KEY, key.len);
    plain.len = strlen(PLAIN);
    plain.buf = OPENSSL_malloc(plain.len);
    memcpy(plain.buf, PLAIN, plain.len);
    cipher.len = 512;
    cipher.buf = OPENSSL_malloc(cipher.len);
    tag.len = 16; // 必须小于等于16
    tag.buf = OPENSSL_malloc(tag.len);

    ctx = EVP_CIPHER_CTX_new();
    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) != 1){
        printf("EVP_EncryptInit_ex-1\n");
        return;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL) != 1){ // 必须是7
        printf("EVP_CTRL_CCM_SET_IVLEN\n");
        return;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag.len, NULL) != 1){
        printf("EVP_CTRL_CCM_SET_TAG\n");
        return;
    }
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, key.buf, IV) != 1){
        printf("EVP_EncryptInit_ex-2\n");
        return;
    }
    if(EVP_EncryptUpdate(ctx, NULL, &len, NULL, plain.len) != 1){
        printf("EVP_EncryptUpdate-1\n");
        return;
    }
    if(EVP_EncryptUpdate(ctx, NULL, &len, AD, strlen(AD)) != 1){
        printf("EVP_EncryptUpdate-2\n");
        return;
    }
    if(EVP_EncryptUpdate(ctx, cipher.buf, &cipher.len, plain.buf, plain.len) != 1){
        printf("EVP_EncryptUpdate-3\n");
        return;
    }
    if(EVP_EncryptFinal_ex(ctx, cipher.buf + cipher.len, &len) != 1){
        printf("EVP_EncryptFinal_ex\n");
        return;
    }
    cipher.len += len;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.len, tag.buf) != 1){
        printf("EVP_CTRL_GCM_GET_TAG\n");
        return;
    }

    WritePemFile(&cipher, "aes-128-ccm-sha256.enc");
    WritePemFile(&tag, "aes-128-ccm-sha256.tag");

    EVP_CIPHER_CTX_free(ctx);
    if(key.buf){
        OPENSSL_free(key.buf);
    }
    if(plain.buf){
        OPENSSL_free(plain.buf);
    }
    if(cipher.buf){
        OPENSSL_free(cipher.buf);
    }
    printf("CCM Authenticated Encryption successful\n");
}

void DecAES128CCMSHA256()
{
    Buffer key, plain, cipher, tag;
    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    key.len = strlen(KEY);
    key.buf = OPENSSL_malloc(key.len);
    memcpy(key.buf, KEY, key.len);
    ReadPemFile(&cipher, "aes-128-ccm-sha256.enc");
    ReadPemFile(&tag, "aes-128-ccm-sha256.tag");
    plain.len = 512;
    plain.buf = OPENSSL_malloc(plain.len);

    ctx = EVP_CIPHER_CTX_new();
    if(EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) != 1){
        printf("EVP_DecryptInit_ex-1\n");
        return;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL) != 1){ // 必须是7
        printf("EVP_CTRL_GCM_SET_IVLEN\n");
        return;
    }
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.len, tag.buf) != 1){
        printf("EVP_CTRL_GCM_SET_TAG\n");
        return;
    }
    if(EVP_DecryptInit_ex(ctx, NULL, NULL, key.buf, IV) != 1){
        printf("EVP_DecryptInit_ex-2\n");
        return;
    }
    if(EVP_DecryptUpdate(ctx, NULL, &len, NULL, cipher.len) != 1){
        printf("EVP_DecryptUpdate-1\n");
        return;
    }
    if(EVP_DecryptUpdate(ctx, NULL, &len, AD, strlen(AD)) != 1){
        printf("EVP_DecryptUpdate-2\n");
        return;
    }
    if(EVP_DecryptUpdate(ctx, plain.buf, &plain.len, cipher.buf, cipher.len) == 0){
        printf("EVP_DecryptUpdate-3\n");
        return;
    }

    WritePemFile(&plain, "aes-128-ccm-sha256.dec");

    EVP_CIPHER_CTX_free(ctx);
    if(key.buf){
        OPENSSL_free(key.buf);
    }
    if(plain.buf){
        OPENSSL_free(plain.buf);
    }
    if(cipher.buf){
        OPENSSL_free(cipher.buf);
    }
    printf("CCM Authenticated Decryption successful\n");
}

void ECDHE()
{
    Buffer SessionA, SessionB, PrivateKeyA, PrivateKeyB, PublicKeyA, PublicKeyB;
    EC_KEY *keya = NULL;
    EC_KEY *keyb = NULL;
    BIO *pria, *puba, *prib, *pubb;
    EC_GROUP *group;
    int sizea, sizeb;
    
    SessionA.len = 16;
    SessionA.buf = OPENSSL_malloc(SessionA.len);
    SessionB.len = 16;
    SessionB.buf = OPENSSL_malloc(SessionB.len);

    keya = EC_KEY_new();
    keyb = EC_KEY_new();
    if(keya == NULL || keyb == NULL){
        return;
    }
    group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE); // 设置该标志位可以降低PEM互殴这ASN.1编码大小
    EC_KEY_set_group(keya, group);
    EC_KEY_set_group(keyb, group);
    if(!EC_KEY_generate_key(keya)){
        return;
    }
    if(!EC_KEY_generate_key(keyb)){
        return;
    }

    puba = BIO_new(BIO_s_mem());
    pubb = BIO_new(BIO_s_mem());
    // PEM_write_bio_EC_PUBKEY(puba, keya);
    // PEM_write_bio_EC_PUBKEY(pubb, keyb);
    i2d_EC_PUBKEY_bio(puba, keya);
    i2d_EC_PUBKEY_bio(pubb, keyb);

    PublicKeyA.len = 1024;
    PublicKeyA.buf = OPENSSL_malloc(PublicKeyA.len);
    PublicKeyA.len = BIO_read(puba, PublicKeyA.buf, PublicKeyA.len);
    PublicKeyB.len = 1024;
    PublicKeyB.buf = OPENSSL_malloc(PublicKeyB.len);
    PublicKeyB.len = BIO_read(pubb, PublicKeyB.buf, PublicKeyB.len);
    WritePemFile(&PublicKeyA, "ecdha.pub");
    WritePemFile(&PublicKeyB, "ecdhb.pub");

    pria = BIO_new(BIO_s_mem());
    prib = BIO_new(BIO_s_mem());
    // PEM_write_bio_ECPrivateKey(pria, keya, NULL, NULL, 0, NULL, NULL);
    // PEM_write_bio_ECPrivateKey(prib, keyb, NULL, NULL, 0, NULL, NULL);
    i2d_ECPrivateKey_bio(pria, keya);
    i2d_ECPrivateKey_bio(prib, keyb);

    PrivateKeyA.len = 1024;
    PrivateKeyA.buf = OPENSSL_malloc(PrivateKeyA.len);
    PrivateKeyA.len = BIO_read(pria, PrivateKeyA.buf, PrivateKeyA.len);
    PrivateKeyB.len = 1024;
    PrivateKeyB.buf = OPENSSL_malloc(PrivateKeyB.len);
    PrivateKeyB.len = BIO_read(prib, PrivateKeyB.buf, PrivateKeyB.len);
    WritePemFile(&PrivateKeyA, "ecdha.pem");
    WritePemFile(&PrivateKeyB, "ecdhb.pem");

    // 计算共享密钥
    sizea = ECDH_compute_key(SessionA.buf, SessionA.len, EC_KEY_get0_public_key(keya), keyb, NULL);
    sizeb = ECDH_compute_key(SessionB.buf, SessionB.len, EC_KEY_get0_public_key(keyb), keya, NULL);

    for(int i = 0; i < sizea; i++)
    {
        printf("%02x", *((unsigned char*)SessionA.buf + i));
    }
    printf("\n");
    for(int j = 0; j < sizeb; j++)
    {
        printf("%02x", *((unsigned char*)SessionB.buf + j));
    }
    printf("\n");

    EC_KEY_free(keya);
    EC_KEY_free(keyb);
    BIO_free(puba);
    BIO_free(pubb);
    BIO_free(pria);
    BIO_free(prib);
    EC_GROUP_free(group);
    OPENSSL_free(SessionA.buf);
    OPENSSL_free(SessionB.buf);
    OPENSSL_free(PrivateKeyA.buf);
    OPENSSL_free(PrivateKeyB.buf);
    OPENSSL_free(PublicKeyA.buf);
    OPENSSL_free(PublicKeyB.buf);
}

int main()
{
    // RSASignature();
    // RSAVerificationByCert();
    // VerifyCerts();
    
    // RSASha256Signature();
    // RSASha256VerifyByCert();
    
    // RSAEncryptionByCert();
    // RSADecryption();

    EncAES128GCMSHA256();
    DecAES128GCMSHA256();

    // EncAES128CCMSHA256();
    // DecAES128CCMSHA256();

    // ECDHE();
    return 0;
}