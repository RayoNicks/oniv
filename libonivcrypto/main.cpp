#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#include "libonivcrypto.h"

using namespace std;
using namespace libonivcrypto;

void TestSignAndVerify()
{
    cout << "Test for Signature and verification" << endl;
    ifstream sk, crt;
    string PrivateKey, certificate, data("A3B237C2FB83D8F0"), signature, line;
    char sigbuf[512] = { 0 };
    size_t length;

    sk.open("../certs/ecc/guest4-ecc-sk.pem", ifstream::in | ifstream::binary);
    if(!sk){
        return;
    }
    while(getline(sk, line)){
        PrivateKey += line;
        PrivateKey.push_back('\n');
    }
    cout << PrivateKey << endl;

    crt.open("../certs/ecc/guest4-ecc.crt", ifstream::in | ifstream::binary);
    if(!crt){
        return;
    }
    while(getline(crt, line)){
        certificate += line;
        certificate.push_back('\n');
    }
    cout << certificate << endl;

    length = sign(PrivateKey.c_str(), PrivateKey.length(), data.c_str(), data.length(),
        sigbuf, sizeof(sigbuf), FORMAT_PEM);
    signature.assign(sigbuf, length);
    for(const char &c : signature)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;

    cout << verify(certificate.c_str(), certificate.length(), data.c_str(), data.length(),
        sigbuf, length, FORMAT_PEM) << endl;

    sk.close();
    crt.close();
}

void TestGCM()
{
    cout << "Test for AES-128-GCM" << endl;
    string sk("sharedsessionkey"), plain("plain text"), cipher, tag;
    string InitVector("UUIDUUIDUUID"), AssData("UUIDUUIDUUIDUUID-\x11");
    char CipherBuf[plain.length()] = { '\0' }, TagBuf[16] = { '\0' }, PlainBuf[plain.length() + 1] = { '\0' };
    size_t length;

    length = GCMEncryption(sk.c_str(), sk.length(), plain.c_str(), plain.length(),
        InitVector.c_str(), InitVector.length(), AssData.c_str(), AssData.length(),
        CipherBuf, sizeof(CipherBuf), TagBuf, sizeof(TagBuf));
    cipher.assign(CipherBuf, length);
    tag.assign(TagBuf, sizeof(TagBuf));
    for(const char &c : cipher)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
    for(const char &c : tag)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;

    cout << GCMDecryption(sk.c_str(), sk.length(), cipher.c_str(), cipher.length(),
        InitVector.c_str(), InitVector.length(), AssData.c_str(), AssData.length(),
        PlainBuf, sizeof(PlainBuf), TagBuf, sizeof(TagBuf)) << endl;
    
    cout << PlainBuf << endl;
}

void TestCheckCerts()
{
    cout << "Test for checking certificates" << endl;
    ifstream root, second, guest;
    string ca, user, line;
    root.open("../certs/ecc/root-ecc.crt", ifstream::in | ifstream::binary);
    second.open("../certs/ecc/second-ecc.crt", ifstream::in | ifstream::binary);
    guest.open("../certs/ecc/guest4-ecc.crt", ifstream::in | ifstream::binary);
    if(!root || !second || !guest){
        return;
    }
    while(getline(root, line)){
        ca += line;
        ca.push_back('\n');
    }
    while(getline(second, line)){
        ca += line;
        ca.push_back('\n');
    }
    while(getline(guest, line)){
        user += line;
        user.push_back('\n');
    }

    cout << ca << endl;
    cout << user << endl;

    cout << CheckCertificate(ca.c_str(), ca.length(), user.c_str(), user.length(), FORMAT_PEM) << endl;

    root.close();
    second.close();
    guest.close();
}

void TestECDH()
{
    cout << "Test for ecdh" << endl;
    char ska[512] = { '\0' }, pka[512] = { '\0' }, skb[512] = { '\0' }, pkb[512] = { '\0' };
    char SessionBuffa[128] = { '\0' }, SessionBuffb[128] = { '\0' };
    size_t skalen, pkalen, skblen, pkblen, SessionLena, SessionLenb;
    string SKa, SKb;
    skalen = GenECPrivateKey("secp384r1", ska, sizeof(ska), FORMAT_PEM);
    pkalen = GetECPublicKey(ska, skalen, pka, sizeof(pka), FORMAT_PEM);
    skblen = GenECPrivateKey("secp384r1", skb, sizeof(skb), FORMAT_PEM);
    pkblen = GetECPublicKey(skb, skblen, pkb, sizeof(pkb), FORMAT_PEM);

    cout << ska << endl;
    cout << pka << endl;
    cout << skb << endl;
    cout << pkb << endl;

    SessionLena = ComputeSK(ska, skalen, pkb, pkblen, SessionBuffa, sizeof(SessionBuffa), FORMAT_PEM);
    SessionLenb = ComputeSK(skb, skblen, pka, pkalen, SessionBuffb, sizeof(SessionBuffb), FORMAT_PEM);
    cout << dec << SessionLena << ' ' << SessionLenb << endl;
    SKa.assign(SessionBuffa, SessionLena);
    SKb.assign(SessionBuffb, SessionLenb);
    for(const char &c : SKa)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
    for(const char &c : SKb)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
    cout << (SKa == SKb) << endl;
}

void TestEncAndDec()
{
    cout << "Test for encryption and decryption" << endl;
    string cipher, plain("plain text plain text"), certificate, line, PrivateKey;
    ifstream crt, sk;
    char CipherBuf[512] = { '\0' }, PlainBuf[512] = { '\0' };
    size_t size;

    crt.open("../certs/ecc/guest2-ecc.crt", ifstream::in | ifstream::binary);
    if(!crt){
        return;
    }
    while(getline(crt, line)){
        certificate += line;
        certificate.push_back('\n');
    }
    cout << certificate << endl;

    sk.open("ecc/guest2-ecc-sk.pem", ifstream::in | ifstream::binary);
    if(!sk){
        return;
    }
    while(getline(sk, line)){
        PrivateKey += line;
        PrivateKey.push_back('\n');
    }
    cout << PrivateKey << endl;

    size = encrypt(certificate.c_str(), certificate.length(), plain.c_str(), plain.length(), CipherBuf, sizeof(CipherBuf), FORMAT_PEM);
    cipher.assign(CipherBuf, size);
    for(const char &c : cipher)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;

    size = decrypt(PrivateKey.c_str(), PrivateKey.length(), cipher.c_str(), cipher.length(), PlainBuf, sizeof(PlainBuf), FORMAT_PEM);
    cout << PlainBuf << endl;
}

void TestCCM()
{
    cout << "Test for AES-128-CCM" << endl;
    string sk("sharedsessionkey"), plain("plain text"), cipher, tag;
    string InitVector("UUIDUUIDUUID"), AssData("UUIDUUIDUUIDUUID-\x11");
    char CipherBuf[plain.length()] = { '\0' }, TagBuf[16] = { '\0' }, PlainBuf[plain.length() + 1] = { '\0' };
    size_t length;

    length = CCMEncryption(sk.c_str(), sk.length(), plain.c_str(), plain.length(),
        InitVector.c_str(), InitVector.length(), AssData.c_str(), AssData.length(),
        CipherBuf, sizeof(CipherBuf), TagBuf, sizeof(TagBuf));
    cipher.assign(CipherBuf, length);
    tag.assign(TagBuf, sizeof(TagBuf));
    for(const char &c : cipher)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
    for(const char &c : tag)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;

    cout << CCMDecryption(sk.c_str(), sk.length(), cipher.c_str(), cipher.length(),
        InitVector.c_str(), InitVector.length(), AssData.c_str(), AssData.length(),
        PlainBuf, sizeof(PlainBuf), TagBuf, sizeof(TagBuf)) << endl;
    
    cout << PlainBuf << endl;
}

void TestUUID()
{
    cout << "Test for UUID version 5" << endl;
    ifstream crt;
    string certificate, line, UUID;
    char uuid[16] = { '\0' };

    crt.open("../certs/ecc/guest2-ecc.crt", ifstream::in | ifstream::binary);
    if(!crt){
        return;
    }
    while(getline(crt, line)){
        certificate += line;
        certificate.push_back('\n');
    }
    cout << certificate << endl;
    uuid5(certificate.c_str(), certificate.length(), uuid, sizeof(uuid), FORMAT_PEM);
    UUID.assign(uuid, 16);
    for(const char &c : uuid)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
}

void TestIssuer()
{
    cout << "Test for getting issuer" << endl;
    ifstream crt;
    string certificate, line;
    char name[128] = { '\0' };

    crt.open("MicrosoftECCRootCertificateAuthority2017.crt", ifstream::in | ifstream::binary);
    if(!crt){
        return;
    }
    while(getline(crt, line)){
        certificate += line;
        certificate.push_back('\n');
    }
    cout << certificate << endl;

    GetIssuer(certificate.c_str(), certificate.length(), name, sizeof(name), FORMAT_PEM);
    cout << "Issuer name is:\n" << name << endl;
}

void TestCurveName()
{
    cout << "Test for getting curve name" << endl;
    ifstream crt;
    string certificate, line;

    crt.open("MicrosoftECCRootCertificateAuthority2017.crt", ifstream::in | ifstream::binary);
    if(!crt){
        return;
    }
    while(getline(crt, line)){
        certificate += line;
        certificate.push_back('\n');
    }
    cout << certificate << endl;

    cout << "Curve name is:";
    cout << GetCurveName(certificate.c_str(), certificate.length(), FORMAT_PEM) << endl;
}

int main()
{
    TestSignAndVerify();
    TestGCM();
    TestCheckCerts();
    TestECDH();
    TestEncAndDec();
    TestCCM();
    TestUUID();
    TestIssuer();
    TestCurveName();
    return 0;
}
