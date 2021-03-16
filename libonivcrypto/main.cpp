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
    string PrivateKey, certificate, data("A3B237C2FB83D8F0"), line;
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
    cout << "private key is:\n" << PrivateKey << endl;

    crt.open("../certs/ecc/guest4-ecc.crt", ifstream::in | ifstream::binary);
    if(!crt){
        return;
    }
    while(getline(crt, line)){
        certificate += line;
        certificate.push_back('\n');
    }
    cout << "certificate is:\n" << certificate << endl;

    length = sign(PrivateKey.c_str(), PrivateKey.length(), data.c_str(), data.length(),
        sigbuf, sizeof(sigbuf), FORMAT_PEM);
    cout << "signature is:" << endl;
    for(const char &c : string(sigbuf, length))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;

    cout << "verify result is:" << endl;
    cout << verify(certificate.c_str(), certificate.length(), data.c_str(), data.length(),
        sigbuf, length, FORMAT_PEM) << endl;

    sk.close();
    crt.close();
}

void TestGCM(const string &name)
{
    cout << "Test for " << name << endl;
    string sk("sharedsessionkey"), plain("plain text");
    string InitVector("UUIDUUIDUUID"), AssData("UUIDUUIDUUIDUUID-\x11");
    char CipherBuf[plain.length()] = { 0 }, TagBuf[16] = { 0 }, PlainBuf[plain.length() + 1] = { 0 };
    size_t length;

    length = GCMEncryption(name.c_str(), sk.c_str(), sk.length(), plain.c_str(), plain.length(),
        InitVector.c_str(), InitVector.length(), AssData.c_str(), AssData.length(),
        CipherBuf, sizeof(CipherBuf), TagBuf, sizeof(TagBuf));
    cout << "cipher text is:" << endl;
    for(const char &c : string(CipherBuf, length))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
    cout << "tag is:" << endl;
    for(const char &c : string(TagBuf, sizeof(TagBuf)))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;

    cout << GCMDecryption(name.c_str(), sk.c_str(), sk.length(), CipherBuf, length,
        InitVector.c_str(), InitVector.length(), AssData.c_str(), AssData.length(),
        PlainBuf, sizeof(PlainBuf), TagBuf, sizeof(TagBuf)) << endl;
    
    cout << "plain is:\n" << PlainBuf << endl;
}

void TestCheckCerts()
{
    cout << "Test for checking certificates" << endl;
    ifstream root, second, guest;
    string ca, user, line;
    root.open("../certs/ecc/root-ecc.crt", ifstream::in | ifstream::binary);
    second.open("../certs/ecc/second-ecc.crt", ifstream::in | ifstream::binary);
    guest.open("../certs/ecc/guest1-ecc.crt", ifstream::in | ifstream::binary);
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

    cout << "ca file is:\n" << ca << endl;
    cout << "user certificate is\n:" << user << endl;

    cout << CheckCertificate(ca.c_str(), ca.length(), user.c_str(), user.length(), FORMAT_PEM) << endl;

    root.close();
    second.close();
    guest.close();
}

void TestECDH()
{
    cout << "Test for ecdh" << endl;
    char ska[512] = { 0 }, pka[512] = { 0 }, skb[512] = { 0 }, pkb[512] = { 0 };
    char SessionBuffa[128] = { 0 }, SessionBuffb[128] = { 0 };
    size_t skalen, pkalen, skblen, pkblen, SessionLena, SessionLenb;
    skalen = GenECPrivateKey("secp384r1", ska, sizeof(ska), FORMAT_PEM);
    pkalen = GetECPublicKey(ska, skalen, pka, sizeof(pka), FORMAT_PEM);
    skblen = GenECPrivateKey("secp384r1", skb, sizeof(skb), FORMAT_PEM);
    pkblen = GetECPublicKey(skb, skblen, pkb, sizeof(pkb), FORMAT_PEM);

    cout << "private keya is:\n" << ska << endl;
    cout << "public keya is:" << endl;
    for(const char &c : string(pka, pkalen))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
    cout << "private keyb is:\n" << skb << endl;
    cout << "public keyb is:" << endl;
    for(const char &c : string(pkb, pkblen))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;

    SessionLena = ComputeSK(ska, skalen, pkb, pkblen, SessionBuffa, sizeof(SessionBuffa), FORMAT_PEM);
    SessionLenb = ComputeSK(skb, skblen, pka, pkalen, SessionBuffb, sizeof(SessionBuffb), FORMAT_PEM);
    cout << "session key computed by a is:" << endl;
    for(const char &c : string(SessionBuffa, SessionLena))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
    cout << "session key computed by b is:" << endl;
    for(const char &c : string(SessionBuffb, SessionLenb))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
}

void TestEncAndDec()
{
    cout << "Test for encryption and decryption" << endl;
    string plain("a plain text for compressed point"), certificate, line, PrivateKey;
    ifstream crt, sk;
    char CipherBuf[512] = { 0 }, PlainBuf[512] = { 0 };
    size_t size;

    crt.open("../certs/ecc/guest2-ecc.crt", ifstream::in | ifstream::binary);
    if(!crt){
        return;
    }
    while(getline(crt, line)){
        certificate += line;
        certificate.push_back('\n');
    }
    cout << "certificate is:\n" << certificate << endl;

    sk.open("../certs/ecc/guest2-ecc-sk.pem", ifstream::in | ifstream::binary);
    if(!sk){
        return;
    }
    while(getline(sk, line)){
        PrivateKey += line;
        PrivateKey.push_back('\n');
    }
    cout << "private key is:\n" << PrivateKey << endl;

    size = encrypt(certificate.c_str(), certificate.length(), plain.c_str(), plain.length(), CipherBuf, sizeof(CipherBuf), FORMAT_PEM);
    cout << "cipher text is:" << endl;
    for(const char &c : string(CipherBuf, size))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;

    size = decrypt(PrivateKey.c_str(), PrivateKey.length(), CipherBuf, size, PlainBuf, sizeof(PlainBuf), FORMAT_PEM);
    cout << "plain text is:" << PlainBuf << endl;
}

void TestCCM()
{
    cout << "Test for AES-128-CCM" << endl;
    string sk("sharedsessionkey"), plain("plain text");
    string InitVector("UUIDUUIDUUID"), AssData("UUIDUUIDUUIDUUID-\x11");
    char CipherBuf[plain.length()] = { 0 }, TagBuf[16] = { 0 }, PlainBuf[plain.length() + 1] = { 0 };
    size_t length;

    length = CCMEncryption(sk.c_str(), sk.length(), plain.c_str(), plain.length(),
        InitVector.c_str(), InitVector.length(), AssData.c_str(), AssData.length(),
        CipherBuf, sizeof(CipherBuf), TagBuf, sizeof(TagBuf));
    for(const char &c : string(CipherBuf, length))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
    for(const char &c : string(TagBuf, sizeof(TagBuf)))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;

    cout << CCMDecryption(sk.c_str(), sk.length(), CipherBuf, length,
        InitVector.c_str(), InitVector.length(), AssData.c_str(), AssData.length(),
        PlainBuf, sizeof(PlainBuf), TagBuf, sizeof(TagBuf)) << endl;
    
    cout << PlainBuf << endl;
}

void TestUUID()
{
    cout << "Test for UUID version 5" << endl;
    ifstream crt;
    string certificate, line;
    char uuid[16] = { 0 };

    crt.open("../certs/ecc/guest2-ecc.crt", ifstream::in | ifstream::binary);
    if(!crt){
        return;
    }
    while(getline(crt, line)){
        certificate += line;
        certificate.push_back('\n');
    }
    cout << "cerificate is:\n" << certificate << endl;
    uuid5(certificate.c_str(), certificate.length(), uuid, sizeof(uuid), FORMAT_PEM);
    for(const char &c : string(uuid, 16))
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << endl;
}

void TestSubject()
{
    cout << "Test for getting subject" << endl;
    ifstream crt;
    string certificate, line;
    char name[128] = { 0 };

    crt.open("MicrosoftECCRootCertificateAuthority2017.crt", ifstream::in | ifstream::binary);
    if(!crt){
        return;
    }
    while(getline(crt, line)){
        certificate += line;
        certificate.push_back('\n');
    }
    cout << "cerificate is:\n" << certificate << endl;

    GetSubjectName(certificate.c_str(), certificate.length(), name, sizeof(name), FORMAT_PEM);
    cout << "Subject name is:";
    cout << name << endl;
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
    cout << "cerificate is:\n" << certificate << endl;

    cout << "Curve name is:" << endl;;
    cout << GetCurveName(certificate.c_str(), certificate.length(), FORMAT_PEM) << endl;
}

int main()
{
    LoadAlgorithms();
    // TestSignAndVerify();
    // TestGCM("aes-256-gcm");
    // TestCheckCerts();
    TestECDH();
    // TestEncAndDec();
    // TestCCM();
    // TestUUID();
    // TestSubject();
    // TestCurveName();
    return 0;
}
