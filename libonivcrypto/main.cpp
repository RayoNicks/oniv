#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#include "libonivcrypto.h"

using namespace std;
using namespace libonivcrypto;

#define ECC_PRI "./ecc/guest4-ecc-sk.pem"
#define ECC_CRT "./ecc/guest4-ecc.crt"

int main()
{
    ifstream sk, crt;
    string PrivateKey, certificate, data("A3B237C2FB83D8F0"), signature, line;
    char sigbuf[512] = { 0 };
    size_t length;

    sk.open(ECC_PRI, ifstream::in | ifstream::binary);
    if(!sk){
        return 0;
    }
    while(getline(sk, line)){
        PrivateKey += line;
        PrivateKey.push_back('\n');
    }
    cout << PrivateKey << endl;

    crt.open(ECC_CRT, ifstream::in | ifstream::binary);
    if(!crt){
        return 0;
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

    return 0;
}
