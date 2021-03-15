#include <iostream>
#include <string>

#include "onivd.h"

using namespace std;

void usage()
{
    cout << "onivd [local interface name for creating tunnel] [host name for certificate]" << endl;
}

int main(int argc, char *argv[])
{
    if(argc != 3){
        usage();
        return 0;
    }

    string HostName(argv[2]);
    if(!OnivCrypto::LoadIdentity(HostName)){
        cout << "Load certificates for " << HostName << " failed" << endl;
        return 0;
    }

    string TunnelAdapterName(argv[1]);
    Onivd oniv(TunnelAdapterName, HostName);
    oniv.run();
    return 0;
}
