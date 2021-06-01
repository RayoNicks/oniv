#include <iostream>

#include "onivcrypto.h"
#include "onivd.h"
#include "onivglobal.h"

using namespace std;

void usage()
{
    cout << "onivd [configuration file for starting oniv]" << endl;
}

int main(int argc, char *argv[])
{
    if(argc != 2){
        usage();
        return 0;
    }

    if(!OnivGlobal::LoadConfiguration(argv[1])){
        cout << "Load configuration file " << argv[1] << " failed" << endl;
        return 0;
    }

    if(!OnivCrypto::LoadIdentity()){
        cout << "Load certificates failed" << endl;
        return 0;
    }

    Onivd oniv(OnivGlobal::GetConfig("tunnel_interface"));
    oniv.run();
    return 0;
}
