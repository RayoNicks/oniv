#include <iostream>

#include "onivd.h"

using namespace std;

void usage()
{
    cout << "onivd [local address for creating tunnel]" << endl;
}

int main(int argc, char* argv[])
{
    if(argc != 2){
        usage();
        return 0;
    }
    string TunnelAdapterName(argv[1]);
    Onivd oniv(TunnelAdapterName);
    oniv.run();
    return 0;
}
