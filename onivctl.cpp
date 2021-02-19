#include <cstdio>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <err.h>
#include <linux/un.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include "onivcmd.h"
#include "onivglobal.h"

using namespace std;

void usage()
{
    printf(
        "onivctl [command]\n"
        "command:\n"
        "\tadd-adp <name> <ipv4> <vni> <mtu>\n"
        "\tdel-adp <name>\n"
        "\tclr-adp\n"
        "\tadd-tun <ipv4> <vni>\n"
        "\tdel-tun <ipv4>\n"
        "\tclr-tun\n"
        "\tstop\n"
    );
}

string convert(char* buf, size_t len)
{
    string ret;
    while(len > 0){
        ret.push_back(*buf);
        buf += 1;
        len--;
    }
    return ret;
}

string ParseCommand(int argc, char* argv[])
{
    string cmd;
    if(strcmp(argv[1], "add-adp") == 0 && argc == 6){
        string name(argv[2]);
        in_addr_t address = inet_addr(argv[3]);
        uint32_t vni = stoi(argv[4]);
        int mtu = stoi(argv[5]);
        name.resize(IFNAMSIZ);
        cmd.push_back(static_cast<char>(COMMAND_ADD_ADP));
        cmd.push_back(static_cast<char>(IFNAMSIZ + sizeof(in_addr_t) + sizeof(uint32_t) + sizeof(int)));
        cmd += name;
        cmd += convert((char*)&address, sizeof(in_addr_t));
        cmd += convert((char*)&vni, sizeof(uint32_t));
        cmd += convert((char*)&mtu, sizeof(int));
    }
    else if(strcmp(argv[1], "del-adp") == 0 && argc == 3){
        string name(argv[2]);
        name.resize(IFNAMSIZ);
        cmd.push_back(static_cast<char>(COMMAND_DEL_ADP));
        cmd.push_back(static_cast<char>(IFNAMSIZ));
        cmd += name;
    }
    else if(strcmp(argv[1], "clr-adp") == 0 && argc == 2){
        cmd.push_back(static_cast<char>(COMMAND_CLR_ADP));
    }
    else if(strcmp(argv[1], "add-tun") == 0 && argc == 4){
        in_addr_t address = inet_addr(argv[2]);
        uint32_t vni = stoi(argv[3]);
        cmd.push_back(static_cast<char>(COMMAND_ADD_TUN));
        cmd.push_back(static_cast<char>(sizeof(in_addr_t) + sizeof(uint32_t)));
        cmd += convert((char*)&address, sizeof(in_addr_t));
        cmd += convert((char*)&vni, sizeof(uint32_t));
    }
    else if(strcmp(argv[1], "del-tun") == 0 && argc == 3){
        in_addr_t address = inet_addr(argv[2]);
        cmd.push_back(static_cast<char>(COMMAND_DEL_TUN));
        cmd.push_back(static_cast<char>(sizeof(in_addr_t)));
        cmd += convert((char*)&address, sizeof(in_addr_t));
    }
    else if(strcmp(argv[1], "clr-tun") == 0 && argc == 2){
        cmd.push_back(static_cast<char>(COMMAND_CLR_TUN));
    }
    else if(strcmp(argv[1], "stop") == 0 && argc == 2){
        cmd.push_back(static_cast<char>(COMMAND_STOP));
    }
    return cmd;
}

int ConnectControllerSocket(const char* ControllerSocketPath)
{
    int ClientSocket;
    struct sockaddr_un ControllerAddress;

    if((ClientSocket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
        err(EXIT_FAILURE, "Create client socket failed");
    }

    memset(&ControllerAddress, 0, sizeof(struct sockaddr_un));
    ControllerAddress.sun_family = AF_UNIX;
    strncpy(ControllerAddress.sun_path, ControllerSocketPath, UNIX_PATH_MAX - 1);

    if(connect(ClientSocket, (const struct sockaddr*)&ControllerAddress, sizeof(struct sockaddr_un)) == -1){
        err(EXIT_FAILURE, "Connect to controller %s failed", ControllerSocketPath);
    }
    return ClientSocket;
}

int main(int argc, char* argv[])
{
    int ClientSocket, WriteNumber, size;
    string CmdBuf;

    if(argc < 2){
        usage();
        return 0;
    }

    CmdBuf = ParseCommand(argc, argv);

    ClientSocket = ConnectControllerSocket(OnivGlobal::SwitchServerTmpPath.c_str());
    if((WriteNumber = write(ClientSocket, CmdBuf.c_str(), CmdBuf.size()) < 0)){
        err(EXIT_FAILURE, "Write command failed");
    }

    return 0;
}
