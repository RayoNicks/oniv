#include <cstring>
#include <iostream>
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
        "\tadd-adp <name> <ipv4> <mask> <bdi> <mtu>\n"
        "\tdel-adp <name>\n"
        "\tclr-adp\n"
        "\tadd-tun <ipv4> <bdi>\n"
        "\tdel-tun <ipv4>\n"
        "\tclr-tun\n"
        "\tadd-route <dest> <mask> <gateway> <name>\n"
        "\tdel-route <dest> <mask> <name>\n"
        "\tstop\n"
    );
}

string convert(void *buf, size_t len)
{
    string ret;
    char *p = (char*)buf;
    while(len > 0){
        ret.push_back(*p);
        p++;
        len--;
    }
    return ret;
}

string ParseCommand(int argc, char *argv[])
{
    string cmd;
    if(strcmp(argv[1], "stop") == 0 && argc == 2){
        cmd.push_back(static_cast<char>(COMMAND_STOP));
    }
    else if(strcmp(argv[1], "add-adp") == 0 && argc == 7){
        string name(argv[2]);
        in_addr_t address = inet_addr(argv[3]);
        in_addr_t mask = inet_addr(argv[4]);
        uint32_t bdi = htonl(stoi(argv[5]));
        int mtu = stoi(argv[6]);
        name.resize(IFNAMSIZ);
        cmd.push_back(static_cast<char>(COMMAND_ADD_ADP));
        cmd.push_back(static_cast<char>(IFNAMSIZ + sizeof(in_addr_t) * 2 + sizeof(uint32_t) + sizeof(int)));
        cmd += name;
        cmd += convert(&address, sizeof(in_addr_t));
        cmd += convert(&mask, sizeof(in_addr_t));
        cmd += convert(&bdi, sizeof(uint32_t));
        cmd += convert(&mtu, sizeof(int));
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
        uint32_t bdi = htonl(stoi(argv[3]));
        cmd.push_back(static_cast<char>(COMMAND_ADD_TUN));
        cmd.push_back(static_cast<char>(sizeof(in_addr_t) + sizeof(uint32_t)));
        cmd += convert(&address, sizeof(in_addr_t));
        cmd += convert(&bdi, sizeof(uint32_t));
    }
    else if(strcmp(argv[1], "del-tun") == 0 && argc == 3){
        in_addr_t address = inet_addr(argv[2]);
        cmd.push_back(static_cast<char>(COMMAND_DEL_TUN));
        cmd.push_back(static_cast<char>(sizeof(in_addr_t)));
        cmd += convert(&address, sizeof(in_addr_t));
    }
    else if(strcmp(argv[1], "clr-tun") == 0 && argc == 2){
        cmd.push_back(static_cast<char>(COMMAND_CLR_TUN));
    }
    else if(strcmp(argv[1], "add-route") == 0 && argc == 6){
        in_addr_t dest = inet_addr(argv[2]);
        in_addr_t mask = inet_addr(argv[3]);
        in_addr_t gateway = inet_addr(argv[4]);
        string name(argv[5]);
        name.resize(IFNAMSIZ);
        cmd.push_back(static_cast<char>(COMMAND_ADD_ROU));
        cmd.push_back(static_cast<char>(sizeof(in_addr_t) * 3 + IFNAMSIZ));
        cmd += convert(&dest, sizeof(in_addr_t));
        cmd += convert(&mask, sizeof(in_addr_t));
        cmd += convert(&gateway, sizeof(in_addr_t));
        cmd += name;
    }
    else if(strcmp(argv[1], "del-route") == 0 && argc == 5){
        in_addr_t dest = inet_addr(argv[2]);
        in_addr_t mask = inet_addr(argv[3]);
        string name(argv[4]);
        name.resize(IFNAMSIZ);
        cmd.push_back(static_cast<char>(COMMAND_DEL_ROU));
        cmd.push_back(static_cast<char>(sizeof(in_addr_t) * 2 + IFNAMSIZ));
        cmd += convert(&dest, sizeof(in_addr_t));
        cmd += convert(&mask, sizeof(in_addr_t));
        cmd += name;
    }
    return cmd;
}

int ConnectControllerSocket(const char *ControllerSocketPath)
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

int main(int argc, char *argv[])
{
    int ClientSocket, WriteNumber;
    string CmdBuf;
    char result[256] = { 0 };

    if(argc < 2){
        usage();
        return 0;
    }

    CmdBuf = ParseCommand(argc, argv);
    if(CmdBuf.empty()){
        usage();
        return 0;
    }

    ClientSocket = ConnectControllerSocket(OnivGlobal::SwitchServerTmpPath.c_str());
    if((WriteNumber = write(ClientSocket, CmdBuf.c_str(), CmdBuf.size()) < 0)){
        err(EXIT_FAILURE, "Write command failed");
    }

    read(ClientSocket, result, sizeof(result));
    cout << result << endl;

    return 0;
}
