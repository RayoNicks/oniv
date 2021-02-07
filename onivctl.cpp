#include <cstdio>
#include <cstring>

#include <arpa/inet.h>
#include <err.h>
#include <linux/un.h>
#include <sys/socket.h>
#include <unistd.h>

#include "onivcmd.h"
#include "onivglobal.h"

using std::to_string;

void usage()
{
    printf(
        "onivctl [command]\n"
        "command:\n"
        "\tadd-dev <name>\n"
        "\tdel-dev <name>\n"
        "\tclear-dev\n"
        "\tadd-tun <name> x.x.x.x\n"
        "\tdel-tun <name>\n"
        "\tclear-tun\n"
        "\tstop\n"
    );
}

string ParseCommand(int argc, char* argv[])
{
    string cmd;
    if(strcmp(argv[1], "add-dev") == 0 && argc == 3){
        cmd.push_back(static_cast<char>(COMMAND_ADD_DEV));
        cmd.push_back(static_cast<char>(strlen(argv[2])));
        cmd += argv[2];
    }
    else if(strcmp(argv[1], "del-dev") == 0 && argc == 3){
        cmd.push_back(static_cast<char>(COMMAND_DEL_DEV));
        cmd.push_back(static_cast<char>(strlen(argv[2])));
        cmd += argv[2];
    }
    else if(strcmp(argv[1], "clr-dev") == 0 && argc == 2){
        cmd.push_back(static_cast<char>(COMMAND_CLR_DEV));
    }
    else if(strcmp(argv[1], "add-tun") == 0 && argc == 4){
        cmd.push_back(static_cast<char>(COMMAND_ADD_TUN));
        cmd.push_back(static_cast<char>(strlen(argv[2])));
        cmd += argv[2];
        cmd.push_back('\0');
        cmd += to_string(inet_addr(argv[3]));
    }
    else if(strcmp(argv[1], "del-tun") == 0 && argc == 3){
        cmd.push_back(static_cast<char>(COMMAND_DEL_TUN));
        cmd.push_back(static_cast<char>(strlen(argv[2])));
        cmd += argv[2];
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

    ClientSocket = ConnectControllerSocket(OnivGlobal::SwitcherServerTmpPath.c_str());
    if((WriteNumber = write(ClientSocket, CmdBuf.c_str(), CmdBuf.size()) < 0)){
        err(EXIT_FAILURE, "Write command failed");
    }

    return 0;
}
