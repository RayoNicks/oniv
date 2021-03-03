#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "c-s.h"

void usage()
{
    printf("server-udp [server address]\n");
    return;
}

int main(int argc, char *argv[])
{
    int ServerSocket, ret;
    struct sockaddr_in ServerAddress, ClientAddress;
    char buffer[BUFFER_SIZE] = { 0 };
    socklen_t ClientAddressLen = sizeof(struct sockaddr_in);

    if(argc != 2){
        usage();
        return 0;
    }

    ServerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if(ServerSocket == - 1){
        printf("socket error\n");
        return 0;
    }

    memset(&ServerAddress, 0, sizeof(struct sockaddr_in));
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_port = htons(8472);
    ServerAddress.sin_addr.s_addr = inet_addr(argv[1]);

    ret = bind(ServerSocket, (const struct sockaddr*)&ServerAddress, sizeof(struct sockaddr_in));
    if(ret < 0){
        printf("bind error\n");
        return 0;
    }

    ret = recvfrom(ServerSocket, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&ClientAddress, &ClientAddressLen);
    if(ret == -1){
        printf("recvfrom error\n");
        return 0;
    }
    else{
        printf("receive %d bytes from port 8472 at %s\n", ret, argv[1]);
    }

    close(ServerSocket);

    return 0;
}
