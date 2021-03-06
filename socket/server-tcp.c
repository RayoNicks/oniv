#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "c-s.h"

void usage()
{
    printf("server-tcp [server address]\n");
    return;
}

int main(int argc, char *argv[])
{
    int ListenSocket, ServerSocket, ret;
    struct sockaddr_in ServerAddress, ClientAddress;
    char buffer[BUFFER_SIZE] = { 0 };
    socklen_t ClientAddressLen = sizeof(struct sockaddr_in);

    if(argc != 2){
        usage();
        return 0;
    }

    ListenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(ListenSocket == - 1){
        printf("socket error\n");
        return 0;
    }

    memset(&ServerAddress, 0, sizeof(struct sockaddr_in));
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_port = htons(8472);
    ServerAddress.sin_addr.s_addr = inet_addr(argv[1]);

    ret = bind(ListenSocket, (const struct sockaddr*)&ServerAddress, sizeof(struct sockaddr_in));
    if(ret < 0){
        printf("bind error\n");
        return 0;
    }

    ret = listen(ListenSocket, 20);
    if(ret == -1){
        printf("listen error\n");
        return 0;
    }

    ServerSocket = accept(ListenSocket, (struct sockaddr*)&ClientAddress, &ClientAddressLen);
    if(ServerSocket == -1){
        printf("accept error\n");
        return 0;
    }

    do{
        ret = recv(ServerSocket, buffer, BUFFER_SIZE, 0);
        if(ret == -1){
            printf("recv error\n");
            return 0;
        }
        else if(ret == 0){
            break;
        }
        else{
            printf("receive %d bytes from port 8472 at %s\n", ret, argv[1]);
        }
    }while(ret > 0);

    close(ServerSocket);

    return 0;
}