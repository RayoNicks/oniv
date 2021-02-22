#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "c-s.h"

int main()
{
    int ClientSocket, ret;
    struct sockaddr_in ServerAddress;
    char buffer[BUFFER_SIZE] = { 0 };
    int idx = 0;

    for(idx = 0; idx + strlen(MESSAGE) < BUFFER_SIZE; idx += strlen(MESSAGE))
    {
        memcpy(buffer + idx, MESSAGE, strlen(MESSAGE));
    }
    memcpy(buffer + idx, MESSAGE, BUFFER_SIZE - idx);

    ClientSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if(ClientSocket == - 1){
        printf("socket error\n");
        return 0;
    }

    memset(&ServerAddress, 0, sizeof(struct sockaddr_in));
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_port = htons(8472);
    ServerAddress.sin_addr.s_addr = inet_addr(SERVER_IP);

    ret = sendto(ClientSocket, buffer, BUFFER_SIZE, 0, (const struct sockaddr*)&ServerAddress, sizeof(struct sockaddr_in));
    if(ret == -1){
        printf("sendto error\n");
        return 0;
    }
    else{
        printf("send %d bytes\n", ret);
    }

    close(ClientSocket);

    return 0;
}