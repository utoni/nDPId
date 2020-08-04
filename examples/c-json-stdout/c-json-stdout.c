#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "jsmn/jsmn.h"

static char serv_listen_addr[INET_ADDRSTRLEN] = DISTRIBUTOR_HOST;
static uint16_t serv_listen_port = DISTRIBUTOR_PORT;

int main(void)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in remote_addr = {};
    socklen_t remote_addrlen = sizeof(remote_addr);
    uint8_t buf[NETWORK_BUFFER_MAX_SIZE];
    //size_t buf_used = 0;
    //unsigned long long int buf_wanted = 0;

    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    remote_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, &serv_listen_addr[0], &remote_addr.sin_addr) != 1) {
        perror("inet_pton");
        return 1;
    }
    remote_addr.sin_port = htons(serv_listen_port);

    if (connect(sockfd, (struct sockaddr *) &remote_addr, remote_addrlen) != 0) {
        perror("connect");
        return 1;
    }

    while (1) {
        errno = 0;
        ssize_t bytes_read = read(sockfd, buf, sizeof(buf));

        if (bytes_read <= 0 || errno != 0) {
            break;
        }

        printf("RECV[%zd]: '%.*s'\n\n", bytes_read, (int) bytes_read, buf);
    }

    return 0;
}
