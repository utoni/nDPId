#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "nDPIsrvd.h"
#include "jsmn/jsmn.h"

static char serv_listen_addr[INET_ADDRSTRLEN] = DISTRIBUTOR_HOST;
static uint16_t serv_listen_port = DISTRIBUTOR_PORT;

static enum nDPIsrvd_callback_return nDPIsrvd_json_callback(struct nDPIsrvd_socket * const sock, void * user_data)
{
    (void)user_data;

    if (sock->jsmn.current_token % 2 == 1)
    {
        printf("[%.*s : ",
               sock->jsmn.tokens[sock->jsmn.current_token].end - sock->jsmn.tokens[sock->jsmn.current_token].start,
               sock->buffer.json_string + sock->jsmn.tokens[sock->jsmn.current_token].start);
    }
    else
    {
        printf("%.*s] ",
               sock->jsmn.tokens[sock->jsmn.current_token].end - sock->jsmn.tokens[sock->jsmn.current_token].start,
               sock->buffer.json_string + sock->jsmn.tokens[sock->jsmn.current_token].start);
    }

    return CALLBACK_OK;
}

int main(int argc, char ** argv)
{
    struct nDPIsrvd_socket * sock = nDPIsrvd_init();

    (void)argc;

    if (sock == NULL)
    {
        fprintf(stderr, "%s: nDPIsrvd socket memory allocation failed!\n", argv[0]);
        return 1;
    }

    printf("Connecting to %s:%u\n", serv_listen_addr, serv_listen_port);
    enum nDPIsrvd_connect_return connect_ret = nDPIsrvd_connect_ip(sock, serv_listen_addr, serv_listen_port);
    if (connect_ret != CONNECT_OK)
    {
        fprintf(stderr, "%s: nDPIsrvd socket connect failed!\n", argv[0]);
        return 1;
    }

    while (1)
    {
        errno = 0;
        enum nDPIsrvd_read_return read_ret = nDPIsrvd_read(sock);
        if (read_ret != READ_OK)
        {
            break;
        }

        enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse(sock, nDPIsrvd_json_callback, NULL);
        switch (parse_ret)
        {
            default:
                break;
        }
        printf("EoF\n");
    }

    return 0;
}
