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

//#define VERBOSE 1

static char serv_listen_addr[INET_ADDRSTRLEN] = DISTRIBUTOR_HOST;
static uint16_t serv_listen_port = DISTRIBUTOR_PORT;

static enum nDPIsrvd_callback_return nDPIsrvd_json_callback(struct nDPIsrvd_socket * const sock, void * user_data)
{
    (void)user_data;

    if (token_is_start(sock) == 1)
    {
#ifdef VERBOSE
        /* Start of a JSON string. */
        printf("JSON ");
#endif
    }
    else if (token_is_end(sock) == 1)
    {
#ifdef VERBOSE
        /* End of a JSON string. */
        printf("EoF\n");
#endif
    }
    else if (token_is_key_value_pair(sock) == 1)
    {
        if (key_equals(sock, "flow_event_name") == 1)
        {
            if (value_equals(sock, "guessed") == 1)
            {
                printf("Guessed flow.\n");
            }
            else if (value_equals(sock, "not-detected") == 1)
            {
                printf("Not detected flow.\n");
            }
        }
#ifdef VERBOSE
        printf("[%.*s : %.*s] ",
               sock->jsmn.key_value.key_length,
               sock->jsmn.key_value.key,
               sock->jsmn.key_value.value_length,
               sock->jsmn.key_value.value);
#endif
    }
    else
    {
        fprintf(stderr, "%s\n", "Internal error, exit ..");
        return CALLBACK_ERROR;
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
    }

    return 0;
}
