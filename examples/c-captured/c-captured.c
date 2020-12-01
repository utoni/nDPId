#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "nDPIsrvd.h"
#include "jsmn/jsmn.h"

//#define VERBOSE 1

struct nDPIsrvd_socket * sock = NULL;
static int main_thread_shutdown = 0;
static char const serv_listen_path[] = DISTRIBUTOR_UNIX_SOCKET;
static char const serv_listen_addr[INET_ADDRSTRLEN] = DISTRIBUTOR_HOST;
static uint16_t const serv_listen_port = DISTRIBUTOR_PORT;

enum nDPIsrvd_callback_return nDPIsrvd_json_callback(struct nDPIsrvd_socket * const sock, void * user_data)
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
            else if (value_equals(sock, "detected") == 1)
            {
                printf("Detected flow.\n");
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

static void sighandler(int signum)
{
    (void)signum;

    if (main_thread_shutdown == 0)
    {
        main_thread_shutdown = 1;
    }
}

int main(int argc, char ** argv)
{
    sock = nDPIsrvd_init();
    if (sock == NULL)
    {
        fprintf(stderr, "%s: nDPIsrvd socket memory allocation failed!\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, sighandler);

    enum nDPIsrvd_connect_return connect_ret;

    if (argc == 2)
    {
        printf("Connecting to UNIX socket: %s\n", argv[1]);
        connect_ret = nDPIsrvd_connect_unix(sock, argv[1]);
    } else if (argc == 1) {
        if (access(serv_listen_path, R_OK) == 0)
        {
            printf("Connecting to %s\n", serv_listen_path);
            connect_ret = nDPIsrvd_connect_unix(sock, serv_listen_path);
        } else {
            printf("Connecting to %s:%u\n", serv_listen_addr, serv_listen_port);
            connect_ret = nDPIsrvd_connect_ip(sock, serv_listen_addr, serv_listen_port);
        }
    }

    if (connect_ret != CONNECT_OK)
    {
        fprintf(stderr, "%s: nDPIsrvd socket connect failed!\n", argv[0]);
        nDPIsrvd_free(&sock);
        return 1;
    }

    while (main_thread_shutdown == 0)
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

    nDPIsrvd_free(&sock);

    return 0;
}
