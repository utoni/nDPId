#ifndef NDPISRVD_H
#define NDPISRVD_H 1

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "jsmn/jsmn.h"

struct nDPIsrvd_socket
{
    int fd;
    int socket_family;

    union {
        struct
        {
            char const * dst_ip;
            unsigned short dst_port;
        } ip_socket;
        struct
        {
            char * path;
        } unix_socket;
    } address;

    struct
    {
        char raw[NETWORK_BUFFER_MAX_SIZE];
        size_t used;
        char * json_string;
        size_t json_string_start;
        unsigned long long int json_string_length;
    } buffer;

    struct
    {
        jsmn_parser parser;
        jsmntok_t tokens[128];
        int current_token;
        int tokens_found;
    } jsmn;
};

#define FIRST_ENUM_VALUE 1

enum nDPIsrvd_connect_return
{
    CONNECT_OK = FIRST_ENUM_VALUE,
    CONNECT_ERROR_SOCKET,
    CONNECT_ERROR_PTON,
    CONNECT_ERROR,
    CONNECT_LAST_ENUM_VALUE
};

enum nDPIsrvd_read_return
{
    READ_OK = CONNECT_LAST_ENUM_VALUE,
    READ_PEER_DISCONNECT,
    READ_ERROR,
    READ_LAST_ENUM_VALUE
};

enum nDPIsrvd_parse_return
{
    PARSE_OK = READ_LAST_ENUM_VALUE,
    PARSE_INVALID_OPENING_CHAR,
    PARSE_SIZE_EXCEEDS_CONVERSION_LIMIT,
    PARSE_SIZE_MISSING,
    PARSE_STRING_TOO_BIG,
    PARSE_INVALID_CLOSING_CHAR,
    PARSE_JSMN_ERROR,
    PARSE_LAST_ENUM_VALUE
};

enum nDPIsrvd_callback_return
{
    CALLBACK_OK = PARSE_LAST_ENUM_VALUE,
    CALLBACK_ERROR,
    CALLBACK_LAST_ENUM_VALUE
};

typedef enum nDPIsrvd_callback_return (*json_callback)(struct nDPIsrvd_socket * const sock, void * user_data);

static inline struct nDPIsrvd_socket * nDPIsrvd_init(void)
{
    struct nDPIsrvd_socket * sock = (struct nDPIsrvd_socket *)malloc(sizeof(*sock));

    if (sock != NULL)
    {
        sock->fd = -1;
        sock->socket_family = -1;
    }
    return sock;
}

static inline enum nDPIsrvd_connect_return nDPIsrvd_connect_ip(struct nDPIsrvd_socket * const sock,
                                                               char const * dst_ip,
                                                               unsigned short dst_port)
{
    struct sockaddr_in remote_addr = {};

    sock->socket_family = remote_addr.sin_family = AF_INET;
    sock->fd = socket(sock->socket_family, SOCK_STREAM, 0);

    if (sock->fd < 0)
    {
        return CONNECT_ERROR_SOCKET;
    }

    if (inet_pton(sock->socket_family, &dst_ip[0], &remote_addr.sin_addr) != 1)
    {
        return CONNECT_ERROR_PTON;
    }
    remote_addr.sin_port = htons(dst_port);

    if (connect(sock->fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) != 0)
    {
        return CONNECT_ERROR;
    }

    return CONNECT_OK;
}

static inline enum nDPIsrvd_connect_return nDPIsrvd_connect_unix(struct nDPIsrvd_socket * const sock,
                                                                 char const * const path)
{
    (void)sock;
    (void)path;

    return CONNECT_OK;
}

static inline enum nDPIsrvd_read_return nDPIsrvd_read(struct nDPIsrvd_socket * const sock)
{
    ssize_t bytes_read =
        read(sock->fd, sock->buffer.raw + sock->buffer.used, sizeof(sock->buffer.raw) - sock->buffer.used);

    if (bytes_read == 0)
    {
        return READ_PEER_DISCONNECT;
    }
    if (bytes_read < 0)
    {
        return READ_ERROR;
    }

    sock->buffer.used += bytes_read;

    return READ_OK;
}

static inline enum nDPIsrvd_parse_return nDPIsrvd_parse(struct nDPIsrvd_socket * const sock,
                                                        json_callback cb,
                                                        void * user_data)
{
    while (sock->buffer.used >= nDPIsrvd_JSON_BYTES + 1)
    {
        if (sock->buffer.raw[nDPIsrvd_JSON_BYTES] != '{')
        {
            return PARSE_INVALID_OPENING_CHAR;
        }

        errno = 0;
        sock->buffer.json_string_length = strtoull((const char *)sock->buffer.raw, &sock->buffer.json_string, 10);
        sock->buffer.json_string_length += sock->buffer.json_string - sock->buffer.raw;
        sock->buffer.json_string_start = sock->buffer.json_string - sock->buffer.raw;

        if (errno == ERANGE)
        {
            return PARSE_SIZE_EXCEEDS_CONVERSION_LIMIT;
        }
        if (sock->buffer.json_string == sock->buffer.raw)
        {
            return PARSE_SIZE_MISSING;
        }
        if (sock->buffer.json_string_length > sizeof(sock->buffer.raw))
        {
            return PARSE_STRING_TOO_BIG;
        }
        if (sock->buffer.json_string_length > sock->buffer.used)
        {
            break;
        }

        if (sock->buffer.raw[sock->buffer.json_string_length - 1] != '}')
        {
            return PARSE_INVALID_CLOSING_CHAR;
        }

        jsmn_init(&sock->jsmn.parser);
        sock->jsmn.tokens_found = jsmn_parse(&sock->jsmn.parser,
                                             (char *)(sock->buffer.raw + sock->buffer.json_string_start),
                                             sock->buffer.json_string_length - sock->buffer.json_string_start,
                                             sock->jsmn.tokens,
                                             sizeof(sock->jsmn.tokens) / sizeof(sock->jsmn.tokens[0]));
        if (sock->jsmn.tokens_found < 0 || sock->jsmn.tokens[0].type != JSMN_OBJECT)
        {
            return PARSE_JSMN_ERROR;
        }

        for (sock->jsmn.current_token = 1; sock->jsmn.current_token < sock->jsmn.tokens_found;
             sock->jsmn.current_token++)
        {
            cb(sock, user_data);
        }

        memmove(sock->buffer.raw,
                sock->buffer.raw + sock->buffer.json_string_length,
                sock->buffer.used - sock->buffer.json_string_length);
        sock->buffer.used -= sock->buffer.json_string_length;
        sock->buffer.json_string_length = 0;
        sock->buffer.json_string_start = 0;
    }

    return PARSE_OK;
}

#endif
