#ifndef NDPISRVD_H
#define NDPISRVD_H 1

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
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
        struct
        {
            char const * key;
            int key_length;
            char const * value;
            int value_length;
        } key_value;
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
    PARSE_CALLBACK_ERROR,
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

static inline void nDPIsrvd_free(struct nDPIsrvd_socket ** const sock)
{
    free(*sock);

    *sock = NULL;
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
    struct sockaddr_un remote_addr = {};

    sock->socket_family = remote_addr.sun_family = AF_UNIX;
    sock->fd = socket(sock->socket_family, SOCK_STREAM, 0);

    if (sock->fd < 0)
    {
        return CONNECT_ERROR_SOCKET;
    }

    if (snprintf(remote_addr.sun_path, sizeof(remote_addr.sun_path), "%s", path) <= 0)
    {
        return CONNECT_ERROR_SOCKET;
    }

    if (connect(sock->fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) != 0)
    {
        return CONNECT_ERROR;
    }

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

static inline int token_is_key(struct nDPIsrvd_socket const * const sock)
{
    return sock->jsmn.current_token % 2;
}

static inline char const * token_get(struct nDPIsrvd_socket const * const sock)
{
    return sock->buffer.json_string + sock->jsmn.tokens[sock->jsmn.current_token].start;
}

static inline int token_size(struct nDPIsrvd_socket const * const sock)
{
    return sock->jsmn.tokens[sock->jsmn.current_token].end - sock->jsmn.tokens[sock->jsmn.current_token].start;
}

static inline int token_is_start(struct nDPIsrvd_socket const * const sock)
{
    return sock->jsmn.current_token == 0;
}

static inline int token_is_end(struct nDPIsrvd_socket const * const sock)
{
    return sock->jsmn.current_token == sock->jsmn.tokens_found;
}

static inline int token_is_key_value_pair(struct nDPIsrvd_socket const * const sock)
{
    return sock->jsmn.current_token > 0 && sock->jsmn.current_token < sock->jsmn.tokens_found;
}

static inline int token_is_jsmn_type(struct nDPIsrvd_socket const * const sock, jsmntype_t type_to_check)
{
    if (token_is_key_value_pair(sock) == 0)
    {
        return 0;
    }

    return sock->jsmn.tokens[sock->jsmn.current_token].type == type_to_check;
}

static inline int key_equals(struct nDPIsrvd_socket const * const sock, char const * const name)
{
    if (sock->jsmn.key_value.key == NULL || sock->jsmn.key_value.key_length == 0)
    {
        return 0;
    }

    return (int)strlen(name) == sock->jsmn.key_value.key_length &&
           strncmp(name, sock->jsmn.key_value.key, sock->jsmn.key_value.key_length) == 0;
}

static inline int value_equals(struct nDPIsrvd_socket const * const sock, char const * const name)
{
    if (sock->jsmn.key_value.value == NULL || sock->jsmn.key_value.value_length == 0)
    {
        return 0;
    }

    return (int)strlen(name) == sock->jsmn.key_value.value_length &&
           strncmp(name, sock->jsmn.key_value.value, sock->jsmn.key_value.value_length) == 0;
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

        if (sock->buffer.raw[sock->buffer.json_string_length - 2] != '}' ||
            sock->buffer.raw[sock->buffer.json_string_length - 1] != '\n')
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

        sock->jsmn.key_value.key = NULL;
        sock->jsmn.key_value.key_length = 0;
        sock->jsmn.key_value.value = NULL;
        sock->jsmn.key_value.value_length = 0;
        sock->jsmn.current_token = 0;
        if (cb(sock, user_data) != CALLBACK_OK)
        {
            return PARSE_CALLBACK_ERROR;
        }

        for (sock->jsmn.current_token = 1; sock->jsmn.current_token < sock->jsmn.tokens_found;
             sock->jsmn.current_token++)
        {
            if (token_is_key(sock) == 1)
            {
                sock->jsmn.key_value.key = token_get(sock);
                sock->jsmn.key_value.key_length = token_size(sock);

                if (sock->jsmn.key_value.key == NULL || sock->jsmn.key_value.value != NULL)
                {
                    return PARSE_JSMN_ERROR;
                }
            }
            else
            {
                sock->jsmn.key_value.value = token_get(sock);
                sock->jsmn.key_value.value_length = token_size(sock);

                if (sock->jsmn.key_value.key == NULL || sock->jsmn.key_value.value == NULL)
                {
                    return PARSE_JSMN_ERROR;
                }
                if (cb(sock, user_data) != CALLBACK_OK)
                {
                    return PARSE_CALLBACK_ERROR;
                }

                sock->jsmn.key_value.key = NULL;
                sock->jsmn.key_value.key_length = 0;
                sock->jsmn.key_value.value = NULL;
                sock->jsmn.key_value.value_length = 0;
            }
        }

        if (cb(sock, user_data) != CALLBACK_OK)
        {
            return PARSE_CALLBACK_ERROR;
        }

        sock->jsmn.current_token = -1;
        sock->jsmn.tokens_found = 0;

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
