#ifndef NDPISRVD_H
#define NDPISRVD_H 1

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "config.h"
#include "jsmn/jsmn.h"
#include "uthash.h"

struct nDPIsrvd_flow
{
    char id[24];
    UT_hash_handle hh;
    uint8_t user_data[0];
};

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

    struct
    {
        char const * event_name;
        int event_name_len;
        char const * flow_id;
        int flow_id_len;
    } current;
};

#define FIRST_ENUM_VALUE 1
#define LAST_ENUM_VALUE CALLBACK_LAST_ENUM_VALUE

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

typedef enum nDPIsrvd_callback_return (*json_callback)(struct nDPIsrvd_socket * const sock, void * const user_data);

/* Slightly modified code: https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64 */
#define WHITESPACE 64
#define EQUALS 65
#define INVALID 66
int nDPIsrvd_base64decode(char * in, size_t inLen, unsigned char * out, size_t * outLen)
{
    char * end = in + inLen;
    char iter = 0;
    uint32_t buf = 0;
    size_t len = 0;

    /* treat ASCII char 92 '\\' as whitespace because libnDPI escapes all strings by prepending '/' with a '\\' */
    static const unsigned char d[] = {66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 64, 66, 66, 66, 66, 66, 66, 66, 66, 66,
                                      66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
                                      66, 66, 66, 62, 66, 66, 66, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 66, 66,
                                      66, 65, 66, 66, 66, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
                                      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 66, 64, 66, 66, 66, 66, 26, 27, 28,
                                      29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                                      49, 50, 51, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
                                      66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
                                      66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
                                      66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
                                      66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
                                      66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
                                      66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66};

    while (in < end)
    {
        unsigned char c = d[*(unsigned char *)in++];

        switch (c)
        {
            case WHITESPACE:
                continue; /* skip whitespace */
            case INVALID:
                return 1; /* invalid input, return error */
            case EQUALS:  /* pad character, end of data */
                in = end;
                continue;
            default:
                buf = buf << 6 | c;
                iter++; // increment the number of iteration
                /* If the buffer is full, split it into bytes */
                if (iter == 4)
                {
                    if ((len += 3) > *outLen)
                        return 1; /* buffer overflow */
                    *(out++) = (buf >> 16) & 255;
                    *(out++) = (buf >> 8) & 255;
                    *(out++) = buf & 255;
                    buf = 0;
                    iter = 0;
                }
        }
    }

    if (iter == 3)
    {
        if ((len += 2) > *outLen)
            return 1; /* buffer overflow */
        *(out++) = (buf >> 10) & 255;
        *(out++) = (buf >> 2) & 255;
    }
    else if (iter == 2)
    {
        if (++len > *outLen)
            return 1; /* buffer overflow */
        *(out++) = (buf >> 4) & 255;
    }

    *outLen = len; /* modify to reflect the actual output size */
    return 0;
}

static inline char const * nDPIsrvd_enum_to_string(int enum_value)
{
    static char const * const enum_str[] = {"CONNECT_OK",
                                            "CONNECT_ERROR_SOCKET",
                                            "CONNECT_ERROR_PTON",
                                            "CONNECT_ERROR",
                                            "READ_OK",
                                            "READ_PEER_DISCONNECT",
                                            "READ_ERROR",
                                            "PARSE_OK",
                                            "PARSE_INVALID_OPENING_CHAR",
                                            "PARSE_SIZE_EXCEEDS_CONVERSION_LIMIT",
                                            "PARSE_SIZE_MISSING",
                                            "PARSE_STRING_TOO_BIG",
                                            "PARSE_INVALID_CLOSING_CHAR",
                                            "PARSE_JSMN_ERROR",
                                            "PARSE_CALLBACK_ERROR"};

    if (enum_value < FIRST_ENUM_VALUE || enum_value >= LAST_ENUM_VALUE)
    {
        return NULL;
    }

    return enum_str[enum_value - FIRST_ENUM_VALUE];
}

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

static inline void nDPIsrvd_free(struct nDPIsrvd_socket ** const sock, struct nDPIsrvd_flow ** const flow_table)
{
    struct nDPIsrvd_flow * current_flow;
    struct nDPIsrvd_flow * tmp;

    if (flow_table != NULL)
    {
        HASH_ITER(hh, *flow_table, current_flow, tmp)
        {
            HASH_DEL(*flow_table, current_flow);
            free(current_flow);
        }
        *flow_table = NULL;
    }

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

static inline int token_event_equals(struct nDPIsrvd_socket const * const sock, char const * const event_value)
{
    return sock->current.event_name != NULL && sock->current.event_name_len > 0 &&
           (int)strlen(event_value) == sock->current.event_name_len &&
           strncmp(sock->current.event_name, event_value, sock->current.event_name_len) == 0;
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

static inline struct nDPIsrvd_flow * nDPIsrvd_get_flow(struct nDPIsrvd_socket * const sock,
                                                       struct nDPIsrvd_flow ** const flow_table,
                                                       size_t user_data_size)
{
    if (token_is_start(sock) == 1)
    {
        memset(&sock->current, 0, sizeof(sock->current));
    }
    else if (token_is_end(sock) == 1)
    {
        if (sock->current.event_name != NULL && sock->current.flow_id != NULL)
        {
            if (strncmp(sock->current.event_name, "new", sock->current.event_name_len) == 0)
            {
                struct nDPIsrvd_flow * f = (struct nDPIsrvd_flow *)calloc(1, sizeof(*f) + user_data_size);
                if (f == NULL)
                {
                    return NULL;
                }
                snprintf(f->id, sizeof(f->id), "%.*s", sock->current.flow_id_len, sock->current.flow_id);
                HASH_ADD(hh, *flow_table, id, (size_t)sock->current.flow_id_len, f);
                return f;
            }
            else
            {
                struct nDPIsrvd_flow * f = NULL;
                HASH_FIND(hh, *flow_table, sock->current.flow_id, (size_t)sock->current.flow_id_len, f);
                return f;
            }
        }
    }
    else if (token_is_key_value_pair(sock) == 1)
    {
        if (key_equals(sock, "packet_event_name") == 1)
        {
            sock->current.event_name = sock->jsmn.key_value.value;
            sock->current.event_name_len = sock->jsmn.key_value.value_length;
        }
        else if (key_equals(sock, "flow_event_name") == 1)
        {
            sock->current.event_name = sock->jsmn.key_value.value;
            sock->current.event_name_len = sock->jsmn.key_value.value_length;
        }
        else if (key_equals(sock, "flow_id") == 1)
        {
            sock->current.flow_id = sock->jsmn.key_value.value;
            sock->current.flow_id_len = sock->jsmn.key_value.value_length;
        }
    }

    return NULL;
}

static inline enum nDPIsrvd_parse_return nDPIsrvd_parse(struct nDPIsrvd_socket * const sock,
                                                        json_callback cb,
                                                        void * user_data)
{
    while (sock->buffer.used >= NETWORK_BUFFER_LENGTH_DIGITS + 1)
    {
        if (sock->buffer.raw[NETWORK_BUFFER_LENGTH_DIGITS] != '{')
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
