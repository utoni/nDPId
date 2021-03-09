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
#include "utarray.h"
#include "uthash.h"

#define nDPIsrvd_MAX_JSON_TOKENS 128
#define nDPIsrvd_FLOW_KEY_TOKENS 3
#define nDPIsrvd_FLOW_KEY_STRLEN 24
#define nDPIsrvd_JSON_KEY_STRLEN 32

#define nDPIsrvd_STRLEN_SZ(s) (sizeof(s)/sizeof(s[0]) - sizeof(s[0]))
#define TOKEN_GET_SZ(sock, key) token_get(sock, (char const *)key, nDPIsrvd_STRLEN_SZ(key))
#define TOKEN_GET_VALUE_SZ(sock, key, value_length) token_get_value(sock, (char const *)key, nDPIsrvd_STRLEN_SZ(key), value_length)
#define TOKEN_VALUE_EQUALS_SZ(token, string_to_check) token_value_equals(token, string_to_check, nDPIsrvd_STRLEN_SZ(string_to_check))
#define TOKEN_VALUE_TO_ULL(token, value) token_value_to_ull(token, value)

#define FIRST_ENUM_VALUE 1
#define LAST_ENUM_VALUE CONVERSION_LAST_ENUM_VALUE

enum nDPIsrvd_connect_return
{
    CONNECT_OK = FIRST_ENUM_VALUE,
    CONNECT_ERROR_SOCKET,
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
    PARSE_JSON_CALLBACK_ERROR,
    PARSE_JSON_MGMT_ERROR,
    PARSE_FLOW_MGMT_ERROR,

    PARSE_LAST_ENUM_VALUE
};

enum nDPIsrvd_callback_return
{
    CALLBACK_OK = PARSE_LAST_ENUM_VALUE,
    CALLBACK_ERROR,

    CALLBACK_LAST_ENUM_VALUE
};

enum nDPIsrvd_conversion_return
{
    CONVERSION_OK = CALLBACK_LAST_ENUM_VALUE,
    CONVERISON_KEY_NOT_FOUND,
    CONVERSION_NOT_A_NUMBER,
    CONVERSION_RANGE_EXCEEDED,

    CONVERSION_LAST_ENUM_VALUE
};

typedef unsigned long long int nDPIsrvd_ull;
typedef nDPIsrvd_ull * nDPIsrvd_ull_ptr;

struct nDPIsrvd_flow_key
{
    char key[nDPIsrvd_FLOW_KEY_STRLEN];
};

struct nDPIsrvd_flow
{
    struct nDPIsrvd_flow_key flow_key;
    nDPIsrvd_ull id_as_ull;
    UT_hash_handle hh;
    uint8_t flow_user_data[0];
};

struct nDPIsrvd_json_token
{
    char key[nDPIsrvd_JSON_KEY_STRLEN];
    int key_length;
    UT_hash_handle hh;
    char const * value;
    int value_length;
};

struct nDPIsrvd_socket;
#ifdef ENABLE_MEMORY_PROFILING
static inline void * nDPIsrvd_uthash_malloc(size_t const size);
static inline void nDPIsrvd_uthash_free(void * const freeable, size_t const size);
#endif

typedef enum nDPIsrvd_callback_return (*json_callback)(struct nDPIsrvd_socket * const sock,
                                                       struct nDPIsrvd_flow * const flow);
typedef void (*flow_end_callback)(struct nDPIsrvd_socket * const sock,
                                  struct nDPIsrvd_flow * const flow);

struct nDPIsrvd_address
{
    socklen_t size;
    union {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
        struct sockaddr raw;
    };
};

struct nDPIsrvd_socket
{
    int fd;
    struct nDPIsrvd_address address;

    size_t flow_user_data_size;
    struct nDPIsrvd_flow * flow_table;
    json_callback json_callback;
    flow_end_callback flow_end_callback;

    struct
    {
        char raw[NETWORK_BUFFER_MAX_SIZE];
        size_t used;
        char * json_string;
        size_t json_string_start;
        nDPIsrvd_ull json_string_length;
    } buffer;

    /* jsmn JSON parser */
    struct
    {
        jsmn_parser parser;
        jsmntok_t tokens[nDPIsrvd_MAX_JSON_TOKENS];
        int tokens_found;
    } jsmn;

    /* easy and fast JSON key/value access via hash table and a static array */
    struct
    {
        UT_array * tokens;
        struct nDPIsrvd_json_token * token_table;
    } json;

    size_t global_user_data_size;
    uint8_t global_user_data[0];
};

static inline void nDPIsrvd_free(struct nDPIsrvd_socket ** const sock);

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
    static char const * const enum_str[LAST_ENUM_VALUE + 1] = {
                                            "CONNECT_OK",
                                            "CONNECT_ERROR_SOCKET",
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
                                            "PARSE_JSON_CALLBACK_ERROR",
                                            "PARSE_JSON_MGMT_ERROR",
                                            "PARSE_FLOW_MGMT_ERROR",

                                            "CALLBACK_OK",
                                            "CALLBACK_ERROR",

                                            "CONVERSION_OK",
                                            "CONVERISON_KEY_NOT_FOUND",
                                            "CONVERSION_NOT_A_NUMBER",
                                            "CONVERSION_RANGE_EXCEEDED",

                                            [LAST_ENUM_VALUE] = "LAST_ENUM_VALUE"
    };

    if (enum_value < FIRST_ENUM_VALUE || enum_value >= LAST_ENUM_VALUE)
    {
        return NULL;
    }

    return enum_str[enum_value - FIRST_ENUM_VALUE];
}

static inline struct nDPIsrvd_socket * nDPIsrvd_init(size_t global_user_data_size,
                                                     size_t flow_user_data_size,
                                                     json_callback json_cb,
                                                     flow_end_callback flow_end_cb)
{
    static const UT_icd packet_data_icd = {sizeof(struct nDPIsrvd_json_token), NULL, NULL, NULL};
    struct nDPIsrvd_socket * sock = (struct nDPIsrvd_socket *)malloc(sizeof(*sock) + global_user_data_size);

    if (json_cb == NULL)
    {
        goto error;
    }

    if (sock != NULL)
    {
        memset(sock, 0, sizeof(*sock));

        sock->fd = -1;
        sock->address.raw.sa_family = -1;
        sock->flow_user_data_size = flow_user_data_size;

        sock->json_callback = json_cb;
        sock->flow_end_callback = flow_end_cb;

        utarray_new(sock->json.tokens, &packet_data_icd);
        if (sock->json.tokens == NULL)
        {
            goto error;
        }
        utarray_reserve(sock->json.tokens, nDPIsrvd_MAX_JSON_TOKENS);

        sock->global_user_data_size = global_user_data_size;
    }

    return sock;
error:
    nDPIsrvd_free(&sock);
    return NULL;
}

static inline void nDPIsrvd_free(struct nDPIsrvd_socket ** const sock)
{
    struct nDPIsrvd_flow * current_flow;
    struct nDPIsrvd_flow * ftmp;
    struct nDPIsrvd_json_token * current_json_token;
    struct nDPIsrvd_json_token * jtmp;

    if (sock == NULL || *sock == NULL)
    {
        return;
    }

    if ((*sock)->json.token_table != NULL)
    {
        HASH_ITER(hh, (*sock)->json.token_table, current_json_token, jtmp)
        {
            HASH_DEL((*sock)->json.token_table, current_json_token);
        }
        (*sock)->json.token_table = NULL;
    }

    if ((*sock)->json.tokens != NULL)
    {
        utarray_free((*sock)->json.tokens);
    }

    if ((*sock)->flow_table != NULL)
    {
        HASH_ITER(hh, (*sock)->flow_table, current_flow, ftmp)
        {
            if ((*sock)->flow_end_callback != NULL) {
                (*sock)->flow_end_callback(*sock, current_flow);
            }
            HASH_DEL((*sock)->flow_table, current_flow);
            free(current_flow);
        }
        (*sock)->flow_table = NULL;
    }

    free(*sock);

    *sock = NULL;
}

static inline int nDPIsrvd_setup_address(struct nDPIsrvd_address * const address, char const * const destination)
{
    size_t len = strlen(destination);
    char * first_colon = strchr(destination, ':');
    char * last_colon = strrchr(destination, ':');

    memset(address, 0, sizeof(*address));

    if (last_colon == NULL) {
        address->raw.sa_family = AF_UNIX;
        address->size = sizeof(address->un);
        if (snprintf(address->un.sun_path, sizeof(address->un.sun_path), "%s", destination) <= 0)
        {
            return 1;
        }
    } else {
        char addr_buf[INET6_ADDRSTRLEN];
        char const * address_start = destination;
        char const * address_end = last_colon;
        void * sock_addr;

        if (first_colon == last_colon)
        {
            address->raw.sa_family = AF_INET;
            address->size = sizeof(address->in);
            address->in.sin_port = htons(atoi(last_colon + 1));
            sock_addr = &address->in.sin_addr;

            if (len < 7)
            {
                return 1;
            }
        } else {
            address->raw.sa_family = AF_INET6;
            address->size = sizeof(address->in6);
            address->in6.sin6_port = htons(atoi(last_colon + 1));
            sock_addr = &address->in6.sin6_addr;

            if (len < 2)
            {
                return 1;
            }
            if (destination[0] == '[')
            {
                if (*(last_colon - 1) != ']')
                {
                    return 1;
                }
                address_start++;
                address_end--;
            }
        }

        if (snprintf(addr_buf, sizeof(addr_buf), "%.*s", (int)(address_end - address_start), address_start) <= 0)
        {
            return 1;
        }
        if (inet_pton(address->raw.sa_family, addr_buf, sock_addr) != 1)
        {
            return 1;
        }
    }

    return 0;
}

static inline enum nDPIsrvd_connect_return nDPIsrvd_connect(struct nDPIsrvd_socket * const sock)
{
    sock->fd = socket(sock->address.raw.sa_family, SOCK_STREAM, 0);

    if (sock->fd < 0)
    {
        return CONNECT_ERROR_SOCKET;
    }

    if (connect(sock->fd, &sock->address.raw, sock->address.size) != 0)
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

static inline int jsmn_token_is_key(int current_token_index)
{
    return current_token_index % 2;
}

static inline char const * jsmn_token_get(struct nDPIsrvd_socket const * const sock, int current_token_index)
{
    return sock->buffer.json_string + sock->jsmn.tokens[current_token_index].start;
}

static inline int jsmn_token_size(struct nDPIsrvd_socket const * const sock, int current_token_index)
{
    return sock->jsmn.tokens[current_token_index].end - sock->jsmn.tokens[current_token_index].start;
}

static inline int jsmn_token_is_jsmn_type(struct nDPIsrvd_socket const * const sock, int current_token_index, jsmntype_t type_to_check)
{
    return sock->jsmn.tokens[current_token_index].type == type_to_check;
}

static inline struct nDPIsrvd_json_token const *
token_get(struct nDPIsrvd_socket const * const sock, char const * const key, size_t key_length)
{
    struct nDPIsrvd_json_token * token = NULL;
    HASH_FIND(hh, sock->json.token_table, key, key_length, token);
    return token;
}

static inline char const *
token_get_value(struct nDPIsrvd_socket const * const sock, char const * const key, size_t key_length, size_t * value_length)
{
    struct nDPIsrvd_json_token const * const token = token_get(sock, key, key_length);
    if (token != NULL)
    {
        if (value_length != NULL)
        {
            *value_length = token->value_length;
        }
        return token->value;
    }

    return NULL;
}

static inline int is_token_valid(struct nDPIsrvd_json_token const * const token)
{
    return token != NULL && token->value_length > 0 && token->value != NULL;
}

static inline int token_value_equals(struct nDPIsrvd_json_token const * const token, char const * const value, size_t value_length)
{
    if (is_token_valid(token) == 0)
    {
        return 0;
    }

    return strncmp(token->value, value, token->value_length) == 0 &&
        token->value_length == (int)value_length;
}

static inline enum nDPIsrvd_conversion_return
str_value_to_ull(char const * const value_as_string, nDPIsrvd_ull_ptr const value)
{
    char * endptr = NULL;
    *value = strtoull(value_as_string, &endptr, 10);

    if (value_as_string == endptr)
    {
        return CONVERSION_NOT_A_NUMBER;
    }
    if (errno == ERANGE)
    {
        return CONVERSION_RANGE_EXCEEDED;
    }

    return CONVERSION_OK;
}

static inline enum nDPIsrvd_conversion_return
token_value_to_ull(struct nDPIsrvd_json_token const * const token, nDPIsrvd_ull_ptr const value)
{
    if (is_token_valid(token) == 0)
    {
        return CONVERISON_KEY_NOT_FOUND;
    }

    return str_value_to_ull(token->value, value);
}

static inline int nDPIsrvd_build_flow_key(struct nDPIsrvd_flow_key * const key,
                                          struct nDPIsrvd_json_token const * const tokens[nDPIsrvd_FLOW_KEY_TOKENS])
{
    if (is_token_valid(tokens[0]) == 0 || is_token_valid(tokens[1]) == 0 ||
        is_token_valid(tokens[2]) == 0)
    {
        return 1;
    }

    if (snprintf(key->key, nDPIsrvd_FLOW_KEY_STRLEN, "%.*s-%.*s-%.*s",
                 tokens[0]->value_length, tokens[0]->value,
                 tokens[1]->value_length, tokens[1]->value,
                 tokens[2]->value_length, tokens[2]->value) <= 0)
    {
        return 1;
    }

    return 0;
}

static inline struct nDPIsrvd_flow * nDPIsrvd_get_flow(struct nDPIsrvd_socket * const sock,
                                                       struct nDPIsrvd_json_token const * const flow_id)
{
    struct nDPIsrvd_json_token const * const tokens[nDPIsrvd_FLOW_KEY_TOKENS] = {
        flow_id, TOKEN_GET_SZ(sock, "alias"), TOKEN_GET_SZ(sock, "source"),
    };
    struct nDPIsrvd_flow_key key = {};

    if (nDPIsrvd_build_flow_key(&key, tokens) != 0)
    {
        return NULL;
    }

    struct nDPIsrvd_flow * flow = NULL;
    HASH_FIND(hh, sock->flow_table, &key, sizeof(key), flow);

    if (flow == NULL)
    {
        flow = (struct nDPIsrvd_flow *)calloc(1, sizeof(*flow) + sock->flow_user_data_size);
        if (flow == NULL)
        {
            return NULL;
        }

        TOKEN_VALUE_TO_ULL(tokens[0], &flow->id_as_ull);
        memcpy(flow->flow_key.key, key.key, nDPIsrvd_FLOW_KEY_STRLEN);
        HASH_ADD(hh, sock->flow_table, flow_key, sizeof(flow->flow_key), flow);
    }

    return flow;
}

static inline int nDPIsrvd_check_flow_end(struct nDPIsrvd_socket * const sock, struct nDPIsrvd_flow * const current_flow)
{
    if (current_flow == NULL)
    {
        return 1;
    }

    struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");

    if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "idle") != 0 &&
        TOKEN_VALUE_EQUALS_SZ(flow_event_name, "end") != 0)
    {
        if (sock->flow_end_callback != NULL) {
            sock->flow_end_callback(sock, current_flow);
        }
        HASH_DEL(sock->flow_table, current_flow);
        free(current_flow);
    }

    return 0;
}

static inline enum nDPIsrvd_parse_return nDPIsrvd_parse(struct nDPIsrvd_socket * const sock)
{
    enum nDPIsrvd_parse_return ret = PARSE_OK;

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
                                             sock->jsmn.tokens, nDPIsrvd_MAX_JSON_TOKENS);
        if (sock->jsmn.tokens_found < 0 || sock->jsmn.tokens[0].type != JSMN_OBJECT)
        {
            return PARSE_JSMN_ERROR;
        }

        char const * key = NULL;
        int key_length = 0;
        for (int current_token = 1; current_token < sock->jsmn.tokens_found; current_token++)
        {
            if (jsmn_token_is_key(current_token) == 1)
            {
                if (key != NULL)
                {
                    ret = PARSE_JSMN_ERROR;
                    break;
                }

                key = jsmn_token_get(sock, current_token);
                key_length = jsmn_token_size(sock, current_token);

                if (key == NULL)
                {
                    ret = PARSE_JSMN_ERROR;
                    break;
                }
            }
            else
            {
                struct nDPIsrvd_json_token * token = NULL;
                HASH_FIND(hh, sock->json.token_table, key, (size_t)key_length, token);

                if (token != NULL)
                {
                    token->value = jsmn_token_get(sock, current_token);
                    token->value_length = jsmn_token_size(sock, current_token);
                } else {
                    struct nDPIsrvd_json_token jt = {
                        .value = jsmn_token_get(sock, current_token),
                        .value_length = jsmn_token_size(sock, current_token),
                        .hh = {}
                    };

                    if (key == NULL || key_length > nDPIsrvd_JSON_KEY_STRLEN ||
                        utarray_len(sock->json.tokens) == nDPIsrvd_MAX_JSON_TOKENS)
                    {
                        ret = PARSE_JSON_MGMT_ERROR;
                        break;
                    }

                    jt.key_length = key_length;
                    snprintf(jt.key, nDPIsrvd_JSON_KEY_STRLEN, "%.*s",  key_length, key);
                    utarray_push_back(sock->json.tokens, &jt);
                    HASH_ADD_STR(sock->json.token_table, key,
                                 (struct nDPIsrvd_json_token *)utarray_back(sock->json.tokens));
                }

                key = NULL;
                key_length = 0;
            }
        }

        struct nDPIsrvd_json_token const * const flow_id = TOKEN_GET_SZ(sock, "flow_id");
        struct nDPIsrvd_flow * flow = NULL;
        if (is_token_valid(flow_id) != 0)
        {
            flow = nDPIsrvd_get_flow(sock, flow_id);
            if (flow == NULL)
            {
                ret = PARSE_FLOW_MGMT_ERROR;
            }
        }
        if (ret == PARSE_OK &&
            sock->json_callback(sock, flow) != CALLBACK_OK)
        {
            ret = PARSE_JSON_CALLBACK_ERROR;
        }
        if (is_token_valid(flow_id) != 0 && nDPIsrvd_check_flow_end(sock, flow) != 0)
        {
            ret = PARSE_FLOW_MGMT_ERROR;
        }

        sock->jsmn.tokens_found = 0;
        {
            struct nDPIsrvd_json_token * current_token = NULL;
            struct nDPIsrvd_json_token * jtmp = NULL;

            HASH_ITER(hh, sock->json.token_table, current_token, jtmp)
            {
                current_token->value = NULL;
                current_token->value_length = 0;
            }
        }

        memmove(sock->buffer.raw,
                sock->buffer.raw + sock->buffer.json_string_length,
                sock->buffer.used - sock->buffer.json_string_length);
        sock->buffer.used -= sock->buffer.json_string_length;
        sock->buffer.json_string_length = 0;
        sock->buffer.json_string_start = 0;
    }

    return ret;
}

#ifdef ENABLE_MEMORY_PROFILING
static inline void * nDPIsrvd_uthash_malloc(size_t const size)
{
    void * p = malloc(size);

    if (p == NULL)
    {
        return NULL;
    }
    printf("malloc(%zu)\n", size);

    return p;
}

static inline void nDPIsrvd_uthash_free(void * const freeable, size_t const size)
{
    printf("free(%zu)\n", size);
    free(freeable);
}
#endif

#endif
