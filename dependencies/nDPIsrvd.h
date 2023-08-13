#ifndef NDPISRVD_H
#define NDPISRVD_H 1

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef JSMN_PARENT_LINKS
#define JSMN_PARENT_LINKS 1
#endif

#include "config.h"
#include "jsmn.h"
#include "utarray.h"
#include "uthash.h"

#ifdef ENABLE_MEMORY_PROFILING
#include <stdarg.h>
#endif

#define nDPIsrvd_MAX_JSON_TOKENS (512u)
#define nDPIsrvd_JSON_KEY_STRLEN (32)
#define nDPIsrvd_HASHKEY_SEED (0x995fd871u)

#define nDPIsrvd_ARRAY_LENGTH(s) (sizeof(s) / sizeof(s[0]))
#define nDPIsrvd_STRLEN_SZ(s) (sizeof(s) / sizeof(s[0]) - sizeof(s[0]))
#define TOKEN_GET_SZ(sock, ...) nDPIsrvd_get_token(sock, __VA_ARGS__, NULL)
#define TOKEN_VALUE_EQUALS(sock, token, string_to_check, string_to_check_length)                                       \
    nDPIsrvd_token_value_equals(sock, token, string_to_check, string_to_check_length)
#define TOKEN_VALUE_EQUALS_SZ(sock, token, string_to_check)                                                            \
    nDPIsrvd_token_value_equals(sock, token, string_to_check, nDPIsrvd_STRLEN_SZ(string_to_check))
#define TOKEN_VALUE_TO_ULL(sock, token, value) nDPIsrvd_token_value_to_ull(sock, token, value)
#define TOKEN_GET_KEY(sock, token, key_length)                                                                         \
    (nDPIsrvd_jsmn_token_to_string(sock, &sock->jsmn.tokens[token->token_index - 1], key_length))
#define TOKEN_GET_VALUE(sock, token, value_length) (nDPIsrvd_get_jsmn_token_value(sock, token, value_length))

#define FIRST_ENUM_VALUE 1
#define LAST_ENUM_VALUE CLEANUP_REASON_LAST_ENUM_VALUE

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
    READ_TIMEOUT,
    READ_ERROR, /* check for errno */

    READ_LAST_ENUM_VALUE
};

enum nDPIsrvd_parse_return
{
    PARSE_OK = READ_LAST_ENUM_VALUE, /* can only be returned by nDPIsrvd_parse_line, not nDPIsrvd_parse_all */
    PARSE_NEED_MORE_DATA,            /* returned by nDPIsrvd_parse_line and nDPIsrvd_parse_all */
    PARSE_INVALID_OPENING_CHAR,
    PARSE_SIZE_EXCEEDS_CONVERSION_LIMIT,
    PARSE_SIZE_MISSING,
    PARSE_STRING_TOO_BIG,
    PARSE_INVALID_CLOSING_CHAR,
    PARSE_JSMN_NOMEM,
    PARSE_JSMN_INVALID,
    PARSE_JSMN_PARTIAL,
    PARSE_JSMN_UNKNOWN_ERROR,
    PARSE_JSON_CALLBACK_ERROR,
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

enum nDPIsrvd_cleanup_reason
{
    CLEANUP_REASON_DAEMON_INIT = CONVERSION_LAST_ENUM_VALUE, // can happen if kill -SIGKILL $(pidof nDPId) or restart
                                                             // after SIGSEGV
    CLEANUP_REASON_DAEMON_SHUTDOWN,                          // graceful shutdown e.g. kill -SIGTERM $(pidof nDPId)
    CLEANUP_REASON_FLOW_END,
    CLEANUP_REASON_FLOW_IDLE,
    CLEANUP_REASON_FLOW_TIMEOUT,
    CLEANUP_REASON_APP_SHUTDOWN,

    CLEANUP_REASON_LAST_ENUM_VALUE
};

typedef unsigned long long int nDPIsrvd_ull;
typedef nDPIsrvd_ull * nDPIsrvd_ull_ptr;
typedef uint32_t nDPIsrvd_hashkey;

struct nDPIsrvd_flow
{
    nDPIsrvd_hashkey flow_key;
    nDPIsrvd_ull id_as_ull;
    nDPIsrvd_hashkey thread_id;
    nDPIsrvd_ull last_seen;
    nDPIsrvd_ull idle_time;
    UT_hash_handle hh;
    uint8_t flow_user_data[0];
};

struct nDPIsrvd_thread_data
{
    nDPIsrvd_hashkey thread_key;
    nDPIsrvd_ull most_recent_flow_time;
    UT_hash_handle hh;
    uint8_t thread_user_data[0];
};

struct nDPIsrvd_instance
{
    nDPIsrvd_hashkey alias_source_key;
    struct nDPIsrvd_flow * flow_table;
    struct nDPIsrvd_thread_data * thread_data_table;
    UT_hash_handle hh;
    uint8_t instance_user_data[0];
};

struct nDPIsrvd_json_token
{
    nDPIsrvd_hashkey token_keys_hash;
    int token_index;
    UT_hash_handle hh;
};

struct nDPIsrvd_socket;
static inline void * nDPIsrvd_calloc(size_t const n, size_t const size);
static inline void * nDPIsrvd_malloc(size_t const size);
static inline void nDPIsrvd_free(void * const freeable);
#ifdef ENABLE_MEMORY_PROFILING
static inline void * nDPIsrvd_uthash_malloc(size_t const size);
static inline void nDPIsrvd_uthash_free(void * const freeable, size_t const size);
extern void nDPIsrvd_memprof_log(char const * const format, ...);
extern void nDPIsrvd_memprof_log_alloc(size_t);
extern void nDPIsrvd_memprof_log_free(size_t);
#endif

typedef enum nDPIsrvd_callback_return (*json_callback)(struct nDPIsrvd_socket * const sock,
                                                       struct nDPIsrvd_instance * const instance,
                                                       struct nDPIsrvd_thread_data * const thread_data,
                                                       struct nDPIsrvd_flow * const flow);
typedef void (*instance_cleanup_callback)(struct nDPIsrvd_socket * const sock,
                                          struct nDPIsrvd_instance * const instance,
                                          enum nDPIsrvd_cleanup_reason reason);
typedef void (*flow_cleanup_callback)(struct nDPIsrvd_socket * const sock,
                                      struct nDPIsrvd_instance * const instance,
                                      struct nDPIsrvd_thread_data * const thread_data,
                                      struct nDPIsrvd_flow * const flow,
                                      enum nDPIsrvd_cleanup_reason reason);

struct nDPIsrvd_address
{
    socklen_t size;
    union
    {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
        struct sockaddr raw;
    };
};

struct nDPIsrvd_buffer
{
    union
    {
        char * text;
        uint8_t * raw;
    } ptr;
    size_t used;
    size_t max;
};

struct nDPIsrvd_json_buffer
{
    struct nDPIsrvd_buffer buf;
    char * json_string;
    size_t json_string_start;
    nDPIsrvd_ull json_string_length;
};

struct nDPIsrvd_jsmn
{
    jsmn_parser parser;
    jsmntok_t tokens[nDPIsrvd_MAX_JSON_TOKENS];
    int tokens_found;
};

struct nDPIsrvd_socket
{
    int fd;
    struct timeval read_timeout;
    struct nDPIsrvd_address address;

    size_t instance_user_data_size;
    size_t thread_user_data_size;
    size_t flow_user_data_size;
    struct nDPIsrvd_instance * instance_table;
    json_callback json_callback;
    instance_cleanup_callback instance_cleanup_callback;
    flow_cleanup_callback flow_cleanup_callback;

    struct nDPIsrvd_json_buffer buffer;
    struct nDPIsrvd_jsmn jsmn;

    /* easy and fast JSON key/value access via hash table and a static array */
    struct
    {
        UT_array * tokens;
        struct nDPIsrvd_json_token * token_table;
    } json;

    size_t global_user_data_size;
    uint8_t global_user_data[0];
};

static inline void nDPIsrvd_socket_free(struct nDPIsrvd_socket ** const sock);

/* Slightly modified code: https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64 */
#define WHITESPACE 64
#define EQUALS 65
#define INVALID 66
static inline int nDPIsrvd_base64decode(char const * in, size_t inLen, unsigned char * out, size_t * outLen)
{
    char const * end = in + inLen;
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
    static char const * const enum_str[LAST_ENUM_VALUE + 1] = {"CONNECT_OK",
                                                               "CONNECT_ERROR_SOCKET",
                                                               "CONNECT_ERROR",

                                                               "READ_OK",
                                                               "READ_PEER_DISCONNECT",
                                                               "READ_TIMEOUT",
                                                               "READ_ERROR",

                                                               "PARSE_OK",
                                                               "PARSE_NEED_MORE_DATA",
                                                               "PARSE_INVALID_OPENING_CHAR",
                                                               "PARSE_SIZE_EXCEEDS_CONVERSION_LIMIT",
                                                               "PARSE_SIZE_MISSING",
                                                               "PARSE_STRING_TOO_BIG",
                                                               "PARSE_INVALID_CLOSING_CHAR",
                                                               "PARSE_JSMN_NOMEM",
                                                               "PARSE_JSMN_INVALID",
                                                               "PARSE_JSMN_PARTIAL",
                                                               "PARSE_JSMN_UNKNOWN_ERROR",
                                                               "PARSE_JSON_CALLBACK_ERROR",
                                                               "PARSE_FLOW_MGMT_ERROR",

                                                               "CALLBACK_OK",
                                                               "CALLBACK_ERROR",

                                                               "CONVERSION_OK",
                                                               "CONVERISON_KEY_NOT_FOUND",
                                                               "CONVERSION_NOT_A_NUMBER",
                                                               "CONVERSION_RANGE_EXCEEDED",

                                                               "CLEANUP_REASON_DAEMON_INIT",
                                                               "CLEANUP_REASON_DAEMON_SHUTDOWN",
                                                               "CLEANUP_REASON_FLOW_END",
                                                               "CLEANUP_REASON_FLOW_IDLE",
                                                               "CLEANUP_REASON_FLOW_TIMEOUT",
                                                               "CLEANUP_REASON_APP_SHUTDOWN",

                                                               [LAST_ENUM_VALUE] = "LAST_ENUM_VALUE"};

    if (enum_value < FIRST_ENUM_VALUE || enum_value >= LAST_ENUM_VALUE)
    {
        return NULL;
    }

    return enum_str[enum_value - FIRST_ENUM_VALUE];
}

static inline int nDPIsrvd_buffer_init(struct nDPIsrvd_buffer * const buffer, size_t buffer_size)
{
    if (buffer->ptr.raw != NULL)
    {
        return 1; /* Do not fail and realloc()? */
    }

    buffer->ptr.raw = (uint8_t *)nDPIsrvd_malloc(buffer_size);
    if (buffer->ptr.raw == NULL)
    {
        return 1;
    }

    buffer->used = 0;
    buffer->max = buffer_size;

    return 0;
}

static inline void nDPIsrvd_buffer_free(struct nDPIsrvd_buffer * const buffer)
{
    nDPIsrvd_free(buffer->ptr.raw);
    buffer->ptr.raw = NULL;
    buffer->used = 0;
    buffer->max = 0;
}

static inline int nDPIsrvd_json_buffer_init(struct nDPIsrvd_json_buffer * const json_buffer, size_t json_buffer_size)
{
    int ret = nDPIsrvd_buffer_init(&json_buffer->buf, json_buffer_size);
    if (ret == 0)
    {
        json_buffer->json_string_start = 0ul;
        json_buffer->json_string_length = 0ull;
        json_buffer->json_string = NULL;
    }

    return ret;
}

static inline void nDPIsrvd_json_buffer_free(struct nDPIsrvd_json_buffer * const json_buffer)
{
    nDPIsrvd_buffer_free(&json_buffer->buf);
    json_buffer->json_string_start = 0ul;
    json_buffer->json_string_length = 0ull;
    json_buffer->json_string = NULL;
}

static inline struct nDPIsrvd_socket * nDPIsrvd_socket_init(size_t global_user_data_size,
                                                            size_t instance_user_data_size,
                                                            size_t thread_user_data_size,
                                                            size_t flow_user_data_size,
                                                            json_callback json_cb,
                                                            instance_cleanup_callback instance_cleanup_cb,
                                                            flow_cleanup_callback flow_cleanup_callback_cb)
{
    static const UT_icd json_token_icd = {sizeof(struct nDPIsrvd_json_token), NULL, NULL, NULL};
    struct nDPIsrvd_socket * sock = (struct nDPIsrvd_socket *)nDPIsrvd_calloc(1, sizeof(*sock) + global_user_data_size);

    if (json_cb == NULL)
    {
        goto error;
    }

    if (sock != NULL)
    {
        sock->fd = -1;
        sock->read_timeout.tv_sec = 0;
        sock->read_timeout.tv_usec = 0;

        if (nDPIsrvd_json_buffer_init(&sock->buffer, NETWORK_BUFFER_MAX_SIZE) != 0)
        {
            goto error;
        }
        sock->address.raw.sa_family = -1;

        sock->instance_user_data_size = instance_user_data_size;
        sock->thread_user_data_size = thread_user_data_size;
        sock->flow_user_data_size = flow_user_data_size;

        sock->json_callback = json_cb;
        sock->instance_cleanup_callback = instance_cleanup_cb;
        sock->flow_cleanup_callback = flow_cleanup_callback_cb;

        utarray_new(sock->json.tokens, &json_token_icd);
        if (sock->json.tokens == NULL)
        {
            goto error;
        }
        utarray_reserve(sock->json.tokens, nDPIsrvd_MAX_JSON_TOKENS);

        sock->global_user_data_size = global_user_data_size;
    }

    return sock;
error:
    nDPIsrvd_json_buffer_free(&sock->buffer);
    nDPIsrvd_socket_free(&sock);
    return NULL;
}

static inline int nDPIsrvd_set_read_timeout(struct nDPIsrvd_socket * const sock,
                                            time_t seconds,
                                            suseconds_t micro_seconds)
{
    struct timeval tv = {.tv_sec = seconds, .tv_usec = micro_seconds};

    if (sock->fd < 0)
    {
        return 1;
    }

    if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        return 1;
    }

    sock->read_timeout = tv;

    return 0;
}

static inline int nDPIsrvd_set_nonblock(struct nDPIsrvd_socket * const sock)
{
    int flags;

    if (sock->fd < 0)
    {
        return 1;
    }

    flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags == -1)
    {
        return 1;
    }

    return (fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK) != 0);
}

static inline void nDPIsrvd_cleanup_flow(struct nDPIsrvd_socket * const sock,
                                         struct nDPIsrvd_instance * const instance,
                                         struct nDPIsrvd_thread_data * const thread_data,
                                         struct nDPIsrvd_flow * const flow,
                                         enum nDPIsrvd_cleanup_reason reason)
{
    if (sock->flow_cleanup_callback != NULL)
    {
        sock->flow_cleanup_callback(sock, instance, thread_data, flow, reason);
    }
    HASH_DEL(instance->flow_table, flow);
    nDPIsrvd_free(flow);
}

static inline void nDPIsrvd_cleanup_flows(struct nDPIsrvd_socket * const sock,
                                          struct nDPIsrvd_instance * const instance,
                                          struct nDPIsrvd_thread_data * const thread_data,
                                          enum nDPIsrvd_cleanup_reason reason)
{
    struct nDPIsrvd_flow * current_flow;
    struct nDPIsrvd_flow * ftmp;

    if (instance->flow_table != NULL)
    {
#ifdef ENABLE_MEMORY_PROFILING
        nDPIsrvd_memprof_log("Cleaning up flows for instance 0x%x and thread %d.",
                             instance->alias_source_key,
                             thread_data->thread_key);
#endif

        HASH_ITER(hh, instance->flow_table, current_flow, ftmp)
        {
            if (current_flow->thread_id == thread_data->thread_key)
            {
                nDPIsrvd_cleanup_flow(sock, instance, thread_data, current_flow, reason);
            }
        }
    }
}

static inline void nDPIsrvd_cleanup_instance(struct nDPIsrvd_socket * const sock,
                                             struct nDPIsrvd_instance * const instance,
                                             enum nDPIsrvd_cleanup_reason reason)
{
    struct nDPIsrvd_thread_data * current_thread_data;
    struct nDPIsrvd_thread_data * ttmp;

    if (instance != NULL)
    {
#ifdef ENABLE_MEMORY_PROFILING
        nDPIsrvd_memprof_log("Cleaning up instance 0x%x.", instance->alias_source_key);
#endif
        if (sock->instance_cleanup_callback != NULL)
        {
            sock->instance_cleanup_callback(sock, instance, reason);
        }

        if (instance->thread_data_table != NULL)
        {
            HASH_ITER(hh, instance->thread_data_table, current_thread_data, ttmp)
            {
                nDPIsrvd_cleanup_flows(sock, instance, current_thread_data, reason);
                HASH_DEL(instance->thread_data_table, current_thread_data);
                nDPIsrvd_free(current_thread_data);
            }
            instance->thread_data_table = NULL;
        }

        HASH_DEL(sock->instance_table, instance);
        nDPIsrvd_free(instance);
    }
}

static inline void nDPIsrvd_socket_free(struct nDPIsrvd_socket ** const sock)
{
    struct nDPIsrvd_instance * current_instance;
    struct nDPIsrvd_instance * itmp;
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

    HASH_ITER(hh, (*sock)->instance_table, current_instance, itmp)
    {
        nDPIsrvd_cleanup_instance(*sock, current_instance, CLEANUP_REASON_APP_SHUTDOWN);
    }
    (*sock)->instance_table = NULL;

    nDPIsrvd_json_buffer_free(&(*sock)->buffer);
    nDPIsrvd_free(*sock);

    *sock = NULL;
}

static inline int nDPIsrvd_setup_address(struct nDPIsrvd_address * const address, char const * const destination)
{
    size_t len = strlen(destination);
    char const * first_colon = strchr(destination, ':');
    char const * last_colon = strrchr(destination, ':');

    memset(address, 0, sizeof(*address));

    if (last_colon == NULL)
    {
        address->raw.sa_family = AF_UNIX;
        address->size = sizeof(address->un);
        if (snprintf(address->un.sun_path, sizeof(address->un.sun_path), "%s", destination) <= 0)
        {
            return 1;
        }
    }
    else
    {
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
        }
        else
        {
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
    if (sock->buffer.buf.used == sock->buffer.buf.max)
    {
        return READ_OK;
    }

    errno = 0;
    ssize_t bytes_read =
        read(sock->fd, sock->buffer.buf.ptr.raw + sock->buffer.buf.used, sock->buffer.buf.max - sock->buffer.buf.used);

    if (bytes_read == 0)
    {
        return READ_PEER_DISCONNECT;
    }
    if (bytes_read < 0)
    {
        if (errno == EAGAIN)
        {
            return READ_TIMEOUT;
        }
        return READ_ERROR;
    }

    sock->buffer.buf.used += bytes_read;

    return READ_OK;
}

static inline enum nDPIsrvd_conversion_return str_value_to_ull(char const * const value_as_string,
                                                               nDPIsrvd_ull_ptr const value)
{
    char * endptr = NULL;
    errno = 0;
    *value = strtoull(value_as_string, &endptr, 10);

    if (value_as_string == NULL || value_as_string == endptr)
    {
        return CONVERSION_NOT_A_NUMBER;
    }
    if (errno == ERANGE)
    {
        return CONVERSION_RANGE_EXCEEDED;
    }
    if (errno == EINVAL)
    {
        return CONVERSION_NOT_A_NUMBER;
    }

    return CONVERSION_OK;
}

static inline nDPIsrvd_hashkey nDPIsrvd_build_key(char const * str, int len)
{
    uint32_t hash = nDPIsrvd_HASHKEY_SEED;
    uint32_t c;

    while (len-- > 0 && (c = *str++) != 0)
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

static inline void nDPIsrvd_drain_buffer(struct nDPIsrvd_json_buffer * const json_buffer)
{
    memmove(json_buffer->buf.ptr.raw,
            json_buffer->buf.ptr.raw + json_buffer->json_string_length,
            json_buffer->buf.used - json_buffer->json_string_length);
    json_buffer->buf.used -= json_buffer->json_string_length;
    json_buffer->json_string_length = 0;
    json_buffer->json_string_start = 0;
}

static inline nDPIsrvd_hashkey nDPIsrvd_vbuild_jsmn_key(char const * const json_key, va_list ap)
{
    char const * arg;
    nDPIsrvd_hashkey key = nDPIsrvd_HASHKEY_SEED + nDPIsrvd_build_key(json_key, strlen(json_key));

    while ((arg = va_arg(ap, char const *)) != NULL)
    {
        key += nDPIsrvd_build_key(arg, strlen(arg));
    }

    return key;
}

static inline nDPIsrvd_hashkey nDPIsrvd_build_jsmn_key(char const * const json_key, ...)
{
    va_list ap;
    nDPIsrvd_hashkey key;

    va_start(ap, json_key);
    key = nDPIsrvd_vbuild_jsmn_key(json_key, ap);
    va_end(ap);

    return key;
}

static inline jsmntok_t const * nDPIsrvd_get_jsmn_token(struct nDPIsrvd_socket const * const sock,
                                                        struct nDPIsrvd_json_token const * const token)
{
    if (token == NULL)
    {
        return NULL;
    }

    if (token->token_index < 0 || token->token_index >= sock->jsmn.tokens_found)
    {
        return NULL;
    }

    return &sock->jsmn.tokens[token->token_index];
}

static inline char const * nDPIsrvd_get_jsmn_token_value(struct nDPIsrvd_socket const * const sock,
                                                         struct nDPIsrvd_json_token const * const token,
                                                         size_t * const value_length)
{
    jsmntok_t const * const jt = nDPIsrvd_get_jsmn_token(sock, token);

    if (jt == NULL)
    {
        return NULL;
    }

    if (jt->type != JSMN_STRING && jt->type != JSMN_PRIMITIVE)
    {
        return NULL;
    }

    if (value_length != NULL)
    {
        *value_length = jt->end - jt->start;
    }

    return sock->buffer.json_string + jt->start;
}

static inline char const * nDPIsrvd_jsmn_token_to_string(struct nDPIsrvd_socket const * const sock,
                                                         jsmntok_t const * const jt,
                                                         size_t * const string_length)
{
    if (jt->size == 0 || jt->start < 0 || jt->end < 0)
    {
        return NULL;
    }

    if (jt->type != JSMN_STRING && jt->type != JSMN_PRIMITIVE)
    {
        return NULL;
    }

    if (string_length != NULL)
    {
        *string_length = jt->end - jt->start;
    }

    return sock->buffer.json_string + jt->start;
}

static inline int nDPIsrvd_get_token_size(struct nDPIsrvd_socket const * const sock,
                                          struct nDPIsrvd_json_token const * const token)
{
    jsmntok_t const * const t = nDPIsrvd_get_jsmn_token(sock, token);

    if (t == NULL)
    {
        return 0;
    }

    return t->end - t->start;
}

static inline char const * nDPIsrvd_get_token_value(struct nDPIsrvd_socket const * const sock,
                                                    struct nDPIsrvd_json_token const * const token)
{
    jsmntok_t const * const t = nDPIsrvd_get_jsmn_token(sock, token);

    if (t == NULL)
    {
        return NULL;
    }

    return sock->buffer.json_string + t->start;
}

static inline struct nDPIsrvd_json_token const * nDPIsrvd_get_next_token(struct nDPIsrvd_socket const * const sock,
                                                                         struct nDPIsrvd_json_token const * const start,
                                                                         int * next_index)
{
    struct nDPIsrvd_json_token const * result = NULL;

    if (start == NULL || *next_index >= sock->jsmn.tokens_found)
    {
        return NULL;
    }

    if (*next_index < 0)
    {
        *next_index = start->token_index;
    }

    for (int i = *next_index + 1; i < sock->jsmn.tokens_found; ++i)
    {
        if (sock->jsmn.tokens[i].parent != start->token_index)
        {
            continue;
        }

        if (sock->jsmn.tokens[i].type != JSMN_STRING && sock->jsmn.tokens[i].type != JSMN_PRIMITIVE)
        {
            continue;
        }

        size_t key_len;
        char const * const key = nDPIsrvd_jsmn_token_to_string(sock, &sock->jsmn.tokens[i], &key_len);
        if (key == NULL)
        {
            break;
        }

        nDPIsrvd_hashkey hash_key = start->token_keys_hash + nDPIsrvd_build_key(key, key_len);
        HASH_FIND_INT(sock->json.token_table, &hash_key, result);
        *next_index = i;
        break;
    }

    return result;
}

static inline int nDPIsrvd_token_iterate(struct nDPIsrvd_socket const * const sock,
                                         struct nDPIsrvd_json_token const * const start,
                                         struct nDPIsrvd_json_token * const next)
{
    if (start == NULL || next->token_index >= sock->jsmn.tokens_found ||
        sock->jsmn.tokens[start->token_index].type != JSMN_ARRAY)
    {
        return 1;
    }

    if (next->token_index <= 0)
    {
        next->token_index = start->token_index;
    }

    next->token_index++;
    if (sock->jsmn.tokens[next->token_index].parent != start->token_index)
    {
        return 1;
    }
    next->token_keys_hash = 0;

    return 0;
}

static inline struct nDPIsrvd_json_token const * nDPIsrvd_get_token(struct nDPIsrvd_socket const * const sock,
                                                                    char const * const json_key,
                                                                    ...)
{
    va_list ap;
    struct nDPIsrvd_json_token * token = NULL;
    nDPIsrvd_hashkey hash_key;

    va_start(ap, json_key);
    hash_key = nDPIsrvd_vbuild_jsmn_key(json_key, ap);
    va_end(ap);

    HASH_FIND_INT(sock->json.token_table, &hash_key, token);
    if (token != NULL && token->token_index >= 0)
    {
        return token;
    }

    return NULL;
}

static inline int nDPIsrvd_token_value_equals(struct nDPIsrvd_socket const * const sock,
                                              struct nDPIsrvd_json_token const * const token,
                                              char const * const value,
                                              size_t value_length)
{
    if (token == NULL)
    {
        return 0;
    }

    return strncmp(nDPIsrvd_get_token_value(sock, token), value, nDPIsrvd_get_token_size(sock, token)) == 0 &&
           nDPIsrvd_get_token_size(sock, token) == (int)value_length;
}

static inline enum nDPIsrvd_conversion_return nDPIsrvd_token_value_to_ull(
    struct nDPIsrvd_socket const * const sock,
    struct nDPIsrvd_json_token const * const token,
    nDPIsrvd_ull_ptr const value)
{
    if (token == NULL)
    {
        return CONVERISON_KEY_NOT_FOUND;
    }

    return str_value_to_ull(nDPIsrvd_get_token_value(sock, token), value);
}

static inline int nDPIsrvd_build_instance_key(struct nDPIsrvd_socket const * const sock,
                                              struct nDPIsrvd_json_token const * const alias,
                                              struct nDPIsrvd_json_token const * const source,
                                              nDPIsrvd_hashkey * const alias_source_key)
{
    if (alias == NULL || source == NULL)
    {
        return 1;
    }

    *alias_source_key = nDPIsrvd_build_key(nDPIsrvd_get_token_value(sock, alias), nDPIsrvd_get_token_size(sock, alias));
    *alias_source_key ^=
        nDPIsrvd_build_key(nDPIsrvd_get_token_value(sock, source), nDPIsrvd_get_token_size(sock, source));

    return 0;
}

static inline int nDPIsrvd_build_flow_key(struct nDPIsrvd_socket const * const sock,
                                          struct nDPIsrvd_json_token const * const flow_id_token,
                                          nDPIsrvd_hashkey * const flow_key)
{
    if (flow_id_token == NULL)
    {
        return 1;
    }

    *flow_key =
        nDPIsrvd_build_key(nDPIsrvd_get_token_value(sock, flow_id_token), nDPIsrvd_get_token_size(sock, flow_id_token));

    return 0;
}

static inline struct nDPIsrvd_json_token * nDPIsrvd_find_token(struct nDPIsrvd_socket * const sock,
                                                               nDPIsrvd_hashkey hash_value)
{
    struct nDPIsrvd_json_token * token = NULL;

    HASH_FIND_INT(sock->json.token_table, &hash_value, token);
    return token;
}

static inline struct nDPIsrvd_json_token * nDPIsrvd_add_token(struct nDPIsrvd_socket * const sock,
                                                              nDPIsrvd_hashkey hash_value,
                                                              int value_token_index)
{
    struct nDPIsrvd_json_token * token = nDPIsrvd_find_token(sock, hash_value);

    if (token != NULL)
    {
        token->token_index = value_token_index;

        return token;
    }
    else
    {
        struct nDPIsrvd_json_token jt = {.token_keys_hash = hash_value, .token_index = value_token_index, .hh = {}};

        utarray_push_back(sock->json.tokens, &jt);
        HASH_ADD_INT(sock->json.token_table,
                     token_keys_hash,
                     (struct nDPIsrvd_json_token *)utarray_back(sock->json.tokens));

        return (struct nDPIsrvd_json_token *)utarray_back(sock->json.tokens);
    }
}

static inline int nDPIsrvd_walk_tokens(
    struct nDPIsrvd_socket * const sock, nDPIsrvd_hashkey h, size_t b, int count, uint8_t is_value, uint8_t depth)
{
    int i, j;
    jsmntok_t const * key;
    jsmntok_t const * const t = &sock->jsmn.tokens[b];
    char const * const js = sock->buffer.json_string;

    if (depth >= 16)
    {
        return 0;
    }
    if (count == 0)
    {
        return 0;
    }
    if (t->type == JSMN_PRIMITIVE)
    {
        if (is_value != 0)
        {
            nDPIsrvd_add_token(sock, h, b);
        }
        return 1;
    }
    else if (t->type == JSMN_STRING)
    {
        if (is_value != 0)
        {
            nDPIsrvd_add_token(sock, h, b);
        }
        return 1;
    }
    else if (t->type == JSMN_OBJECT)
    {
        j = 0;
        for (i = 0; i < t->size; i++)
        {
            key = t + 1 + j;
            j += nDPIsrvd_walk_tokens(sock, h, b + 1 + j, count - j, 0, depth + 1);
            if (key->size > 0)
            {
                nDPIsrvd_add_token(sock, h, b);
                j += nDPIsrvd_walk_tokens(sock,
                                          h + nDPIsrvd_build_key(js + key->start, key->end - key->start),
                                          b + 1 + j,
                                          count - j,
                                          1,
                                          depth + 1);
            }
        }
        return j + 1;
    }
    else if (t->type == JSMN_ARRAY)
    {
        nDPIsrvd_add_token(sock, h, b);
        j = 0;
        for (i = 0; i < t->size; i++)
        {
            j += nDPIsrvd_walk_tokens(sock, h, b + 1 + j, count - j, 0, depth + 1);
        }
        return j + 1;
    }
    return 0;
}

static inline struct nDPIsrvd_instance * nDPIsrvd_get_instance(struct nDPIsrvd_socket * const sock,
                                                               struct nDPIsrvd_json_token const * const alias,
                                                               struct nDPIsrvd_json_token const * const source)
{
    struct nDPIsrvd_instance * instance;
    nDPIsrvd_hashkey alias_source_key;

    if (nDPIsrvd_build_instance_key(sock, alias, source, &alias_source_key) != 0)
    {
        return NULL;
    }

    HASH_FIND_INT(sock->instance_table, &alias_source_key, instance);

    if (instance == NULL)
    {
        instance = (struct nDPIsrvd_instance *)nDPIsrvd_calloc(1, sizeof(*instance) + sock->instance_user_data_size);
        if (instance == NULL)
        {
            return NULL;
        }

        instance->alias_source_key = alias_source_key;
        HASH_ADD_INT(sock->instance_table, alias_source_key, instance);
#ifdef ENABLE_MEMORY_PROFILING
        nDPIsrvd_memprof_log("Instance alias \"%.*s\" with source \"%.*s\" added: %zu bytes.",
                             nDPIsrvd_get_token_size(sock, alias),
                             nDPIsrvd_get_token_value(sock, alias),
                             nDPIsrvd_get_token_size(sock, source),
                             nDPIsrvd_get_token_value(sock, source),
                             sizeof(*instance));
#endif
    }

    return instance;
}

static inline struct nDPIsrvd_thread_data * nDPIsrvd_get_thread_data(
    struct nDPIsrvd_socket * const sock,
    struct nDPIsrvd_instance * const instance,
    struct nDPIsrvd_json_token const * const thread_id_token,
    struct nDPIsrvd_json_token const * const ts_usec_token)
{
    struct nDPIsrvd_thread_data * thread_data;
    nDPIsrvd_hashkey thread_id;

    if (thread_id_token == NULL)
    {
        return NULL;
    }

    {
        nDPIsrvd_ull thread_key;
        TOKEN_VALUE_TO_ULL(sock, thread_id_token, &thread_key);
        thread_id = thread_key;
    }

    HASH_FIND_INT(instance->thread_data_table, &thread_id, thread_data);

    if (thread_data == NULL)
    {
        thread_data =
            (struct nDPIsrvd_thread_data *)nDPIsrvd_calloc(1, sizeof(*thread_data) + sock->thread_user_data_size);
        if (thread_data == NULL)
        {
            return NULL;
        }

        thread_data->thread_key = thread_id;
        HASH_ADD_INT(instance->thread_data_table, thread_key, thread_data);
#ifdef ENABLE_MEMORY_PROFILING
        nDPIsrvd_memprof_log("Thread Data %d added: %zu bytes.",
                             thread_data->thread_key,
                             sizeof(*thread_data) + sock->thread_user_data_size);
#endif
    }

    if (ts_usec_token != NULL)
    {
        nDPIsrvd_ull thread_ts_usec;
        TOKEN_VALUE_TO_ULL(sock, ts_usec_token, &thread_ts_usec);

        if (thread_ts_usec > thread_data->most_recent_flow_time)
        {
            thread_data->most_recent_flow_time = thread_ts_usec;
        }
    }

    return thread_data;
}

static inline struct nDPIsrvd_flow * nDPIsrvd_get_flow(struct nDPIsrvd_socket * const sock,
                                                       struct nDPIsrvd_instance ** const instance,
                                                       struct nDPIsrvd_thread_data ** const thread_data)
{
    struct nDPIsrvd_flow * flow;
    struct nDPIsrvd_json_token const * const tokens[] = {TOKEN_GET_SZ(sock, "alias"),
                                                         TOKEN_GET_SZ(sock, "source"),
                                                         TOKEN_GET_SZ(sock, "thread_id"),
                                                         TOKEN_GET_SZ(sock, "flow_id"),
                                                         TOKEN_GET_SZ(sock, "thread_ts_usec"),
                                                         TOKEN_GET_SZ(sock, "flow_src_last_pkt_time"),
                                                         TOKEN_GET_SZ(sock, "flow_dst_last_pkt_time"),
                                                         TOKEN_GET_SZ(sock, "flow_idle_time")};
    enum
    {
        TOKEN_ALIAS = 0,
        TOKEN_SOURCE,
        TOKEN_THREAD_ID,
        TOKEN_FLOW_ID,
        TOKEN_THREAD_TS_MSEC,
        TOKEN_FLOW_SRC_LAST_PKT_TIME,
        TOKEN_FLOW_DST_LAST_PKT_TIME,
        TOKEN_FLOW_IDLE_TIME
    };
    nDPIsrvd_hashkey flow_key;

    *instance = nDPIsrvd_get_instance(sock, tokens[TOKEN_ALIAS], tokens[TOKEN_SOURCE]);
    if (*instance == NULL)
    {
        return NULL;
    }

    *thread_data = nDPIsrvd_get_thread_data(sock, *instance, tokens[TOKEN_THREAD_ID], tokens[TOKEN_THREAD_TS_MSEC]);
    if (*thread_data == NULL)
    {
        return NULL;
    }

    if (nDPIsrvd_build_flow_key(sock, tokens[TOKEN_FLOW_ID], &flow_key) != 0)
    {
        return NULL;
    }
    HASH_FIND_INT((*instance)->flow_table, &flow_key, flow);

    if (flow == NULL)
    {
        flow = (struct nDPIsrvd_flow *)nDPIsrvd_calloc(1, sizeof(*flow) + sock->flow_user_data_size);
        if (flow == NULL)
        {
            return NULL;
        }

        flow->flow_key = flow_key;
        flow->thread_id = (*thread_data)->thread_key;

        TOKEN_VALUE_TO_ULL(sock, tokens[TOKEN_FLOW_ID], &flow->id_as_ull);
        HASH_ADD_INT((*instance)->flow_table, flow_key, flow);
#ifdef ENABLE_MEMORY_PROFILING
        nDPIsrvd_memprof_log("Flow %llu added: %zu bytes.", flow->id_as_ull, sizeof(*flow) + sock->flow_user_data_size);
#endif
    }

    if (tokens[TOKEN_FLOW_SRC_LAST_PKT_TIME] != NULL)
    {
        nDPIsrvd_ull nmb;
        TOKEN_VALUE_TO_ULL(sock, tokens[TOKEN_FLOW_SRC_LAST_PKT_TIME], &nmb);
        if (nmb > flow->last_seen)
        {
            flow->last_seen = nmb;
        }
    }
    if (tokens[TOKEN_FLOW_DST_LAST_PKT_TIME] != NULL)
    {
        nDPIsrvd_ull nmb;
        TOKEN_VALUE_TO_ULL(sock, tokens[TOKEN_FLOW_DST_LAST_PKT_TIME], &nmb);
        if (nmb > flow->last_seen)
        {
            flow->last_seen = nmb;
        }
    }

    if (tokens[TOKEN_FLOW_IDLE_TIME] != NULL)
    {
        nDPIsrvd_ull flow_idle_time;
        TOKEN_VALUE_TO_ULL(sock, tokens[TOKEN_FLOW_IDLE_TIME], &flow_idle_time);
        flow->idle_time = flow_idle_time;
    }

    return flow;
}

static inline int nDPIsrvd_check_flow_end(struct nDPIsrvd_socket * const sock,
                                          struct nDPIsrvd_instance * const instance,
                                          struct nDPIsrvd_thread_data * const thread_data,
                                          struct nDPIsrvd_flow * const current_flow)
{
    struct nDPIsrvd_json_token const * const tokens[] = {TOKEN_GET_SZ(sock, "daemon_event_name"),
                                                         TOKEN_GET_SZ(sock, "flow_event_name")};
    enum
    {
        TOKEN_DAEMON_EVENT_NAME = 0,
        TOKEN_FLOW_EVENT_NAME
    };

    if (instance == NULL)
    {
        return 0;
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, tokens[TOKEN_DAEMON_EVENT_NAME], "init") != 0)
    {
        nDPIsrvd_cleanup_flows(sock, instance, thread_data, CLEANUP_REASON_DAEMON_INIT);
    }
    if (TOKEN_VALUE_EQUALS_SZ(sock, tokens[TOKEN_DAEMON_EVENT_NAME], "shutdown") != 0)
    {
        nDPIsrvd_cleanup_flows(sock, instance, thread_data, CLEANUP_REASON_DAEMON_SHUTDOWN);
    }

    if (current_flow == NULL)
    {
        return 0;
    }

    int is_idle_flow;
    if ((is_idle_flow = TOKEN_VALUE_EQUALS_SZ(sock, tokens[TOKEN_FLOW_EVENT_NAME], "idle")) != 0 ||
        TOKEN_VALUE_EQUALS_SZ(sock, tokens[TOKEN_FLOW_EVENT_NAME], "end") != 0)
    {
#ifdef ENABLE_MEMORY_PROFILING
        nDPIsrvd_memprof_log("Flow %llu deleted: %zu bytes.",
                             current_flow->id_as_ull,
                             sizeof(*current_flow) + sock->flow_user_data_size);
#endif
        nDPIsrvd_cleanup_flow(sock,
                              instance,
                              thread_data,
                              current_flow,
                              (is_idle_flow != 0 ? CLEANUP_REASON_FLOW_IDLE : CLEANUP_REASON_FLOW_END));
    }
    else if (thread_data != NULL &&
             current_flow->last_seen + current_flow->idle_time < thread_data->most_recent_flow_time)
    {
#ifdef ENABLE_MEMORY_PROFILING
        nDPIsrvd_memprof_log(
            "Flow %llu timed out: %zu bytes. Last seen [%llu] + idle time [%llu] < most recent flow time [%llu]. Diff: "
            "[%llu]",
            current_flow->id_as_ull,
            sizeof(*current_flow) + sock->flow_user_data_size,
            current_flow->last_seen,
            current_flow->idle_time,
            thread_data->most_recent_flow_time,
            thread_data->most_recent_flow_time - (current_flow->last_seen + current_flow->idle_time));
#endif
        nDPIsrvd_cleanup_flow(sock, instance, thread_data, current_flow, CLEANUP_REASON_FLOW_TIMEOUT);
    }

    return 0;
}

static inline enum nDPIsrvd_parse_return nDPIsrvd_parse_line(struct nDPIsrvd_json_buffer * const json_buffer,
                                                             struct nDPIsrvd_jsmn * const jsmn)
{
    if (json_buffer->buf.used < NETWORK_BUFFER_LENGTH_DIGITS + 1)
    {
        return PARSE_NEED_MORE_DATA;
    }
    if (json_buffer->buf.ptr.text[NETWORK_BUFFER_LENGTH_DIGITS] != '{')
    {
        return PARSE_INVALID_OPENING_CHAR;
    }

    errno = 0;
    json_buffer->json_string_length = strtoull((const char *)json_buffer->buf.ptr.text, &json_buffer->json_string, 10);
    json_buffer->json_string_length += json_buffer->json_string - json_buffer->buf.ptr.text;
    json_buffer->json_string_start = json_buffer->json_string - json_buffer->buf.ptr.text;

    if (errno == ERANGE)
    {
        return PARSE_SIZE_EXCEEDS_CONVERSION_LIMIT;
    }
    if (json_buffer->json_string == json_buffer->buf.ptr.text)
    {
        return PARSE_SIZE_MISSING;
    }
    if (json_buffer->json_string_length > json_buffer->buf.max)
    {
        return PARSE_STRING_TOO_BIG;
    }
    if (json_buffer->json_string_length > json_buffer->buf.used)
    {
        return PARSE_NEED_MORE_DATA;
    }
    if (json_buffer->buf.ptr.text[json_buffer->json_string_length - 2] != '}' ||
        json_buffer->buf.ptr.text[json_buffer->json_string_length - 1] != '\n')
    {
        return PARSE_INVALID_CLOSING_CHAR;
    }

    jsmn_init(&jsmn->parser);
    jsmn->tokens_found = jsmn_parse(&jsmn->parser,
                                    json_buffer->buf.ptr.text + json_buffer->json_string_start,
                                    json_buffer->json_string_length - json_buffer->json_string_start,
                                    jsmn->tokens,
                                    nDPIsrvd_MAX_JSON_TOKENS);
    if (jsmn->tokens_found < 0 || jsmn->tokens[0].type != JSMN_OBJECT)
    {
        switch ((enum jsmnerr)jsmn->tokens_found)
        {
            case JSMN_ERROR_NOMEM:
                return PARSE_JSMN_NOMEM;
            case JSMN_ERROR_INVAL:
                return PARSE_JSMN_INVALID;
            case JSMN_ERROR_PART:
                return PARSE_JSMN_PARTIAL;
        }

        return PARSE_JSMN_UNKNOWN_ERROR;
    }

    return PARSE_OK;
}

static inline enum nDPIsrvd_parse_return nDPIsrvd_parse_all(struct nDPIsrvd_socket * const sock)
{
    enum nDPIsrvd_parse_return ret = PARSE_OK;

    while (ret == PARSE_OK && (ret = nDPIsrvd_parse_line(&sock->buffer, &sock->jsmn)) == PARSE_OK)
    {
        nDPIsrvd_walk_tokens(sock, nDPIsrvd_HASHKEY_SEED, 0, sock->jsmn.parser.toknext, 0, 0);

        struct nDPIsrvd_instance * instance = NULL;
        struct nDPIsrvd_thread_data * thread_data = NULL;
        struct nDPIsrvd_flow * flow = NULL;
        flow = nDPIsrvd_get_flow(sock, &instance, &thread_data);
        if (ret == PARSE_OK && sock->json_callback(sock, instance, thread_data, flow) != CALLBACK_OK)
        {
            ret = PARSE_JSON_CALLBACK_ERROR;
        }
        if (nDPIsrvd_check_flow_end(sock, instance, thread_data, flow) != 0)
        {
            ret = PARSE_FLOW_MGMT_ERROR;
        }

        sock->jsmn.tokens_found = 0;
        {
            struct nDPIsrvd_json_token * current_token = NULL;
            struct nDPIsrvd_json_token * jtmp = NULL;

            HASH_ITER(hh, sock->json.token_table, current_token, jtmp)
            {
                current_token->token_index = -1;
            }
        }

        nDPIsrvd_drain_buffer(&sock->buffer);
    }

    return ret;
}

static inline void * nDPIsrvd_calloc(size_t const n, size_t const size)
{
    void * p = nDPIsrvd_malloc(n * size);

    if (p == NULL)
    {
        return NULL;
    }
    memset(p, 0, n * size);

    return p;
}

static inline void * nDPIsrvd_malloc(size_t const size)
{
    void * p = malloc(sizeof(uint64_t) + size);

    if (p == NULL)
    {
        return NULL;
    }

    *(uint64_t *)p = size;
#ifdef ENABLE_MEMORY_PROFILING
    nDPIsrvd_memprof_log("malloc(%zu)", size);
    nDPIsrvd_memprof_log_alloc(size);
#endif

    return (uint8_t *)p + sizeof(uint64_t);
}

static inline void nDPIsrvd_free(void * const freeable)
{
    void * p;

    if (freeable == NULL)
    {
        return;
    }

    p = (uint8_t *)freeable - sizeof(uint64_t);

#ifdef ENABLE_MEMORY_PROFILING
    size_t size = *(uint64_t *)p;
    nDPIsrvd_memprof_log("free(%zu)", size);
    nDPIsrvd_memprof_log_free(size);
#endif

    free(p);
}

#ifdef ENABLE_MEMORY_PROFILING
static inline void * nDPIsrvd_uthash_malloc(size_t const size)
{
    void * p = malloc(size);

    if (p == NULL)
    {
        return NULL;
    }
    nDPIsrvd_memprof_log("uthash malloc(%zu)", size);

    return p;
}

static inline void nDPIsrvd_uthash_free(void * const freeable, size_t const size)
{
    nDPIsrvd_memprof_log("uthash free(%zu)", size);
    free(freeable);
}
#endif

static inline int nDPIsrvd_verify_flows(struct nDPIsrvd_instance * const instance,
                                        void (*verify_cb)(struct nDPIsrvd_thread_data const * const,
                                                          struct nDPIsrvd_flow const *,
                                                          void * user_data),
                                        void * user_data)
{
    int retval = 0;
    struct nDPIsrvd_flow const * current_flow;
    struct nDPIsrvd_flow const * ftmp;

    HASH_ITER(hh, instance->flow_table, current_flow, ftmp)
    {
        struct nDPIsrvd_thread_data * current_thread_data;

        HASH_FIND_INT(instance->thread_data_table, &current_flow->thread_id, current_thread_data);
        if (current_thread_data == NULL)
        {
            if (verify_cb != NULL)
            {
                verify_cb(current_thread_data, current_flow, user_data);
            }
            retval = 1;
        }
        else if (current_flow->thread_id != current_thread_data->thread_key)
        {
            if (verify_cb != NULL)
            {
                verify_cb(current_thread_data, current_flow, user_data);
            }
            retval = 1;
        }
        else if (current_flow->last_seen + current_flow->idle_time < current_thread_data->most_recent_flow_time)
        {
            if (verify_cb != NULL)
            {
                verify_cb(current_thread_data, current_flow, user_data);
            }
            retval = 1;
        }
    }

    return retval;
}

static inline void nDPIsrvd_flow_info(struct nDPIsrvd_socket const * const sock,
                                      void (*info_cb)(struct nDPIsrvd_socket const *,
                                                      struct nDPIsrvd_instance const *,
                                                      struct nDPIsrvd_thread_data const *,
                                                      struct nDPIsrvd_flow const *,
                                                      void *),
                                      void * user_data)
{
    struct nDPIsrvd_instance const * current_instance;
    struct nDPIsrvd_instance const * itmp;
    struct nDPIsrvd_thread_data * current_thread_data;
    struct nDPIsrvd_flow const * current_flow;
    struct nDPIsrvd_flow const * ftmp;

    if (sock->instance_table != NULL)
    {
        HASH_ITER(hh, sock->instance_table, current_instance, itmp)
        {
            if (current_instance->flow_table != NULL)
            {
                HASH_ITER(hh, current_instance->flow_table, current_flow, ftmp)
                {
                    HASH_FIND_INT(current_instance->thread_data_table, &current_flow->thread_id, current_thread_data);
                    info_cb(sock, current_instance, current_thread_data, current_flow, user_data);
                }
            }
        }
    }
}

static inline int nDPIsrvd_json_buffer_length(struct nDPIsrvd_socket const * const sock)
{
    return (int)sock->buffer.json_string_length - NETWORK_BUFFER_LENGTH_DIGITS;
}

static inline char const *nDPIsrvd_json_buffer_string(struct nDPIsrvd_socket const * const sock)
{
    return sock->buffer.json_string;
}

#endif
