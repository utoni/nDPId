#ifndef NCRYPT_H
#define NCRYPT_H 1

#include <time.h>
#include <unistd.h>

#define TLS_HANDSHAKE_TIMEOUT 5

#define WARN_UNUSED __attribute__((__warn_unused_result__))

#define ncrypt_ctx(x)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        (x)->ssl_ctx = NULL;                                                                                           \
    } while (0);
#define ncrypt_entity(x)                                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        (x)->ssl = NULL;                                                                                               \
        (x)->last_ncrypt_error = NCRYPT_SUCCESS;                                                                       \
        (x)->handshake_started = time(NULL);                                                                           \
        (x)->handshake_done = 0;                                                                                       \
        (x)->is_collector = 0;                                                                                         \
        (x)->is_distributor = 0;                                                                                       \
    } while (0);
#define ncrypt_last_error(x) ((x)->last_ncrypt_error)
#define ncrypt_handshake_done(x) ((x)->handshake_done)
#define ncrypt_set_handshake(x)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        (x)->handshake_done = 1;                                                                                       \
    } while (0)
#define ncrypt_clear_handshake(x)                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        (x)->handshake_done = 0;                                                                                       \
    } while (0)
#define ncrypt_since_start(x) ((long long int)(time(NULL) - (x)->handshake_started))

enum
{
    NCRYPT_SUCCESS = 0,
    NCRYPT_NOT_INITIALIZED = -1,
    NCRYPT_ALREADY_INITIALIZED = -2,
    NCRYPT_NULL_PTR = -3,
    NCRYPT_PEM_LOAD_FAILED = -4,
    NCRYPT_WANT_READ = -5,
    NCRYPT_WANT_WRITE = -6,
    NCRYPT_HANDSHAKE_FAILED = -7
};

struct ncrypt_ctx
{
    void * ssl_ctx;
};

struct ncrypt_entity
{
    void * ssl;
    int last_ncrypt_error;
    time_t handshake_started;
    unsigned int handshake_done : 1;
    unsigned int is_collector : 1;
    unsigned int is_distributor : 1;
};

int ncrypt_init(void);

WARN_UNUSED
int ncrypt_init_client(struct ncrypt_ctx * const ctx,
                       char const * const ca_path,
                       char const * const privkey_pem_path,
                       char const * const cert_pem_path);

WARN_UNUSED
int ncrypt_init_server(struct ncrypt_ctx * const ctx,
                       char const * const ca_path,
                       char const * const privkey_pem_path,
                       char const * const cert_pem_path);

WARN_UNUSED
int ncrypt_on_connect(struct ncrypt_ctx * const ctx, int connect_fd, struct ncrypt_entity * const ent);

WARN_UNUSED
int ncrypt_on_accept(struct ncrypt_ctx * const ctx, int accept_fd, struct ncrypt_entity * const ent);

WARN_UNUSED
ssize_t ncrypt_read(struct ncrypt_entity * const ent, char * const json_msg, int json_msg_len);

WARN_UNUSED
ssize_t ncrypt_write(struct ncrypt_entity * const ent, char const * const json_msg, int json_msg_len);

void ncrypt_free_entity(struct ncrypt_entity * const ent);

void ncrypt_free_ctx(struct ncrypt_ctx * const ctx);

#endif
