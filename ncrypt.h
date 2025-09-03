#ifndef NCRYPT_H
#define NCRYPT_H 1

#include <stdlib.h>

#define ncrypt_ctx(x)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        (x)->ssl_ctx = NULL;                                                                                           \
    } while (0);
#define ncrypt_entity(x)                                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        (x)->ssl = NULL;                                                                                               \
        (x)->handshake_done = 0;                                                                                       \
    } while (0);
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

enum
{
    NCRYPT_SUCCESS = 0,
    NCRYPT_NOT_INITIALIZED = -1,
    NCRYPT_ALREADY_INITIALIZED = -2,
    NCRYPT_NULL_PTR = -3,
    NCRYPT_PEM_LOAD_FAILED = -4
};

struct ncrypt_ctx
{
    void * ssl_ctx;
};

struct ncrypt_entity
{
    void * ssl;
    int handshake_done;
};

int ncrypt_init(void);

int ncrypt_init_client(struct ncrypt_ctx * const ctx,
                       char const * const ca_path,
                       char const * const privkey_pem_path,
                       char const * const pubkey_pem_path);

int ncrypt_init_server(struct ncrypt_ctx * const ctx,
                       char const * const ca_path,
                       char const * const privkey_pem_path,
                       char const * const pubkey_pem_path);

int ncrypt_on_connect(struct ncrypt_ctx * const ctx, int connect_fd, struct ncrypt_entity * const ent);

int ncrypt_on_accept(struct ncrypt_ctx * const ctx, int accept_fd, struct ncrypt_entity * const ent);

ssize_t ncrypt_read(struct ncrypt_entity * const ent, char * const json_msg, size_t json_msg_len);

ssize_t ncrypt_write(struct ncrypt_entity * const ent, char const * const json_msg, size_t json_msg_len);

void ncrypt_free_entity(struct ncrypt_entity * const ent);

void ncrypt_free_ctx(struct ncrypt_ctx * const ctx);

#endif
