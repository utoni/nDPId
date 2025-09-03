#include "ncrypt.h"

#include <endian.h>
#include <openssl/conf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <unistd.h>

int ncrypt_init(void)
{
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    return NCRYPT_SUCCESS;
}

static int ncrypt_init_ctx(struct ncrypt_ctx * const ctx, SSL_METHOD const * const meth)
{
    if (meth == NULL)
    {
        return NCRYPT_NULL_PTR;
    }
    if (ctx->ssl_ctx != NULL)
    {
        return NCRYPT_ALREADY_INITIALIZED;
    }

    ctx->ssl_ctx = SSL_CTX_new(meth);
    if (ctx->ssl_ctx == NULL)
    {
        return NCRYPT_NOT_INITIALIZED;
    }

    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx->ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

    return NCRYPT_SUCCESS;
}

static int ncrypt_load_pems(struct ncrypt_ctx * const ctx,
                            char const * const ca_path,
                            char const * const privkey_pem_path,
                            char const * const pubkey_pem_path)
{
    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, pubkey_pem_path, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, privkey_pem_path, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_load_verify_locations(ctx->ssl_ctx, ca_path, NULL) <= 0)
    {
        return NCRYPT_PEM_LOAD_FAILED;
    }

    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx->ssl_ctx, 4);
    return NCRYPT_SUCCESS;
}

int ncrypt_init_client(struct ncrypt_ctx * const ctx,
                       char const * const ca_path,
                       char const * const privkey_pem_path,
                       char const * const pubkey_pem_path)
{
    if (ca_path == NULL || privkey_pem_path == NULL || pubkey_pem_path == NULL)
    {
        return NCRYPT_NULL_PTR;
    }

    int rv = ncrypt_init_ctx(ctx, TLS_client_method());

    if (rv != NCRYPT_SUCCESS)
    {
        return rv;
    }

    return ncrypt_load_pems(ctx, ca_path, privkey_pem_path, pubkey_pem_path);
}

int ncrypt_init_server(struct ncrypt_ctx * const ctx,
                       char const * const ca_path,
                       char const * const privkey_pem_path,
                       char const * const pubkey_pem_path)
{
    if (ca_path == NULL || privkey_pem_path == NULL || pubkey_pem_path == NULL)
    {
        return NCRYPT_NULL_PTR;
    }

    int rv = ncrypt_init_ctx(ctx, TLS_server_method());

    if (rv != NCRYPT_SUCCESS)
    {
        return rv;
    }

    return ncrypt_load_pems(ctx, ca_path, privkey_pem_path, pubkey_pem_path);
}

int ncrypt_on_connect(struct ncrypt_ctx * const ctx, int connect_fd, struct ncrypt_entity * const ent)
{
    if (ent->ssl == NULL)
    {
        ent->ssl = SSL_new(ctx->ssl_ctx);
        if (ent->ssl == NULL)
        {
            return NCRYPT_NOT_INITIALIZED;
        }
        SSL_set_fd(ent->ssl, connect_fd);
        SSL_set_connect_state(ent->ssl);
    }

    int rv = SSL_do_handshake(ent->ssl);
    if (rv != 1)
    {
        return SSL_get_error(ent->ssl, rv);
    }

    return NCRYPT_SUCCESS;
}

int ncrypt_on_accept(struct ncrypt_ctx * const ctx, int accept_fd, struct ncrypt_entity * const ent)
{
    if (ent->ssl == NULL)
    {
        ent->ssl = SSL_new(ctx->ssl_ctx);
        if (ent->ssl == NULL)
        {
            return NCRYPT_NOT_INITIALIZED;
        }
        SSL_set_fd(ent->ssl, accept_fd);
        SSL_set_accept_state(ent->ssl);
    }

    int rv = SSL_accept(ent->ssl);
    if (rv != 1)
    {
        return SSL_get_error(ent->ssl, rv);
    }

    return NCRYPT_SUCCESS;
}

ssize_t ncrypt_read(struct ncrypt_entity * const ent, char * const json_msg, size_t json_msg_len)
{
    if (ent->ssl == NULL)
    {
        errno = EPROTO;
        return -1;
    }

    int rv = SSL_read(ent->ssl, json_msg, json_msg_len);
    if (rv <= 0)
    {
        int err = SSL_get_error(ent->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
        {
            errno = EAGAIN;
        }
        else if (err != SSL_ERROR_SYSCALL)
        {
            errno = EPROTO;
        }
        return -1;
    }

    return rv;
}

ssize_t ncrypt_write(struct ncrypt_entity * const ent, char const * const json_msg, size_t json_msg_len)
{
    if (ent->ssl == NULL)
    {
        errno = EPROTO;
        return -1;
    }

    int rv = SSL_write(ent->ssl, json_msg, json_msg_len);
    if (rv <= 0)
    {
        int err = SSL_get_error(ent->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
        {
            errno = EAGAIN;
        }
        else if (err != SSL_ERROR_SYSCALL)
        {
            errno = EPROTO;
        }
        return -1;
    }

    return rv;
}

void ncrypt_free_entity(struct ncrypt_entity * const ent)
{
    SSL_free(ent->ssl);
    ent->ssl = NULL;
}

void ncrypt_free_ctx(struct ncrypt_ctx * const ctx)
{
    SSL_CTX_free(ctx->ssl_ctx);
    ctx->ssl_ctx = NULL;
    EVP_cleanup();
}
