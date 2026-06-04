#include "ncrypt.h"

#include <endian.h>
#include <openssl/conf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <unistd.h>

int ncrypt_init(void)
{
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    //ERR_print_errors_fp(stderr);

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
                            char const * const cert_pem_path)
{
    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, cert_pem_path, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, privkey_pem_path, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_load_verify_locations(ctx->ssl_ctx, ca_path, NULL) <= 0)
    {
        return NCRYPT_PEM_LOAD_FAILED;
    }

    if (SSL_CTX_check_private_key(ctx->ssl_ctx) != 1) {
        return NCRYPT_PEM_LOAD_FAILED;
    }

    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx->ssl_ctx, 1);
    return NCRYPT_SUCCESS;
}

int ncrypt_init_client(struct ncrypt_ctx * const ctx,
                       char const * const ca_path,
                       char const * const privkey_pem_path,
                       char const * const cert_pem_path)
{
    if (ca_path == NULL || privkey_pem_path == NULL || cert_pem_path == NULL)
    {
        return NCRYPT_NULL_PTR;
    }

    int rv = ncrypt_init_ctx(ctx, TLS_client_method());

    if (rv != NCRYPT_SUCCESS)
    {
        return rv;
    }

    return ncrypt_load_pems(ctx, ca_path, privkey_pem_path, cert_pem_path);
}

int ncrypt_init_server(struct ncrypt_ctx * const ctx,
                       char const * const ca_path,
                       char const * const privkey_pem_path,
                       char const * const cert_pem_path)
{
    if (ca_path == NULL || privkey_pem_path == NULL || cert_pem_path == NULL)
    {
        return NCRYPT_NULL_PTR;
    }

    int rv = ncrypt_init_ctx(ctx, TLS_server_method());

    if (rv != NCRYPT_SUCCESS)
    {
        return rv;
    }

    return ncrypt_load_pems(ctx, ca_path, privkey_pem_path, cert_pem_path);
}

int ncrypt_on_connect(struct ncrypt_ctx * const ctx, int connect_fd, struct ncrypt_entity * const ent)
{
    if (ent->ssl == NULL)
    {
        ent->ssl = SSL_new(ctx->ssl_ctx);
        if (ent->ssl == NULL)
        {
            ent->last_ncrypt_error = NCRYPT_NOT_INITIALIZED;
            return NCRYPT_NOT_INITIALIZED;
        }
        SSL_set1_host(ent->ssl, "nDPIsrvd");
        SSL_set_hostflags(ent->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        SSL_set_fd(ent->ssl, connect_fd);
        SSL_set_connect_state(ent->ssl);
    }

    int rv = SSL_do_handshake(ent->ssl);
    if (rv != 1)
    {
        int err = SSL_get_error(ent->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE)
        {
            ent->last_ncrypt_error = NCRYPT_WANT_WRITE;
            return NCRYPT_WANT_WRITE;
        }
        else if (err == SSL_ERROR_WANT_READ)
        {
            ent->last_ncrypt_error = NCRYPT_WANT_READ;
            return NCRYPT_WANT_READ;
        }
        ent->last_ncrypt_error = NCRYPT_HANDSHAKE_FAILED;
        return NCRYPT_HANDSHAKE_FAILED;
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
            ent->last_ncrypt_error = NCRYPT_NOT_INITIALIZED;
            return NCRYPT_NOT_INITIALIZED;
        }
        SSL_set_fd(ent->ssl, accept_fd);
        SSL_set_accept_state(ent->ssl);
    }

    int rv = SSL_accept(ent->ssl);
    if (rv != 1)
    {
        int err = SSL_get_error(ent->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE)
        {
            ent->last_ncrypt_error = NCRYPT_WANT_WRITE;
            return NCRYPT_WANT_WRITE;
        }
        else if (err == SSL_ERROR_WANT_READ)
        {
            ent->last_ncrypt_error = NCRYPT_WANT_READ;
            return NCRYPT_WANT_READ;
        }
        ent->last_ncrypt_error = NCRYPT_HANDSHAKE_FAILED;
        return NCRYPT_HANDSHAKE_FAILED;
    }

    X509 * const peer = SSL_get_peer_certificate(ent->ssl);
    if (peer == NULL)
    {
        ent->last_ncrypt_error = NCRYPT_HANDSHAKE_FAILED;
        return NCRYPT_HANDSHAKE_FAILED;
    }
    //PEM_write_X509(stderr, peer);

    int matched = 0;
    STACK_OF(GENERAL_NAME) *sans =
        X509_get_ext_d2i(peer, NID_subject_alt_name, NULL, NULL);

    if (sans != NULL)
    {
        int n = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < n && !matched; i++)
        {
            const GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
            if (gn->type != GEN_DNS)
                continue;

            const unsigned char *data = ASN1_STRING_get0_data(gn->d.dNSName);
            int len = ASN1_STRING_length(gn->d.dNSName);

            if (len <= 0 || memchr(data, 0, (size_t)len) != NULL)
                continue;

            if ((size_t)len == strlen("collector") &&
                memcmp(data, "collector", (size_t)len) == 0)
            {
                ent->is_collector = 0b1;
                matched = 1;
            }
            else if ((size_t)len == strlen("distributor") &&
                     memcmp(data, "distributor", (size_t)len) == 0)
            {
                ent->is_distributor = 0b1;
                matched = 1;
            }
        }
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    }

    X509_free(peer);

    if (!matched)
    {
        ent->last_ncrypt_error = EPROTO;
        return NCRYPT_HANDSHAKE_FAILED;
    }

    return NCRYPT_SUCCESS;
}

ssize_t ncrypt_read(struct ncrypt_entity * const ent, char * const json_msg, int json_msg_len)
{
    if (ent->ssl == NULL)
    {
        ent->last_ncrypt_error = NCRYPT_NOT_INITIALIZED;
        return -1;
    }

    if (ncrypt_handshake_done(ent) == 0)
    {
        ent->last_ncrypt_error = NCRYPT_HANDSHAKE_FAILED;
        return -1;
    }

    int rv = SSL_read(ent->ssl, json_msg, json_msg_len);
    if (rv <= 0)
    {
        int err = SSL_get_error(ent->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE)
        {
            ent->last_ncrypt_error = NCRYPT_WANT_WRITE;
        }
        else if (err == SSL_ERROR_WANT_READ)
        {
            ent->last_ncrypt_error = NCRYPT_WANT_READ;
        }
        return -1;
    }

    return rv;
}

ssize_t ncrypt_write(struct ncrypt_entity * const ent, char const * const json_msg, int json_msg_len)
{
    if (ent->ssl == NULL)
    {
        ent->last_ncrypt_error = NCRYPT_NOT_INITIALIZED;
        return -1;
    }

    if (ncrypt_handshake_done(ent) == 0)
    {
        ent->last_ncrypt_error = NCRYPT_HANDSHAKE_FAILED;
        return -1;
    }

    int rv = SSL_write(ent->ssl, json_msg, json_msg_len);
    if (rv <= 0)
    {
        int err = SSL_get_error(ent->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE)
        {
            ent->last_ncrypt_error = NCRYPT_WANT_WRITE;
        }
        else if (err == SSL_ERROR_WANT_READ)
        {
            ent->last_ncrypt_error = NCRYPT_WANT_READ;
        }
        return -1;
    }

    return rv;
}

void ncrypt_free_entity(struct ncrypt_entity * const ent)
{
    if (ent->ssl != NULL) {
        SSL_shutdown(ent->ssl);
        SSL_free(ent->ssl);
    }
    ent->ssl = NULL;
}

void ncrypt_free_ctx(struct ncrypt_ctx * const ctx)
{
    SSL_CTX_free(ctx->ssl_ctx);
    ctx->ssl_ctx = NULL;
}
