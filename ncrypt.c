#include "ncrypt.h"

#include <endian.h>
#include <openssl/conf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include <unistd.h>

#define OPENSSL_DUMP(ptr, siz)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        BIO_dump_indent_fp(stderr, ptr, siz, 2);                                                                       \
        fputc('\n', stderr);                                                                                           \
    } while (0);
#define OPENSSL_ERROR(retval)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        fprintf(stderr, "OpenSSL Error: %s\n", ERR_error_string(ERR_get_error(), NULL));                               \
    } while (0);

union iv
{
    struct
    {
        uint32_t upper;
        uint64_t lower;
    } __attribute__((__packed__)) numeric;
    unsigned char buffer[NCRYPT_AES_IVLEN];
};

int ncrypt_keygen(unsigned char priv_key[NCRYPT_X25519_KEYLEN], unsigned char pub_key[NCRYPT_X25519_KEYLEN])
{
    EVP_PKEY * const pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    size_t klen = NCRYPT_X25519_KEYLEN;

    if (EVP_PKEY_get_raw_private_key(pkey, priv_key, &klen) == 0 || klen != NCRYPT_X25519_KEYLEN)
    {
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &klen) == 0 || klen != NCRYPT_X25519_KEYLEN)
    {
        return -2;
        EVP_PKEY_free(pkey);
    }

    EVP_PKEY_free(pkey);
    return 0;
}

int ncrypt_load_privkey(char const * const private_key_file, unsigned char priv_key[NCRYPT_X25519_KEYLEN])
{
    FILE * const pkfp = fopen(private_key_file, "r+b");
    EVP_PKEY * pkey = NULL;
    size_t klen = NCRYPT_X25519_KEYLEN;

    if (pkfp == NULL)
    {
        return -1;
    }

    pkey = PEM_read_PrivateKey(pkfp, NULL, NULL, NULL);
    if (pkey == NULL)
    {
        fclose(pkfp);
        return -2;
    }
    fclose(pkfp);

    if (EVP_PKEY_get_raw_private_key(pkey, priv_key, &klen) == 0 || klen != NCRYPT_X25519_KEYLEN)
    {
        EVP_PKEY_free(pkey);
        return -3;
    }

    EVP_PKEY_free(pkey);
    return 0;
}

int ncrypt_load_pubkey(char const * const public_key_file, unsigned char pub_key[NCRYPT_X25519_KEYLEN])
{
    FILE * const pkfp = fopen(public_key_file, "r+b");
    EVP_PKEY * pkey = NULL;
    size_t klen = NCRYPT_X25519_KEYLEN;

    if (pkfp == NULL)
    {
        return -1;
    }

    pkey = PEM_read_PUBKEY(pkfp, NULL, NULL, NULL);
    if (pkey == NULL)
    {
        fclose(pkfp);
        return -2;
    }
    fclose(pkfp);

    if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &klen) == 0 || klen != NCRYPT_X25519_KEYLEN)
    {
        EVP_PKEY_free(pkey);
        return -3;
    }

    EVP_PKEY_free(pkey);
    return 0;
}

static int init_iv(struct ncrypt * const nc)
{
    FILE * rnd_fp;

    rnd_fp = fopen("/dev/random", "r+b");

    if (rnd_fp == NULL)
    {
        return -1;
    }

    if (fread(&nc->iv[0], sizeof(nc->iv[0]), sizeof(nc->iv) / sizeof(nc->iv[0]), rnd_fp) != NCRYPT_AES_IVLEN)
    {
        fclose(rnd_fp);
        return -2;
    }

    fclose(rnd_fp);

    return 0;
}

static void next_iv(struct ncrypt * const nc)
{
    union iv * const iv = (union iv *)&nc->iv[0];

    uint64_t lower = be64toh(iv->numeric.lower);
    lower++;
    iv->numeric.lower = htobe64(lower);

    if (iv->numeric.lower == 0)
    {
        uint32_t upper = be32toh(iv->numeric.upper);
        upper++;
        iv->numeric.upper = htobe32(upper);
    }
}

int ncrypt_init(struct ncrypt * const nc,
                unsigned char local_priv_key[NCRYPT_X25519_KEYLEN],
                unsigned char remote_pub_key[NCRYPT_X25519_KEYLEN])
{
    EVP_PKEY_CTX * key_ctx;
    size_t pub_key_datalen = 0;
    size_t secret_len = 0;

    if (nc->libctx != NULL)
    {
        return -1;
    }
    nc->libctx = OSSL_LIB_CTX_new();
    if (nc->libctx == NULL)
    {
        return -2;
    }

    nc->local.priv_key =
        EVP_PKEY_new_raw_private_key_ex(nc->libctx, "X25519", nc->propq, local_priv_key, NCRYPT_X25519_KEYLEN);
    if (nc->local.priv_key == NULL)
    {
        return -3;
    }

    if (EVP_PKEY_get_octet_string_param(nc->local.priv_key,
                                        OSSL_PKEY_PARAM_PUB_KEY,
                                        nc->local.pub_key,
                                        sizeof(nc->local.pub_key),
                                        &pub_key_datalen) == 0)
    {
        return -4;
    }
    if (pub_key_datalen != NCRYPT_X25519_KEYLEN)
    {
        return -5;
    }

    nc->remote.pub_key =
        EVP_PKEY_new_raw_public_key_ex(nc->libctx, "X25519", nc->propq, remote_pub_key, NCRYPT_X25519_KEYLEN);
    if (nc->remote.pub_key == NULL)
    {
        return -6;
    }

    key_ctx = EVP_PKEY_CTX_new_from_pkey(nc->libctx, nc->local.priv_key, nc->propq);
    if (key_ctx == NULL)
    {
        return -7;
    }

    if (EVP_PKEY_derive_init(key_ctx) == 0)
    {
        EVP_PKEY_CTX_free(key_ctx);
        return -8;
    }

    if (EVP_PKEY_derive_set_peer(key_ctx, nc->remote.pub_key) == 0)
    {
        EVP_PKEY_CTX_free(key_ctx);
        return -9;
    }

    if (EVP_PKEY_derive(key_ctx, NULL, &secret_len) == 0)
    {
        EVP_PKEY_CTX_free(key_ctx);
        return -10;
    }
    if (secret_len != NCRYPT_X25519_KEYLEN)
    {
        EVP_PKEY_CTX_free(key_ctx);
        return -11;
    }

    nc->shared_secret = OPENSSL_malloc(secret_len);
    if (nc->shared_secret == NULL)
    {
        EVP_PKEY_CTX_free(key_ctx);
        return -12;
    }
    if (EVP_PKEY_derive(key_ctx, nc->shared_secret, &secret_len) == 0)
    {
        EVP_PKEY_CTX_free(key_ctx);
        OPENSSL_clear_free(nc->shared_secret, secret_len);
        nc->shared_secret = NULL;
        return -13;
    }

    nc->iv_mismatches = 0;

    OPENSSL_cleanse(local_priv_key, NCRYPT_X25519_KEYLEN);
    OPENSSL_cleanse(remote_pub_key, NCRYPT_X25519_KEYLEN);

    EVP_PKEY_CTX_free(key_ctx);
    return 0;
}

int ncrypt_init_encrypt(struct ncrypt * const nc)
{
    if (nc->aesctx == NULL)
    {
        nc->aesctx = EVP_CIPHER_CTX_new();
        if (nc->aesctx == NULL)
        {
            return -1;
        }

        if (EVP_EncryptInit_ex(nc->aesctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 0)
        {
            return -2;
        }

        if (EVP_CIPHER_CTX_ctrl(nc->aesctx, EVP_CTRL_GCM_SET_IVLEN, NCRYPT_AES_IVLEN, NULL) == 0)
        {
            return -3;
        }
    }

    if (init_iv(nc) != 0)
    {
        return -4;
    }

    if (EVP_EncryptInit_ex(nc->aesctx, NULL, NULL, nc->shared_secret, nc->iv) == 0)
    {
        return -5;
    }

    return 0;
}

int ncrypt_init_decrypt(struct ncrypt * const nc)
{
    if (nc->aesctx == NULL)
    {
        nc->aesctx = EVP_CIPHER_CTX_new();
        if (nc->aesctx == NULL)
        {
            return -1;
        }

        if (EVP_DecryptInit_ex(nc->aesctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 0)
        {
            return -2;
        }

        if (EVP_CIPHER_CTX_ctrl(nc->aesctx, EVP_CTRL_GCM_SET_IVLEN, NCRYPT_AES_IVLEN, NULL) == 0)
        {
            return -3;
        }
    }

    if (EVP_DecryptInit_ex(nc->aesctx, NULL, NULL, nc->shared_secret, nc->iv) == 0)
    {
        return -4;
    }

    return 0;
}

void ncrypt_free(struct ncrypt * const nc)
{
    if (nc->aesctx != NULL)
    {
        EVP_CIPHER_CTX_free(nc->aesctx);
        nc->aesctx = NULL;
    }

    if (nc->shared_secret != NULL)
    {
        OPENSSL_clear_free(nc->shared_secret, NCRYPT_X25519_KEYLEN);
        nc->shared_secret = NULL;
    }

    if (nc->local.priv_key != NULL)
    {
        EVP_PKEY_free(nc->local.priv_key);
        nc->local.priv_key = NULL;
    }

    if (nc->remote.pub_key != NULL)
    {
        EVP_PKEY_free(nc->remote.pub_key);
        nc->remote.pub_key = NULL;
    }

    if (nc->libctx != NULL)
    {
        OSSL_LIB_CTX_free(nc->libctx);
        nc->libctx = NULL;
    }
}

static int encrypt(struct ncrypt * const nc,
                   unsigned char const * const plaintext,
                   size_t used,
                   unsigned char encrypted[NCRYPT_BUFFER_SIZE],
                   unsigned char tag[NCRYPT_TAG_SIZE])
{
    int encrypted_used;
    int remaining;

    if (EVP_EncryptInit_ex(nc->aesctx, NULL, NULL, NULL, nc->iv) == 0)
    {
        return -2;
    }

    if (EVP_EncryptUpdate(nc->aesctx, encrypted, &encrypted_used, plaintext, used) == 0)
    {
        return -3;
    }

    if (EVP_EncryptFinal_ex(nc->aesctx, encrypted + encrypted_used, &remaining) == 0)
    {
        return -4;
    }

    if (EVP_CIPHER_CTX_ctrl(nc->aesctx, EVP_CTRL_GCM_GET_TAG, NCRYPT_TAG_SIZE, tag) == 0)
    {
        return -5;
    }

    return encrypted_used + remaining;
}

int ncrypt_encrypt(struct ncrypt * const nc,
                   unsigned char const * const plaintext,
                   size_t used,
                   unsigned char encrypted[NCRYPT_BUFFER_SIZE],
                   unsigned char tag[NCRYPT_TAG_SIZE])
{
    if (used > NCRYPT_BUFFER_SIZE)
    {
        return -1;
    }

    next_iv(nc);

    return encrypt(nc, plaintext, used, encrypted, tag);
}

int decrypt(struct ncrypt * const nc,
            unsigned char const * const encrypted,
            size_t used,
            unsigned char tag[NCRYPT_TAG_SIZE],
            unsigned char plaintext[NCRYPT_BUFFER_SIZE])
{
    int decrypted_used;
    int remaining;

    if (EVP_DecryptInit_ex(nc->aesctx, NULL, NULL, NULL, nc->iv) == 0)
    {
        return -2;
    }

    if (EVP_DecryptUpdate(nc->aesctx, plaintext, &decrypted_used, encrypted, used) == 0)
    {
        return -3;
    }

    if (EVP_CIPHER_CTX_ctrl(nc->aesctx, EVP_CTRL_GCM_SET_TAG, NCRYPT_TAG_SIZE, tag) == 0)
    {
        return -4;
    }

    if (EVP_DecryptFinal_ex(nc->aesctx, plaintext + decrypted_used, &remaining) == 0)
    {
        return -5;
    }

    return decrypted_used + remaining;
}

int ncrypt_decrypt(struct ncrypt * const nc,
                   unsigned char const * const encrypted,
                   size_t used,
                   unsigned char tag[NCRYPT_TAG_SIZE],
                   unsigned char plaintext[NCRYPT_BUFFER_SIZE])
{
    if (used > NCRYPT_BUFFER_SIZE)
    {
        return -1;
    }

    next_iv(nc);

    return decrypt(nc, encrypted, used, tag, plaintext);
}

int ncrypt_encrypt_send(struct ncrypt * const nc, int fd, struct ncrypt_buffer * const buf)
{
    int encrypted_used = encrypt(nc, buf->plaintext.data, buf->data_used, buf->encrypted.data, buf->encrypted.tag);
    if (encrypted_used < 0)
    {
        return -1;
    }

    memcpy(buf->encrypted.iv, nc->iv, NCRYPT_AES_IVLEN);
    ssize_t bytes_written = write(fd, buf->encrypted.raw, NCRYPT_AES_IVLEN + NCRYPT_TAG_SIZE + encrypted_used);
    next_iv(nc);

    if (bytes_written < 0)
    {
        return -2;
    }
    if (bytes_written != NCRYPT_AES_IVLEN + NCRYPT_TAG_SIZE + encrypted_used)
    {
        nc->partial_writes++;
        buf->write_offset += bytes_written;
    }

    return (int)bytes_written;
}

int ncrypt_decrypt_recv(struct ncrypt * const nc, int fd, struct ncrypt_buffer * const buf)
{
    ssize_t bytes_read = read(fd, buf->encrypted.raw, sizeof(buf->encrypted.raw));

    if (bytes_read < 0)
    {
        return -1;
    }
    if (bytes_read < NCRYPT_AES_IVLEN + NCRYPT_TAG_SIZE + 1)
    {
        return -2;
    }

    if (memcmp(nc->iv, buf->encrypted.iv, NCRYPT_AES_IVLEN) != 0)
    {
        nc->iv_mismatches++;
    }
    memcpy(nc->iv, buf->encrypted.iv, NCRYPT_AES_IVLEN);
    int decrypted_used = decrypt(nc,
                                 buf->encrypted.data,
                                 bytes_read - NCRYPT_AES_IVLEN - NCRYPT_TAG_SIZE,
                                 buf->encrypted.tag,
                                 buf->plaintext.data);
    next_iv(nc);

    if (decrypted_used < 0)
    {
        return -3;
    }

    buf->data_used = decrypted_used;

    return (int)bytes_read;
}
