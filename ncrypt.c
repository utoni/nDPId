#include "ncrypt.h"

#include <endian.h>
#include <openssl/conf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OPENSSL_DUMP(ptr, siz)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        fprintf(stderr, "Raw output (%s, %zu):\n", #ptr, siz);                                                         \
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

union packet
{
    unsigned char raw[NCRYPT_PACKET_BUFFER_SIZE];
    struct
    {
        unsigned char iv[NCRYPT_AES_IVLEN];
        unsigned char tag[NCRYPT_TAG_SIZE];
        unsigned char data[NCRYPT_BUFFER_SIZE];
    } __attribute__((__packed__));
} __attribute__((__packed__));

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(((union iv *)0)->buffer) == sizeof(((union iv *)0)->numeric),
               "IV buffer must be of the same size as the numerics");
#endif

static inline nDPIsrvd_hashkey peer_build_hashkey(struct nDPIsrvd_address const * const peer_address)
{
    uint32_t hash = nDPIsrvd_HASHKEY_SEED;

    socklen_t slen = peer_address->size;
    while (slen-- > 0)
    {
        hash = ((hash << 5) + hash) + ((uint8_t *)&peer_address->raw)[slen];
    }

    return hash;
}

int ncrypt_add_peer(struct ncrypt * const nc, struct nDPIsrvd_address const * const peer_address)
{
    nDPIsrvd_hashkey peer_key = peer_build_hashkey(peer_address);
    if (peer_key == nDPIsrvd_HASHKEY_SEED)
    {
        return -1;
    }

    struct peer * peer = (struct peer *)calloc(1, sizeof(*peer));
    if (peer == NULL)
    {
        return -2;
    }

    peer->hash_key = peer_key;
    peer->address = *peer_address;
    HASH_ADD_INT(nc->peers, hash_key, peer);
    return 0;
}

struct peer * ncrypt_get_peer(struct ncrypt * const nc, struct nDPIsrvd_address const * const peer_address)
{
    nDPIsrvd_hashkey peer_key = peer_build_hashkey(peer_address);
    if (peer_key == nDPIsrvd_HASHKEY_SEED)
    {
        return NULL;
    }

    struct peer * peer;
    HASH_FIND_INT(nc->peers, &peer_key, peer);
    if (peer == NULL)
    {
        return NULL;
    }

    return peer;
}

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

static int init_iv(struct peer * const peer)
{
    FILE * rnd_fp;

    rnd_fp = fopen("/dev/random", "r+b");

    if (rnd_fp == NULL)
    {
        return -1;
    }

    if (fread(&peer->iv[0], sizeof(peer->iv[0]), sizeof(peer->iv) / sizeof(peer->iv[0]), rnd_fp) != NCRYPT_AES_IVLEN)
    {
        fclose(rnd_fp);
        return -2;
    }

    fclose(rnd_fp);

    return 0;
}

static void next_iv(struct peer * const peer)
{
    union iv * const iv = (union iv *)&peer->iv[0];

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
    int rv = 0;
    EVP_PKEY_CTX * key_ctx = NULL;
    size_t pub_key_datalen = 0;
    size_t secret_len = 0;
    struct
    {
        EVP_PKEY * priv_key;
        unsigned char pub_key[NCRYPT_X25519_KEYLEN];
    } local = {.priv_key = NULL, .pub_key = {}};
    struct
    {
        EVP_PKEY * pub_key;
    } remote = {.pub_key = NULL};

    if (nc->libctx != NULL)
    {
        return -1;
    }
    nc->libctx = OSSL_LIB_CTX_new();
    if (nc->libctx == NULL)
    {
        return -2;
    }

    local.priv_key =
        EVP_PKEY_new_raw_private_key_ex(nc->libctx, "X25519", nc->propq, local_priv_key, NCRYPT_X25519_KEYLEN);
    if (local.priv_key == NULL)
    {
        return -3;
    }

    if (EVP_PKEY_get_octet_string_param(
            local.priv_key, OSSL_PKEY_PARAM_PUB_KEY, local.pub_key, sizeof(local.pub_key), &pub_key_datalen) == 0)
    {
        rv = -4;
        goto error;
    }
    if (pub_key_datalen != NCRYPT_X25519_KEYLEN)
    {
        rv = -5;
        goto error;
    }

    remote.pub_key =
        EVP_PKEY_new_raw_public_key_ex(nc->libctx, "X25519", nc->propq, remote_pub_key, NCRYPT_X25519_KEYLEN);
    if (remote.pub_key == NULL)
    {
        rv = -6;
        goto error;
    }

    key_ctx = EVP_PKEY_CTX_new_from_pkey(nc->libctx, local.priv_key, nc->propq);
    if (key_ctx == NULL)
    {
        rv = -7;
        goto error;
    }

    if (EVP_PKEY_derive_init(key_ctx) == 0)
    {
        rv = -8;
        goto error;
    }

    if (EVP_PKEY_derive_set_peer(key_ctx, remote.pub_key) == 0)
    {
        rv = -9;
        goto error;
    }

    if (EVP_PKEY_derive(key_ctx, NULL, &secret_len) == 0)
    {
        rv = -10;
        goto error;
    }
    if (secret_len != NCRYPT_X25519_KEYLEN)
    {
        rv = -11;
        goto error;
    }

    if (EVP_PKEY_derive(key_ctx, nc->shared_secret, &secret_len) == 0)
    {
        rv = -12;
        OPENSSL_cleanse(nc->shared_secret, NCRYPT_X25519_KEYLEN);
        goto error;
    }

    OPENSSL_cleanse(local_priv_key, NCRYPT_X25519_KEYLEN);
    OPENSSL_cleanse(remote_pub_key, NCRYPT_X25519_KEYLEN);

error:
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(local.priv_key);
    EVP_PKEY_free(remote.pub_key);

    return rv;
}

int ncrypt_init_encrypt(struct ncrypt * const nc, struct aes * const aes)
{
    aes->ctx = EVP_CIPHER_CTX_new();
    if (aes->ctx == NULL)
    {
        return -3;
    }

    if (EVP_EncryptInit_ex(aes->ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 0)
    {
        return -4;
    }

    if (EVP_CIPHER_CTX_ctrl(aes->ctx, EVP_CTRL_GCM_SET_IVLEN, NCRYPT_AES_IVLEN, NULL) == 0)
    {
        return -5;
    }

    if (EVP_EncryptInit_ex(aes->ctx, NULL, NULL, nc->shared_secret, NULL) == 0)
    {
        return -6;
    }

    return 0;
}

int ncrypt_init_encrypt2(struct ncrypt * const nc, struct nDPIsrvd_address * const peer_address)
{
    struct peer * const peer = ncrypt_get_peer(nc, peer_address);

    if (peer == NULL)
    {
        return -1;
    }

    if (init_iv(peer) != 0)
    {
        return -2;
    }

    return ncrypt_init_encrypt(nc, &peer->aes);
}

int ncrypt_init_decrypt(struct ncrypt * const nc, struct aes * const aes)
{
    aes->ctx = EVP_CIPHER_CTX_new();
    if (aes->ctx == NULL)
    {
        return -2;
    }

    if (EVP_DecryptInit_ex(aes->ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 0)
    {
        return -3;
    }

    if (EVP_CIPHER_CTX_ctrl(aes->ctx, EVP_CTRL_GCM_SET_IVLEN, NCRYPT_AES_IVLEN, NULL) == 0)
    {
        return -4;
    }

    if (EVP_DecryptInit_ex(aes->ctx, NULL, NULL, nc->shared_secret, NULL) == 0)
    {
        return -5;
    }

    return 0;
}

int ncrypt_init_decrypt2(struct ncrypt * const nc, struct nDPIsrvd_address * const peer_address)
{
    struct peer * const peer = ncrypt_get_peer(nc, peer_address);

    if (peer == NULL)
    {
        return -1;
    }

    return ncrypt_init_decrypt(nc, &peer->aes);
}

void ncrypt_free_aes(struct aes * const aes)
{
    EVP_CIPHER_CTX_free(aes->ctx);
    aes->ctx = NULL;
}

static void cleanup_peers(struct ncrypt * const nc)
{
    struct peer * current_peer;
    struct peer * ctmp;

    if (nc->peers == NULL)
    {
        return;
    }

    HASH_ITER(hh, nc->peers, current_peer, ctmp)
    {
        ncrypt_free_aes(&current_peer->aes);
        HASH_DEL(nc->peers, current_peer);
        free(current_peer);
    }
}

void ncrypt_free(struct ncrypt * const nc)
{
    OPENSSL_cleanse(nc->shared_secret, NCRYPT_X25519_KEYLEN);

    if (nc->libctx != NULL)
    {
        OSSL_LIB_CTX_free(nc->libctx);
        nc->libctx = NULL;
    }

    cleanup_peers(nc);
}

static int encrypt(struct aes * const aes,
                   char const * const plaintext,
                   size_t plaintext_size,
                   unsigned char const iv[NCRYPT_AES_IVLEN],
                   unsigned char encrypted[NCRYPT_BUFFER_SIZE],
                   unsigned char tag[NCRYPT_TAG_SIZE])
{
    int encrypted_used;
    int remaining;

    if (EVP_EncryptInit_ex(aes->ctx, NULL, NULL, NULL, iv) == 0)
    {
        return -2;
    }

    if (EVP_EncryptUpdate(aes->ctx, encrypted, &encrypted_used, (const unsigned char *)plaintext, plaintext_size) == 0)
    {
        return -3;
    }

    if (EVP_EncryptFinal_ex(aes->ctx, encrypted + encrypted_used, &remaining) == 0)
    {
        return -4;
    }

    if (EVP_CIPHER_CTX_ctrl(aes->ctx, EVP_CTRL_GCM_GET_TAG, NCRYPT_TAG_SIZE, tag) == 0)
    {
        return -5;
    }

    return encrypted_used + remaining;
}

int ncrypt_encrypt(struct aes * const aes,
                   char const * const plaintext,
                   size_t plaintext_size,
                   unsigned char const iv[NCRYPT_AES_IVLEN],
                   unsigned char encrypted[NCRYPT_BUFFER_SIZE],
                   unsigned char tag[NCRYPT_TAG_SIZE])
{
    if (plaintext_size > NCRYPT_BUFFER_SIZE)
    {
        return -1;
    }

    return encrypt(aes, plaintext, plaintext_size, iv, encrypted, tag);
}

static int decrypt(struct aes * const aes,
                   unsigned char const * const encrypted,
                   size_t encrypt_size,
                   unsigned char const iv[NCRYPT_AES_IVLEN],
                   unsigned char tag[NCRYPT_TAG_SIZE],
                   char plaintext[NCRYPT_BUFFER_SIZE])
{
    int decrypted_used;
    int remaining;

    if (EVP_DecryptInit_ex(aes->ctx, NULL, NULL, NULL, iv) == 0)
    {
        return -2;
    }

    if (EVP_DecryptUpdate(aes->ctx, (unsigned char *)plaintext, &decrypted_used, encrypted, encrypt_size) == 0)
    {
        return -3;
    }

    if (EVP_CIPHER_CTX_ctrl(aes->ctx, EVP_CTRL_GCM_SET_TAG, NCRYPT_TAG_SIZE, tag) == 0)
    {
        return -4;
    }

    if (EVP_DecryptFinal_ex(aes->ctx, (unsigned char *)plaintext + decrypted_used, &remaining) == 0)
    {
        return -5;
    }

    return decrypted_used + remaining;
}

int ncrypt_decrypt(struct aes * const aes,
                   unsigned char const * const encrypted,
                   size_t encrypt_size,
                   unsigned char const iv[NCRYPT_AES_IVLEN],
                   unsigned char tag[NCRYPT_TAG_SIZE],
                   char plaintext[NCRYPT_BUFFER_SIZE])
{
    if (encrypt_size > NCRYPT_BUFFER_SIZE)
    {
        return -1;
    }

    return decrypt(aes, encrypted, encrypt_size, iv, tag, plaintext);
}

int ncrypt_dgram_send(struct ncrypt * const nc, int fd, char const * const plaintext, size_t plaintext_size)
{
    if (plaintext_size > NCRYPT_BUFFER_SIZE)
    {
        return -1;
    }

    int retval = 0;
    struct peer * current_peer;
    struct peer * tmp_peer;
    union packet encrypted;
    HASH_ITER(hh, nc->peers, current_peer, tmp_peer)
    {
        int encrypted_used =
            encrypt(&current_peer->aes, plaintext, plaintext_size, current_peer->iv, encrypted.data, encrypted.tag);
        if (encrypted_used < 0 || encrypted_used > (int)NCRYPT_BUFFER_SIZE)
        {
            current_peer->crypto_errors++;
            retval++;
            continue;
        }
        current_peer->cryptions++;

        memcpy(encrypted.iv, current_peer->iv, NCRYPT_AES_IVLEN);
        ssize_t bytes_written = sendto(fd,
                                       encrypted.raw,
                                       NCRYPT_PACKET_OVERHEAD + encrypted_used,
                                       0,
                                       &current_peer->address.raw,
                                       current_peer->address.size);
        next_iv(current_peer);

        if (bytes_written < 0)
        {
            current_peer->send_errors++;
            retval++;
            continue;
        }
        if (bytes_written != NCRYPT_PACKET_OVERHEAD + encrypted_used)
        {
            current_peer->partial_writes++;
            retval++;
            continue;
        }
    }

    return retval;
}

int ncrypt_dgram_recv(struct ncrypt * const nc, int fd, char * const plaintext, size_t plaintext_size)
{
    if (plaintext_size > NCRYPT_BUFFER_SIZE)
    {
        return -1;
    }

    struct nDPIsrvd_address remote = {.size = sizeof(remote.raw)};
    union packet encrypted;
    ssize_t bytes_read = recvfrom(fd, encrypted.raw, sizeof(encrypted.raw), 0, &remote.raw, &remote.size);

    if (bytes_read < 0)
    {
        return -2;
    }
    if (bytes_read < NCRYPT_PACKET_MIN_SIZE)
    {
        return -3;
    }
    if (plaintext_size < (size_t)bytes_read - NCRYPT_PACKET_OVERHEAD)
    {
        return -4;
    }

    struct peer * peer = ncrypt_get_peer(nc, &remote);
    if (peer == NULL)
    {
        if (ncrypt_add_peer(nc, &remote) != 0)
        {
            return -5;
        }
        peer = ncrypt_get_peer(nc, &remote);
        ncrypt_init_decrypt(nc, &peer->aes);
    }

    if (memcmp(peer->iv, encrypted.iv, NCRYPT_AES_IVLEN) != 0)
    {
        peer->iv_mismatches++;
        memcpy(peer->iv, encrypted.iv, NCRYPT_AES_IVLEN);
    }
    int decrypted_used =
        decrypt(&peer->aes, encrypted.data, bytes_read - NCRYPT_PACKET_OVERHEAD, peer->iv, encrypted.tag, plaintext);
    next_iv(peer);

    if (decrypted_used < 0)
    {
        return -6;
    }
    peer->cryptions++;

    return 0;
}
