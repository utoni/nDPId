#ifndef NCRYPT_H
#define NCRYPT_H 1

#include <stdlib.h>

#include "config.h"
#include "nDPIsrvd.h"

#define NCRYPT_X25519_KEYLEN 32
#define NCRYPT_AES_IVLEN 12
#define NCRYPT_TAG_SIZE 16
#define NCRYPT_BUFFER_SIZE NETWORK_BUFFER_MAX_SIZE
#define NCRYPT_PACKET_OVERHEAD (NCRYPT_AES_IVLEN + NCRYPT_TAG_SIZE)
#define NCRYPT_PACKET_BUFFER_SIZE (NCRYPT_PACKET_OVERHEAD + NCRYPT_BUFFER_SIZE)
#define NCRYPT_PACKET_MIN_SIZE (NCRYPT_PACKET_OVERHEAD + NETWORK_BUFFER_LENGTH_DIGITS + 1)

struct aes
{
    void * ctx;
};

struct peer
{
    nDPIsrvd_hashkey hash_key;
    struct nDPIsrvd_address address;
    unsigned char iv[NCRYPT_AES_IVLEN];
    size_t crypto_errors;
    size_t iv_mismatches;
    size_t send_errors;
    size_t recv_errors;
    size_t partial_writes;
    struct aes aes;
    UT_hash_handle hh;
};

struct ncrypt
{
    void * libctx;
    const char * propq;
    unsigned char shared_secret[NCRYPT_X25519_KEYLEN];
    struct peer * peers;
};

int ncrypt_keygen(unsigned char priv_key[NCRYPT_X25519_KEYLEN], unsigned char pub_key[NCRYPT_X25519_KEYLEN]);

int ncrypt_load_privkey(char const * const private_key_file, unsigned char priv_key[NCRYPT_X25519_KEYLEN]);

int ncrypt_load_pubkey(char const * const public_key_file, unsigned char pub_key[NCRYPT_X25519_KEYLEN]);

int ncrypt_init(struct ncrypt * const nc,
                unsigned char local_priv_key[NCRYPT_X25519_KEYLEN],
                unsigned char remote_pub_key[NCRYPT_X25519_KEYLEN]);

int ncrypt_init_encrypt(struct ncrypt * const nc, struct aes * const aes);

int ncrypt_init_encrypt2(struct ncrypt * const nc, struct nDPIsrvd_address * const peer_address);

int ncrypt_init_decrypt(struct ncrypt * const nc, struct aes * const aes);

int ncrypt_init_decrypt2(struct ncrypt * const nc, struct nDPIsrvd_address * const peer_address);

void ncrypt_free_aes(struct aes * const aes);

void ncrypt_free(struct ncrypt * const nc);

int ncrypt_add_peer(struct ncrypt * const nc, struct nDPIsrvd_address const * const peer_address);

struct peer * ncrypt_get_peer(struct ncrypt * const nc, struct nDPIsrvd_address const * const peer_address);

int ncrypt_encrypt(struct aes * const aes,
                   char const * const plaintext,
                   size_t plaintext_size,
                   unsigned char const iv[NCRYPT_AES_IVLEN],
                   unsigned char encrypted[NCRYPT_BUFFER_SIZE],
                   unsigned char tag[NCRYPT_TAG_SIZE]);

int ncrypt_decrypt(struct aes * const aes,
                   unsigned char const * const encrypted,
                   size_t encrypted_size,
                   unsigned char const iv[NCRYPT_AES_IVLEN],
                   unsigned char tag[NCRYPT_TAG_SIZE],
                   char plaintext[NCRYPT_BUFFER_SIZE]);

int ncrypt_dgram_send(struct ncrypt * const nc, int fd, char const * const plaintext, size_t plaintext_size);

int ncrypt_dgram_recv(struct ncrypt * const nc, int fd, char * const plaintext, size_t plaintext_size);

#endif
