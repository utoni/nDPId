#ifndef NCRYPT_H
#define NCRYPT_H 1

#include <stdlib.h>

#include "config.h"

#define NCRYPT_X25519_KEYLEN 32
#define NCRYPT_AES_IVLEN 12
#define NCRYPT_TAG_SIZE 16
#define NCRYPT_BUFFER_SIZE NETWORK_BUFFER_MAX_SIZE
#define NCRYPT_PACKET_BUFFER_SIZE NCRYPT_AES_IVLEN + NCRYPT_TAG_SIZE + NCRYPT_BUFFER_SIZE

struct ncrypt
{
    void * libctx;
    void * aesctx;
    unsigned char * shared_secret;
    const char * propq;
    struct
    {
        void * priv_key;
        unsigned char pub_key[NCRYPT_X25519_KEYLEN];
    } local;
    struct
    {
        void * pub_key;
    } remote;
    unsigned char iv[NCRYPT_AES_IVLEN];
    size_t iv_mismatches;
    size_t partial_writes;
};

struct ncrypt_buffer
{
    struct
    {
        unsigned char data[NCRYPT_BUFFER_SIZE];
    } plaintext;

    struct
    {
        union
        {
            unsigned char raw[NCRYPT_PACKET_BUFFER_SIZE];
            struct
            {
                unsigned char iv[NCRYPT_AES_IVLEN];
                unsigned char tag[NCRYPT_TAG_SIZE];
                unsigned char data[NCRYPT_BUFFER_SIZE];
            } __attribute__((__packed__));
        };
    } encrypted;

    size_t data_used;    // size of plaintext and encrypted is equal for AES-GCM
    size_t write_offset; // partial write; offset to next bytes of data
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(((struct ncrypt_buffer *)0)->encrypted) == sizeof(((struct ncrypt_buffer *)0)->encrypted.raw),
               "Raw buffer and iv/tag/data sizes differ");
#endif

int ncrypt_keygen(unsigned char priv_key[NCRYPT_X25519_KEYLEN], unsigned char pub_key[NCRYPT_X25519_KEYLEN]);

int ncrypt_load_privkey(char const * const private_key_file, unsigned char priv_key[NCRYPT_X25519_KEYLEN]);

int ncrypt_load_pubkey(char const * const public_key_file, unsigned char pub_key[NCRYPT_X25519_KEYLEN]);

int ncrypt_init(struct ncrypt * const nc,
                unsigned char local_priv_key[NCRYPT_X25519_KEYLEN],
                unsigned char remote_pub_key[NCRYPT_X25519_KEYLEN]);

int ncrypt_init_encrypt(struct ncrypt * const nc);

int ncrypt_init_decrypt(struct ncrypt * const nc);

void ncrypt_free(struct ncrypt * const nc);

int ncrypt_encrypt(struct ncrypt * const nc,
                   unsigned char const * const plaintext,
                   size_t used,
                   unsigned char encrypted[NCRYPT_BUFFER_SIZE],
                   unsigned char tag[NCRYPT_TAG_SIZE]);

int ncrypt_decrypt(struct ncrypt * const nc,
                   unsigned char const * const encrypted,
                   size_t used,
                   unsigned char tag[NCRYPT_TAG_SIZE],
                   unsigned char plaintext[NCRYPT_BUFFER_SIZE]);

int ncrypt_encrypt_send(struct ncrypt * const nc, int fd, struct ncrypt_buffer * const buf);

int ncrypt_decrypt_recv(struct ncrypt * const nc, int fd, struct ncrypt_buffer * const buf);

#endif
