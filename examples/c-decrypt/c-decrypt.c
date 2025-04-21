#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "config.h"
#include "ncrypt.h"
#include "nDPIsrvd.h"
#include "utils.h"

struct
{
    struct nDPIsrvd_address parsed_listen_address;
    struct cmdarg listen_address;
    struct cmdarg local_private_key_file;
    struct cmdarg remote_public_key_file;
    struct cmdarg parse_json_lines;
    struct cmdarg quiet;
} options = {.listen_address = CMDARG_STR("127.0.0.1:7443"),
             .local_private_key_file = CMDARG_STR(NULL),
             .remote_public_key_file = CMDARG_STR(NULL),
             .parse_json_lines = CMDARG_BOOL(0),
             .quiet = CMDARG_BOOL(0)};

struct confopt config_map[] = {CONFOPT(NULL, &options.listen_address),
                               CONFOPT(NULL, &options.local_private_key_file),
                               CONFOPT(NULL, &options.remote_public_key_file)};

static void print_usage(char const * const arg0)
{
    static char const usage[] =
        "Usage: %s "
        "[-l] [-L listen-address] [-k private-key-file] [-K public-key-file]\n"
        "\t  \t"
        "[-h]\n\n"
        "\t-l\tLog all messages to stderr.\n"
        "\t-L\tThe address on which this example will listen for incoming\n"
        "\t  \t(encrypted) UDP packets sent by nDPId\n"
        "\t-k\tThe path to the local private X25519 key file (PEM format)\n"
        "\t-K\tThe path to the remote public X25519 key file (PEM format)\n"
        "\t-p\tParse decrypted JSON lines\n"
        "\t-q\tQuiet mode, print errors only\n"
        "\t-h\tthis\n";

    fprintf(stderr, usage, arg0);
}

static int parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "lL:k:K:pqh")) != -1)
    {
        switch (opt)
        {
            case 'l':
                enable_console_logger();
                break;
            case 'L':
                set_cmdarg_string(&options.listen_address, optarg);
                break;
            case 'k':
                set_cmdarg_string(&options.local_private_key_file, optarg);
                break;
            case 'K':
                set_cmdarg_string(&options.remote_public_key_file, optarg);
                break;
            case 'p':
                set_cmdarg_boolean(&options.parse_json_lines, 1);
                break;
            case 'q':
                set_cmdarg_boolean(&options.quiet, 1);
                break;

            case 'h':
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind < argc)
    {
        if (optind > 0)
        {
            logger_early(1, "Unexpected argument(s) after %s\n\n", argv[optind]);
        }
        else
        {
            logger_early(1, "%s\n\n", "Unexpected argument(s)");
        }
        print_usage(argv[0]);

        return 1;
    }

    return 0;
}

int udp_server(struct ncrypt * const nc)
{
    int sock_fd = socket(options.parsed_listen_address.raw.sa_family, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        return 1;
    }

    if (bind(sock_fd, &options.parsed_listen_address.raw, options.parsed_listen_address.size) != 0)
    {
        return 1;
    }

    size_t msgs_recvd = 0;
    char read_buffer[NCRYPT_BUFFER_SIZE];
    struct nDPIsrvd_json_buffer json_buf;
    struct nDPIsrvd_jsmn json_ctx;
    for (;;)
    {
        nDPIsrvd_json_buffer_reset(&json_buf);
        size_t read_buffer_size = sizeof(read_buffer);
        int ret = ncrypt_dgram_recv(nc, sock_fd, read_buffer, read_buffer_size);
        if (ret < 0)
        {
            logger(1, "Crypto error: %d", ret);
            continue;
        }
        msgs_recvd++;

        if (GET_CMDARG_BOOL(options.quiet) == 0)
        {
            printf("received: %.*s\n", (int)read_buffer_size, read_buffer);
            if ((msgs_recvd % 25) == 0)
            {
                printf("*** Messages received: %zu ***\n", msgs_recvd);
                struct peer * current_peer;
                struct peer * ctmp;
                HASH_ITER(hh, nc->peers, current_peer, ctmp)
                {
                    printf(
                        "*** Peer: %8X | Key Rotations: %5zu | Cryptions: %5zu | Crypto Errors: %2zu | IV Mismatches: "
                        "%2zu | Send Errors: "
                        "%2zu | "
                        "Partial Writes: %2zu ***\n",
                        current_peer->hash_key,
                        current_peer->key_rotations,
                        current_peer->cryptions,
                        current_peer->crypto_errors,
                        current_peer->iv_mismatches,
                        current_peer->send_errors,
                        current_peer->partial_writes);
                }
            }
        }

        if (GET_CMDARG_BOOL(options.parse_json_lines) != 0)
        {
            json_buf.buf.ptr.raw = (uint8_t *)read_buffer;
            json_buf.buf.used = json_buf.buf.max = read_buffer_size;

            enum nDPIsrvd_parse_return ret = nDPIsrvd_parse_line(&json_buf, &json_ctx);
            if (ret != PARSE_OK)
            {
                logger(1, "JSON parsing failed with: %d", ret);
                continue;
            }
            json_ctx.tokens_found = 0;
        }
    }

    ncrypt_free(nc);

    return 0;
}

int main(int argc, char ** argv)
{
    if (argc == 0 || argv == NULL || stdout == NULL || stderr == NULL)
    {
        return 1;
    }

    init_logging("nDPId-decrypt");

    if (parse_options(argc, argv) != 0)
    {
        return 1;
    }

    set_config_defaults(&config_map[0], nDPIsrvd_ARRAY_LENGTH(config_map));

    if (nDPIsrvd_setup_address(&options.parsed_listen_address, GET_CMDARG_STR(options.listen_address)) != 0)
    {
        logger_early(1, "Collector socket invalid listen address: `%s'", GET_CMDARG_STR(options.listen_address));
        return 1;
    }

    if (IS_CMDARG_SET(options.local_private_key_file) == 0 || IS_CMDARG_SET(options.remote_public_key_file) == 0)
    {
        logger_early(1, "%s", "Arguments `-k' and `-K' are mandatory!");
        return 1;
    }

    struct ncrypt nc = {};
    {
        int ret;
        unsigned char priv_key[NCRYPT_X25519_KEYLEN];
        unsigned char pub_key[NCRYPT_X25519_KEYLEN];
        ret = ncrypt_load_privkey(GET_CMDARG_STR(options.local_private_key_file), priv_key);
        if (ret != 0)
        {
            logger_early(1,
                         "Invalid PEM private key file `%s': %d (%s)",
                         GET_CMDARG_STR(options.local_private_key_file),
                         ret,
                         strerror(errno));
            return 1;
        }
        ret = ncrypt_load_pubkey(GET_CMDARG_STR(options.remote_public_key_file), pub_key);
        if (ret != 0)
        {
            logger_early(1,
                         "Invalid PEM public key file `%s': %d (%s)",
                         GET_CMDARG_STR(options.remote_public_key_file),
                         ret,
                         strerror(errno));
            return 1;
        }
        ret = ncrypt_init(&nc, priv_key, pub_key);
        if (ret != 0)
        {
            logger_early(1, "Crypto initialization failed: %d", ret);
            return 1;
        }
    }

    return udp_server(&nc);
}
