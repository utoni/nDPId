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
} options = {.listen_address = CMDARG_STR("127.0.0.1:7443"),
             .local_private_key_file = CMDARG_STR(NULL),
             .remote_public_key_file = CMDARG_STR(NULL)};

struct confopt config_map[] = {CONFOPT(NULL, &options.listen_address),
                               CONFOPT(NULL, &options.local_private_key_file),
                               CONFOPT(NULL, &options.remote_public_key_file)};

static void print_usage(char const * const arg0)
{
    static char const usage[] =
        "Usage: %s "
        "\t \t"
        "[-l] [-L listen-address] [-k private-key-file] [-K public-key-file]\n"
        "\t  \t"
        "[-h]\n\n"
        "\t-l\tLog all messages to stderr.\n"
        "\t-L\tThe address on which this example will listen for incoming\n"
        "\t  \t(encrypted) UDP packets sent by nDPId\n"
        "\t-k\tThe path to the local private X25519 key file (PEM format)\n"
        "\t-K\tThe path to the remote public X25519 key file (PEM format)\n"
        "\t-h\tthis\n";

    fprintf(stderr, usage, arg0);
}

static int parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "lL:k:K:h")) != -1)
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

    struct ncrypt_buffer read_buf = {};
    for (;;)
    {
        int bytes_read = ncrypt_decrypt_recv(nc, sock_fd, &read_buf);
        if (bytes_read <= 0)
        {
            logger(1, "Crypto error: %d", bytes_read);
            break;
        }

        printf("read %d bytes: %.*s", bytes_read, (int)read_buf.data_used, read_buf.plaintext.data);
    }

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
        ret = ncrypt_init_decrypt(&nc);
        if (ret != 0)
        {
            logger_early(1, "Crypto decrypt initialization failed: %d", ret);
            return 1;
        }
    }

    return udp_server(&nc);
}
