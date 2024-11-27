#include <stdio.h>
#include <unistd.h>

#include "utils.h"

static void print_usage(char const * const arg0)
{
    static char const usage[] =
        "Usage: %s "
        "[-L listen-address] [-k private-key-file] [-K public-key-file]\n"
        "\t  \t"
        "[-h]\n\n"
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

    while ((opt = getopt(argc, argv, "hk:K:s:")) != -1)
    {
        switch (opt)
        {
            case 'h':
                print_usage(argv[0]);
                return 1;
            case 'k':
                break;
            case 'K':
                break;
            case 's':
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind < argc)
    {
        if (optind > 0) {
            logger_early(1, "Unexpected argument(s) after %s\n\n", argv[optind]);
        } else {
            logger_early(1, "%s\n\n", "Unexpected argument(s)");
        }
        print_usage(argv[0]);

        return 1;
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
    }

    return 0;
}
