/*
 * Make sure that filter table with forward chain does exist:
 *   nft add table inet filter
 *   nft add chain inet filter forward '{ type filter hook forward priority 0; }'
 * Flush it with:
 *   nft flush chain inet filter forward
 * Delete it with (chain + table):
 *   nft delete chain inet filter forward
 *   nft delete table inet filter
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <nftables/libnftables.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nDPIsrvd.h"
#include "utils.h"

#define NF_DEFAULT_TABLE "filter"

#define IP_BUFSIZ (sizeof(struct in6_addr))

static struct {
    int dry_run;
    int verbose;
    int ignore_source;
    int no_conntrack;
    char * distributor_host;
    char * user;
    char * group;
    char * table;
    char * protocol;
    char * category;
    char * breed;
    int encrypted;
    int plaintext;
} options = {
    .dry_run = 0,
    .verbose = 0,
    .ignore_source = 0,
    .no_conntrack = 0,
    .distributor_host = NULL,
    .user = NULL,
    .group = NULL,
    .table = NULL,
    .protocol = NULL,
    .category = NULL,
    .breed = NULL,
    .encrypted = 0,
    .plaintext = 0
};

static struct nDPIsrvd_socket * ndpisrvd_socket = NULL;
static struct nfct_handle * nf_deleter = NULL;
static struct nft_ctx * nf_blocker = NULL;
static int main_thread_shutdown = 0;

typedef uint8_t IP_BUF[IP_BUFSIZ];

struct ip
{
    int family;
    union {
        uint32_t addr4;
        IP_BUF addr6;
    };
    char addr_str[INET6_ADDRSTRLEN];
};

struct filter
{
    int have_src;
    int have_dst;
    int have_sport;
    int have_dport;
    struct ip src;
    struct ip dst;
    int layer4_proto;
    uint16_t sport;
    uint16_t dport;
};

#ifdef ENABLE_MEMORY_PROFILING
void nDPIsrvd_memprof_log_alloc(size_t alloc_size)
{
    (void)alloc_size;
}

void nDPIsrvd_memprof_log_free(size_t free_size)
{
    (void)free_size;
}

void nDPIsrvd_memprof_log(char const * const format, ...)
{
    va_list ap;

    va_start(ap, format);
    logger(0, "%s", "nDPIsrvd MemoryProfiler: ");
    vlogger(0, format, ap);
    va_end(ap);
}
#endif

static void print_usage(const char * arg0)
{
    static char const usage[] =
        "Usage: %s [Options]\n"
        "\nOptions:\n"
        "\t-s, --server       distributor host\n"
        "\t-u, --user         change user after connect\n"
        "\t-g, --group        change group after connect\n"
        "\t-t, --table        Netfilter table to use\n"
        "\t-i, --ignore       Ignore source address, block destination only\n"
        "\t--no-conntrack     Disable Netfilter Conntrack entry deletion\n"
        "\t--flow-protocol    Filter only a detected flow protocol\n"
        "\t                   Example: tls.lagofast\n"
        "\t--flow-category    Filter only a detected flow category\n"
        "\t                   Example: vpn\n"
        "\t--flow-breed       Filter only a detected flow breed\n"
        "\t                   Example: dangerous\n"
        "\t--flow-encrypted   Filter only encrypted traffic\n"
        "\t--flow-plaintext   Filter only plaintext traffic\n"
        "\t-n, --dry-run      only show what would have been done\n"
        "\t-c, --console      log to console instead of syslog\n"
        "\t-v, --verbose      log even more debug messages\n"
        "\t-h, --help         this\n\n";

    fprintf(stderr, usage, arg0);
}

static int parse_options(int argc, char ** argv)
{
    static const struct option opts[] = {{"server", required_argument, 0, 's'},
                                         {"user", required_argument, 0, 'u'},
                                         {"group", required_argument, 0, 'g'},
                                         {"table", required_argument, 0, 't'},
                                         {"ignore", no_argument, 0, 'i'},
                                         {"no-conntrack", no_argument, 0, 0},
                                         {"flow-protocol", required_argument, 0, 0},
                                         {"flow-category", required_argument, 0, 0},
                                         {"flow-breed", required_argument, 0, 0},
                                         {"flow-encrypted", no_argument, 0, 0},
                                         {"flow-plaintext", no_argument, 0, 0},
                                         {"dry-run", no_argument, 0, 'n'},
                                         {"console", no_argument, 0, 'c'},
                                         {"verbose", no_argument, 0, 'v'},
                                         {"help", no_argument, 0, 'h'},
                                         {0, 0, 0, 0}};

    int c;
    int optindex;
    while ((c = getopt_long(argc, argv, "s:u:g:t:incvh", opts, &optindex)) != -1)
    {
        switch (c)
        {
            case 0:
                if (strcmp(opts[optindex].name, "no-conntrack") == 0)
                    options.no_conntrack = 1;
                else if (strcmp(opts[optindex].name, "flow-protocol") == 0)
                    options.protocol = strdup(optarg);
                else if (strcmp(opts[optindex].name, "flow-category") == 0)
                    options.category = strdup(optarg);
                else if (strcmp(opts[optindex].name, "flow-breed") == 0)
                    options.breed = strdup(optarg);
                else if (strcmp(opts[optindex].name, "flow-encrypted") == 0)
                    options.encrypted = 1;
                else if (strcmp(opts[optindex].name, "flow-plaintext") == 0)
                    options.plaintext = 1;
                else {
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 's':
                free(options.distributor_host);
                options.distributor_host = strdup(optarg);
                break;
            case 'u':
                free(options.user);
                options.user = strdup(optarg);
                break;
            case 'g':
                free(options.group);
                options.group = strdup(optarg);
                break;
            case 't':
                free(options.table);
                options.table = strdup(optarg);
                break;
            case 'i':
                options.ignore_source = 1;
                break;
            case 'n':
                options.dry_run = 1;
                break;
            case 'c':
                enable_console_logger();
                break;
            case 'v':
                options.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 1;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (options.encrypted != 0 && options.plaintext != 0)
    {
        fprintf(stderr,
                "%s: Exclusive filtering encrypted and plaintext traffic at the same time does not make any sense\n",
                argv[0]);
        return 1;
    }

    if (options.table == NULL)
        options.table = strdup(NF_DEFAULT_TABLE);

    if (options.distributor_host == NULL)
        options.distributor_host = strdup(DISTRIBUTOR_UNIX_SOCKET);

    if (nDPIsrvd_setup_address(&ndpisrvd_socket->address, options.distributor_host) != 0)
    {
        fprintf(stderr, "%s: Could not parse address `%s'\n", argv[0], options.distributor_host);
        return 1;
    }

    return 0;
}

static struct nf_conntrack *
build_conntrack(struct filter const * const flt)
{
    struct nf_conntrack * const ct = nfct_new();

    if (ct == NULL)
        return NULL;

    if ((flt->src.family != AF_INET &&
         flt->src.family != AF_INET6) ||
        flt->src.family != flt->dst.family ||
        (flt->layer4_proto != IPPROTO_TCP &&
         flt->layer4_proto != IPPROTO_UDP))
    {
        nfct_destroy(ct);
        return NULL;
    }

    nfct_set_attr_u8(ct,  ATTR_L3PROTO, flt->src.family);
    if (flt->src.family == AF_INET) {
        if (options.ignore_source == 0)
            nfct_set_attr_u32(ct, ATTR_IPV4_SRC, flt->src.addr4);
        nfct_set_attr_u32(ct, ATTR_IPV4_DST, flt->dst.addr4);
    } else {
        if (options.ignore_source == 0)
            nfct_set_attr(ct, ATTR_IPV6_SRC, flt->src.addr6);
        nfct_set_attr(ct, ATTR_IPV6_DST, flt->dst.addr6);
    }
    nfct_set_attr_u8(ct,  ATTR_L4PROTO, flt->layer4_proto);
    if (options.ignore_source == 0)
        nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(flt->sport));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(flt->dport));

    if (options.verbose != 0)
        logger(0, "Netfilter Conntrack buffer: %s",
               (flt->src.family == AF_INET ? "AF_INET" : "AF_INET6"));

    return ct;
}

static int run_netfilter_conntrack(struct filter const * const flt)
{
    if (flt->have_src == 0 && flt->have_dst == 0 && flt->have_sport == 0 && flt->have_dport == 0)
    {
        logger(1, "Missing at least one filter criteria (source/dest IP/Port)");
        return 1;
    }

    struct nf_conntrack * const src_to_dst = build_conntrack(flt);
    if (src_to_dst == NULL) {
        logger(1, "Failed to build conntrack deleter context");
        return 1;
    }

    if (options.dry_run == 0) {
        errno = 0;
        int ret = nfct_query(nf_deleter, NFCT_Q_DESTROY, src_to_dst);
        if (ret == -1) {
            nfct_destroy(src_to_dst);
            logger(1, "Could not destroy conntrack entry: %s", strerror(errno));
            return 1;
        }
    }

    nfct_destroy(src_to_dst);
    return 0;
}

static int
nft_dpi_rule_exists(void)
{
    char buf[BUFSIZ];
    int written = snprintf(buf, sizeof(buf),
        "nft list chain inet %s forward 2>/dev/null", options.table);
    if (written >= BUFSIZ)
        return 0;

    FILE *fp = popen(buf, "r");
    if (fp == NULL)
        return 0;

    char line[BUFSIZ];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "nDPIsrvd-dpi-block") != NULL) {
            pclose(fp);
            return 1;
        }
    }

    pclose(fp);
    return 0;
}

static int run_netfilter_init(void)
{
    int rv = 0;
    char buf[BUFSIZ];

    if (options.dry_run == 0 && nft_dpi_rule_exists() != 0) {
        logger(0, "Table %s with chain forward does already exist, skipping init..", options.table);
        return 0;
    }

    int written = snprintf(buf, sizeof(buf),
        "add table inet %s", options.table);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter init Set: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to init Netfilter Set '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    written = snprintf(buf, sizeof(buf),
        "add set inet %s dpi_block_ip4 "
        "{ type ipv4_addr . ipv4_addr; flags timeout; timeout 60s; }",
        options.table);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter init Set: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to init Netfilter Set '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    written = snprintf(buf, sizeof(buf),
        "add set inet %s dpi_block_ip4_dst "
        "{ type ipv4_addr; flags timeout; timeout 60s; }",
        options.table);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter init Set: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to init Netfilter Set '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    written = snprintf(buf, sizeof(buf),
        "add set inet %s dpi_block_ip6 "
        "{ type ipv6_addr . ipv6_addr; flags timeout; timeout 60s; }",
        options.table);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter init Set: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to init Netfilter Set '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    written = snprintf(buf, sizeof(buf),
        "add set inet %s dpi_block_ip6_dst "
        "{ type ipv6_addr; flags timeout; timeout 60s; }",
        options.table);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter init Set: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to init Netfilter Set '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    written = snprintf(buf, sizeof(buf),
        "insert rule inet %s forward "
        "ip saddr . ip daddr @dpi_block_ip4 "
        "counter drop "
        "comment \"nDPIsrvd-dpi-block-ip4\"", options.table);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter init Set: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to init Netfilter Set '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    written = snprintf(buf, sizeof(buf),
        "insert rule inet %s forward "
        "ip daddr @dpi_block_ip4_dst "
        "counter drop "
        "comment \"nDPIsrvd-dpi-block-ip4-dst\"", options.table);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter init Set: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to init Netfilter Set '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    written = snprintf(buf, sizeof(buf),
        "insert rule inet %s forward "
        "ip6 saddr . ip6 daddr @dpi_block_ip6 "
        "counter drop "
        "comment \"nDPIsrvd-dpi-block-ip6\"", options.table);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter init Set: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to init Netfilter Set '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    written = snprintf(buf, sizeof(buf),
        "insert rule inet %s forward "
        "ip6 daddr @dpi_block_ip6_dst "
        "counter drop "
        "comment \"nDPIsrvd-dpi-block-ip6-dst\"", options.table);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter init Set: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to init Netfilter Set '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    return rv;
}

static int run_netfilter_block(struct filter const * const flt)
{
    int rv = 0;

    if (flt->have_src == 0 || flt->have_dst == 0)
        return 1;

    char buf[BUFSIZ];
    int written = BUFSIZ;
    if (options.ignore_source == 0) {
        written = snprintf(buf, sizeof(buf),
            "add element inet %s dpi_block_ip%c {"
            " %s . %s timeout 60s }",
            options.table, (flt->src.family == AF_INET ? '4' : '6'),
            flt->src.addr_str, flt->dst.addr_str);
    } else {
        written = snprintf(buf, sizeof(buf),
            "add element inet %s dpi_block_ip%c_dst {"
            " %s timeout 60s }",
            options.table, (flt->src.family == AF_INET ? '4' : '6'),
            flt->dst.addr_str);
    }
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter Block rule: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(nf_blocker, buf) != 0) {
            logger(1, "Failed to add Netfilter block rule '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    return rv;
}

static int token_to_ip_str(struct nDPIsrvd_socket * const sock,
                           struct nDPIsrvd_json_token const * const token,
                           char out[INET6_ADDRSTRLEN])
{
    size_t token_length = 0;
    char const * const token_value = TOKEN_GET_VALUE(sock, token, &token_length);

    if (token_length == 0 || token_value == NULL)
        return 1;
    if (token_length > INET6_ADDRSTRLEN)
        return 1;

    memcpy(out, token_value, token_length);
    return 0;
}

static int token_to_port(struct nDPIsrvd_socket * const sock,
                         struct nDPIsrvd_json_token const * const token,
                         uint16_t * const out)
{
    size_t token_length = 0;
    char const * const token_value = TOKEN_GET_VALUE(sock, token, &token_length);

    if (token_value == NULL)
        return 1;

    char * end = NULL;
    long v = strtol(token_value, &end, 10);

    if (*end != '\0' && *end != ',' && *end != '}')
        return 1;
    if (end == token_value || v < 1 || v > 65535)
        return 1;

    *out = (uint16_t)v;
    return 0;
}

static int token_equals(struct nDPIsrvd_socket * const sock,
                        struct nDPIsrvd_json_token const * const token,
                        char const * const equals_to_string)
{
    size_t token_length = 0;
    char const * const token_value = TOKEN_GET_VALUE(sock, token, &token_length);

    if (token_value == NULL || token_length == 0)
        return 1;

    return (strncmp(token_value, equals_to_string, token_length) == 0 ? 1 : 0);
}

static void run_netfilter(struct nDPIsrvd_socket * const sock,
                          struct nDPIsrvd_json_token const * const l3_proto,
                          struct nDPIsrvd_json_token const * const src_ip,
                          struct nDPIsrvd_json_token const * const dst_ip,
                          struct nDPIsrvd_json_token const * const l4_proto,
                          struct nDPIsrvd_json_token const * const src_port,
                          struct nDPIsrvd_json_token const * const dst_port)
{
    int is_ip4 = token_equals(sock, l3_proto, "ip4");
    int is_ip6 = token_equals(sock, l3_proto, "ip6");
    int is_tcp = token_equals(sock, l4_proto, "tcp");
    int is_udp = token_equals(sock, l4_proto, "udp");

    if (is_ip4 == 0 && is_ip6 == 0) {
        logger(1, "Not blocking traffic as Layer3 is neither IPv4 nor IPv6");
        return;
    }
    if (is_tcp == 0 && is_udp == 0) {
        logger(1, "Not blocking traffic as Layer4 is neither TCP nor UDP");
        return;
    }

    struct filter flt;
    memset(&flt, '\0', sizeof(flt));

    if (token_to_ip_str(sock, src_ip, flt.src.addr_str) != 0) {
        logger(1, "Could not convert token to source IP");
        return;
    }
    if (token_to_ip_str(sock, dst_ip, flt.dst.addr_str) != 0) {
        logger(1, "Could not convert token to destination IP");
        return;
    }

    if (is_ip4 != 0 && inet_pton(AF_INET, flt.src.addr_str, &flt.src.addr4) == 1) {
        flt.src.family = AF_INET;
        flt.have_src = 1;
    } else if (is_ip6 != 0 && inet_pton(AF_INET6, flt.src.addr_str, &flt.src.addr6) == 1) {
        flt.src.family = AF_INET6;
        flt.have_src = 1;
    } else {
        logger(1, "Not a valid source IP address: '%s'", flt.src.addr_str);
    }

    if (inet_pton(AF_INET, flt.dst.addr_str, &flt.dst.addr4) == 1) {
        flt.dst.family = AF_INET;
        flt.have_dst = 1;
    } else if (inet_pton(AF_INET6, flt.dst.addr_str, &flt.dst.addr6) == 1) {
        flt.dst.family = AF_INET6;
        flt.have_dst = 1;
    } else {
        logger(1, "Not a valid destination IP address: '%s'", flt.dst.addr_str);
    }

    flt.layer4_proto = (is_tcp != 0 ? IPPROTO_TCP : IPPROTO_UDP);

    uint16_t src_port_u16;
    uint16_t dst_port_u16;

    if (token_to_port(sock, src_port, &src_port_u16) == 0) {
        flt.sport = src_port_u16;
        flt.have_sport = 1;
    } else {
        logger(1, "Could not convert token to source Port");
    }
    if (token_to_port(sock, dst_port, &dst_port_u16) == 0) {
        flt.dport = dst_port_u16;
        flt.have_dport = 1;
    } else {
        logger(1, "Could not convert token to destination Port");
    }

    if (options.verbose) {
        logger(0, "src -> dst: %s [%s]:%u -> [%s]:%u",
               (is_tcp != 0 ? "TCP" : "UDP"),
               flt.src.addr_str, src_port_u16, flt.dst.addr_str, dst_port_u16);
    }

    if (run_netfilter_block(&flt) != 0)
        return;
    if (options.no_conntrack == 0 && run_netfilter_conntrack(&flt) != 0)
        return;
}

static enum nDPIsrvd_callback_return captured_json_callback(struct nDPIsrvd_socket * const sock,
                                                            struct nDPIsrvd_instance * const instance,
                                                            struct nDPIsrvd_thread_data * const thread_data,
                                                            struct nDPIsrvd_flow * const flow)
{
    (void)instance;
    (void)thread_data;
    (void)flow;

    int do_block = 0;

    {
        struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");
        if (flow_event_name == NULL)
            return CALLBACK_OK;
    }
    {
        struct nDPIsrvd_json_token const * const flow_proto = TOKEN_GET_SZ(sock, "ndpi", "proto");
        if (flow_proto != NULL && options.protocol != NULL) {
            size_t proto_length = 0;
            char const * const proto = TOKEN_GET_VALUE(sock, flow_proto, &proto_length);
            if (proto != NULL && proto_length > 0)
            {
                if (options.verbose != 0)
                    logger(0, "Matching `%s' against `%.*s' (flow-protocol)",
                           options.protocol, (int)proto_length, proto);

                if (proto_length >= strlen(options.protocol))
                {
                    if (strncasecmp(proto, options.protocol, proto_length) == 0)
                    {
                        do_block++;
                    } else {
                        if (options.verbose != 0)
                            logger(0, "NO match `%s' against `%.*s' (flow-protocol)",
                                   options.protocol, (int)proto_length, proto);
                        char const * app_proto = NULL;
                        for (size_t i = 0; i < proto_length; ++i) {
                            if (proto[i] == '.') {
                                app_proto = &proto[i + 1];
                                break;
                            }
                        }
                        if (app_proto != NULL) {
                            size_t app_length = proto_length - (app_proto - proto);
                            if (options.verbose != 0)
                                logger(0, "Matching `%s' against application `%.*s' (flow-protocol)",
                                       options.protocol, (int)app_length, app_proto);

                            if (app_length > 0 &&
                                strncasecmp(app_proto, options.protocol, app_length) == 0)
                            {
                                do_block++;
                            } else if (options.verbose != 0) {
                                logger(0, "NO match `%s' against application `%.*s' (flow-protocol)",
                                       options.protocol, (int)app_length, app_proto);
                            }
                        }
                    }
                }
            }
        }
    }
    {
        struct nDPIsrvd_json_token const * const flow_category = TOKEN_GET_SZ(sock, "ndpi", "category");
        if (flow_category != NULL && options.category != NULL) {
            size_t category_length = 0;
            char const * const category = TOKEN_GET_VALUE(sock, flow_category, &category_length);
            if (category != NULL && category_length > 0)
            {
                if (options.verbose != 0)
                    logger(0, "Matching `%s' against `%.*s' (flow-category)",
                           options.category, (int)category_length, category);
                if (category_length >= strlen(options.category) &&
                    strncasecmp(category, options.category, category_length) == 0)
                {
                    do_block++;
                } else if (options.verbose != 0)
                    logger(0, "NO match `%s' against `%.*s' (flow-category)",
                           options.category, (int)category_length, category);
            }
        }
    }
    {
        struct nDPIsrvd_json_token const * const flow_breed = TOKEN_GET_SZ(sock, "ndpi", "breed");
        if (flow_breed != NULL && options.breed != NULL) {
            size_t breed_length = 0;
            char const * const breed = TOKEN_GET_VALUE(sock, flow_breed, &breed_length);
            if (breed != NULL && breed_length > 0)
            {
                if (options.verbose != 0)
                    logger(0, "Matching `%s' against `%.*s' (flow-breed)",
                           options.breed, (int)breed_length, breed);
                if (breed_length >= strlen(options.breed) &&
                    strncasecmp(breed, options.breed, breed_length) == 0)
                {
                    do_block++;
                } else if (options.verbose != 0)
                    logger(0, "NO match `%s' against `%.*s' (flow-breed)",
                           options.breed, (int)breed_length, breed);
            }
        }
    }
    {
        struct nDPIsrvd_json_token const * const flow_encrypted = TOKEN_GET_SZ(sock, "ndpi", "encrypted");
        if (flow_encrypted != NULL && (options.encrypted != 0 || options.plaintext != 0)) {
            size_t encrypted_length = 0;
            char const * const encrypted = TOKEN_GET_VALUE(sock, flow_encrypted, &encrypted_length);
            if (encrypted != NULL && encrypted_length > 0) {
                if (options.verbose != 0) {
                    if (options.encrypted != 0)
                        logger(0, "Matching 1 against `%.*s' (flow-encrypted)",
                               (int)encrypted_length, encrypted);
                    if (options.plaintext != 0)
                        logger(0, "Matching 0 against `%.*s' (flow-plaintext)",
                               (int)encrypted_length, encrypted);
                }
                if (strncmp(encrypted, "1", encrypted_length) == 0) {
                    if (options.encrypted != 0)
                        do_block++;
                } else if (options.plaintext != 0) {
                    do_block++;
                } else {
                    logger(0, "NO match 1 / 0 against `%.*s' (flow-encrypted / flow-plaintext)",
                           (int)encrypted_length, encrypted);
                }
            }
        }
    }

    if (do_block > 0)
    {
        struct nDPIsrvd_json_token const * const l3_proto = TOKEN_GET_SZ(sock, "l3_proto");
        struct nDPIsrvd_json_token const * const l4_proto = TOKEN_GET_SZ(sock, "l4_proto");
        struct nDPIsrvd_json_token const * const src_ip = TOKEN_GET_SZ(sock, "src_ip");
        struct nDPIsrvd_json_token const * const dst_ip = TOKEN_GET_SZ(sock, "dst_ip");
        struct nDPIsrvd_json_token const * const src_port = TOKEN_GET_SZ(sock, "src_port");
        struct nDPIsrvd_json_token const * const dst_port = TOKEN_GET_SZ(sock, "dst_port");

        if (options.verbose != 0)
            logger(0, "Matched %u DPI criteria", do_block);
        if (l3_proto == NULL || l4_proto == NULL) {
            if (options.verbose != 0)
                logger(0, "Not blocking traffic as Layer3 or Layer4 protocol missing");
            return CALLBACK_ERROR;
        }
        if (src_ip == NULL || dst_ip == NULL) {
            if (options.verbose != 0)
                logger(0, "Not blocking traffic as Source or Destination IP address missing");
            return CALLBACK_ERROR;
        }

        run_netfilter(sock, l3_proto, src_ip, dst_ip, l4_proto, src_port, dst_port);
    }

    return CALLBACK_OK;
}

static int mainloop(void)
{
    enum nDPIsrvd_read_return read_ret = READ_OK;

    while (main_thread_shutdown == 0)
    {
        read_ret = nDPIsrvd_read(ndpisrvd_socket);
        if (errno == EINTR)
        {
            continue;
        }
        if (read_ret == READ_TIMEOUT)
        {
            logger(0,
                   "No data received during the last %llu second(s).",
                   (long long unsigned int)ndpisrvd_socket->read_timeout.tv_sec);
            continue;
        }
        if (read_ret != READ_OK)
        {
            logger(1, "Could not read from socket: %s", nDPIsrvd_enum_to_string(read_ret));
            break;
        }

        enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(ndpisrvd_socket);
        if (parse_ret != PARSE_NEED_MORE_DATA)
        {
            logger(1, "Could not parse json message: %s", nDPIsrvd_enum_to_string(parse_ret));
            break;
        }
    }

    if (main_thread_shutdown == 0 && read_ret != READ_OK)
    {
        return 1;
    }

    return 0;
}

static void sighandler(int signum)
{
    (void)signum;

    if (main_thread_shutdown == 0)
    {
        main_thread_shutdown = 1;
    }
}

int main(int argc, char ** argv)
{
    init_logging("nDPIsrvd-nf-conntrack");

    ndpisrvd_socket = nDPIsrvd_socket_init(0, 0, 0, 0,
                                           captured_json_callback,
                                           NULL, NULL);
    if (ndpisrvd_socket == NULL)
    {
        fprintf(stderr, "%s: nDPIsrvd socket memory allocation failed!\n", argv[0]);
        return 1;
    }

    errno = 0;
    nf_deleter = nfct_open(CONNTRACK, 0);
    if (nf_deleter == NULL)
    {
        logger(1, "Could not open Netfilter Conntrack (deleter handle): %s", strerror(errno));
        return 1;
    }

    if (options.dry_run == 0)
    {
        errno = 0;
        nf_blocker = nft_ctx_new(NFT_CTX_DEFAULT);
        if (nf_blocker == NULL)
        {
            logger(1, "Could not open Netfilter (blocker): %s", strerror(errno));
            return 1;
        }
    }

    if (parse_options(argc, argv) != 0)
        return 1;

    if (run_netfilter_init() != 0)
        return 1;

    logger(0, "Recv buffer size: %u", NETWORK_BUFFER_MAX_SIZE);
    logger(0, "Connecting to `%s'..", options.distributor_host);

    errno = 0;
    if (nDPIsrvd_connect(ndpisrvd_socket) != CONNECT_OK)
    {
        fprintf(stderr, "%s: nDPIsrvd socket connect to %s failed with: %s\n", argv[0], options.distributor_host, strerror(errno));
        nDPIsrvd_socket_free(&ndpisrvd_socket);
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, sighandler);

    errno = 0;
    if (options.user != NULL && change_user_group(options.user, options.group, NULL) != 0)
    {
        if (errno != 0)
        {
            logger(1, "Change user/group failed: %s", strerror(errno));
        }
        else
        {
            logger(1, "Change user/group failed.");
        }
        return 1;
    }

    if (nDPIsrvd_set_read_timeout(ndpisrvd_socket, 180, 0) != 0)
    {
        return 1;
    }

    int retval = mainloop();

    nDPIsrvd_socket_free(&ndpisrvd_socket);
    shutdown_logging();

    if (options.dry_run == 0)
        nft_ctx_free(nf_blocker);
    nfct_close(nf_deleter);

    return retval;
}
