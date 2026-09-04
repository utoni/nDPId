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

#define IP_BUFSIZ (sizeof(struct in6_addr))

static struct {
    int dry_run;
    int verbose;
    char * distributor_host;
    char * user;
    char * group;
} options = {
    .dry_run = 0,
    .verbose = 0,
    .distributor_host = NULL,
    .user = NULL,
    .group = NULL,
};

static struct nDPIsrvd_socket * ndpisrvd_socket = NULL;
static struct nfct_handle * nf_querier = NULL;
static struct nfct_handle * nf_deleter = NULL;
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
    uint16_t sport;
    uint16_t dport;
    int match_reply;
    unsigned long matched;
    unsigned long deleted;
};

static int match_ip(struct nf_conntrack const * const ct,
                    enum nf_conntrack_attr attr,
                    struct ip const * const ip)
{
    switch (ip->family) {
        case AF_INET:
            if (nfct_attr_is_set(ct, attr) != 0)
                return 1;
            return (nfct_get_attr_u32(ct, attr) == ip->addr4 ? 0 : 1);
        case AF_INET6:
            if (nfct_attr_is_set(ct, attr) != 0)
                return 1;
            return (memcmp(nfct_get_attr(ct, attr), ip->addr6, IP_BUFSIZ) == 0 ? 0 : 1);
    }

    return -1;
}

static int match_orig(const struct nf_conntrack * ct, const struct filter * f)
{
    if (f->have_src &&
        (match_ip(ct, ATTR_ORIG_IPV4_SRC, &f->src) == 0 ||
         match_ip(ct, ATTR_ORIG_IPV6_SRC, &f->src) == 0))
    {
        return 0;
    }
    if (f->have_dst &&
        (match_ip(ct, ATTR_ORIG_IPV4_DST, &f->dst) == 0 ||
         match_ip(ct, ATTR_ORIG_IPV6_DST, &f->dst) == 0))
    {
        return 0;
    }
    if (f->have_sport && nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) != f->sport)
        return 0;
    if (f->have_dport && nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST) != f->dport)
        return 0;
    return 1;
}

static int match_reply(const struct nf_conntrack * ct, const struct filter * f)
{
    if (f->have_src &&
        (match_ip(ct, ATTR_REPL_IPV4_SRC, &f->src) == 0 ||
         match_ip(ct, ATTR_REPL_IPV6_SRC, &f->src) == 0))
    {
        return 0;
    }
    if (f->have_dst &&
        (match_ip(ct, ATTR_REPL_IPV4_DST, &f->dst) == 0 ||
         match_ip(ct, ATTR_REPL_IPV6_DST, &f->dst) == 0))
    {
        return 0;
    }
    if (f->have_sport && nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC) != f->sport)
        return 0;
    if (f->have_dport && nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST) != f->dport)
        return 0;
    return 1;
}

static int matches(const struct nf_conntrack * ct, const struct filter * f)
{
    if (nfct_get_attr_u8(ct, ATTR_L4PROTO) != IPPROTO_TCP)
        return 0;
    if (match_orig(ct, f))
        return 1;
    if (f->match_reply && match_reply(ct, f))
        return 1;
    return 0;
}

static int nf_conntrack_cb(enum nf_conntrack_msg_type type, struct nf_conntrack * ct, void * data)
{
    (void)type;
    struct filter * f = data;

    if (!matches(ct, f))
        return NFCT_CB_CONTINUE;

    f->matched++;

    char buf[1024];
    nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3);

    if (options.dry_run != 0)
    {
        logger(0, "[dry-run] Delete: %s\n", buf);
        return NFCT_CB_CONTINUE;
    }

    if (nfct_query(nf_deleter, NFCT_Q_DESTROY, ct) < 0)
    {
        logger(1, "Can not delete (%s): %s\n", strerror(errno), buf);
    }
    else
    {
        f->deleted++;
        if (options.verbose != 0)
            logger(0, "Deleted: %s\n", buf);
    }
    return NFCT_CB_CONTINUE;
}

static void print_usage(const char * arg0)
{
    static char const usage[] =
        "Usage: %s [Options]\n"
        "\nOptions:\n"
        "\t-s, --server       distributor host\n"
        "\t-u, --user         change user after connect\n"
        "\t-g, --group        change group after connect\n"
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
                                         {"dry-run", no_argument, 0, 'n'},
                                         {"console", no_argument, 0, 'c'},
                                         {"verbose", no_argument, 0, 'v'},
                                         {"help", no_argument, 0, 'h'},
                                         {0, 0, 0, 0}};

    int c;
    while ((c = getopt_long(argc, argv, "s:u:g:ncvh", opts, NULL)) != -1)
    {
        switch (c)
        {
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
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (options.distributor_host == NULL)
    {
        options.distributor_host = strdup(DISTRIBUTOR_UNIX_SOCKET);
    }

    if (nDPIsrvd_setup_address(&ndpisrvd_socket->address, options.distributor_host) != 0)
    {
        fprintf(stderr, "%s: Could not parse address `%s'\n", argv[0], options.distributor_host);
        return 1;
    }

    return 0;
}

static int run_netfilter_conntrack(struct filter * const flt)
{
    if (!flt->have_src && !flt->have_dst && !flt->have_sport && !flt->have_dport)
    {
        logger(1, "Missing at least one filter criteria (source/dest IP or Port)");
        return 1;
    }

    errno = 0;
    if (nfct_callback_register(nf_querier, NFCT_T_ALL, nf_conntrack_cb, flt) != 0) {
        logger(1, "Could not register Netfilter Conntrack callback: %s", strerror(errno));
        return 1;
    }

    if (options.dry_run == 0) {
        uint32_t family = flt->dst.family;
        errno = 0;
        int ret = nfct_query(nf_querier, NFCT_Q_DUMP, &family);
        if (ret < 0)
            logger(1, "Could not query or dump Netfilter Conntrack: %s", strerror(errno));
    }

    if (options.verbose) {
        logger(0, "Netfilter Conntrack found: %lu entries, deleted: %lu entries%s",
               flt->matched, flt->deleted, options.dry_run != 0 ? " (dry-run)" : "");
    }

    nfct_callback_unregister(nf_querier);

    return 0;
}

static int run_netfilter_block(struct filter const * const flt)
{
    int rv = 0;
    struct nft_ctx *ctx;

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);

    if (ctx == NULL)
        return 1;

    if (flt->have_src == 0 || flt->have_dst == 0)
        return 1;

    char const * const src_family = (flt->src.family == AF_INET ? "ip" : "ip6");
    char const * const dst_family = (flt->dst.family == AF_INET ? "ip" : "ip6");

    char buf[BUFSIZ];
    int written = snprintf(buf, sizeof(buf),
        "add rule inet filter forward"
        " %s saddr %s %s daddr %s drop",
        src_family, flt->src.addr_str,
        dst_family, flt->dst.addr_str);
    if (written < BUFSIZ) {
        errno = 0;
        if (options.dry_run != 0) {
            logger(0, "Netfilter Block rule: '%s' (dry-run)", buf);
        } else if (nft_run_cmd_from_buffer(ctx, buf) != 0) {
            logger(1, "Failed to add Netfilter block rule '%s': %s",
                   buf, strerror(errno));
            rv = 1;
        }
    } else {
        rv = 1;
    }

    nft_ctx_free(ctx);

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

    if (token_value == NULL)
        return 1;

    return (memcmp(token_value, equals_to_string, token_length) == 0 ? 1 : 0);
}

static void run_netfilter(struct nDPIsrvd_socket * const sock,
                          struct nDPIsrvd_json_token const * const l3_proto,
                          struct nDPIsrvd_json_token const * const src_ip,
                          struct nDPIsrvd_json_token const * const dst_ip,
                          struct nDPIsrvd_json_token const * const src_port,
                          struct nDPIsrvd_json_token const * const dst_port)
{
    int is_ip4 = token_equals(sock, l3_proto, "ip4");
    int is_ip6 = token_equals(sock, l3_proto, "ip6");

    if (is_ip4 == 0 && is_ip6 == 0)
        return;

    struct filter flt;
    memset(&flt, '\0', sizeof(flt));

    if (token_to_ip_str(sock, src_ip, flt.src.addr_str) != 0)
        return;
    if (token_to_ip_str(sock, dst_ip, flt.dst.addr_str) != 0)
        return;

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

    uint16_t src_port_u16;
    uint16_t dst_port_u16;

    if (token_to_port(sock, src_port, &src_port_u16) == 0)
        flt.have_sport = 1;
    if (token_to_port(sock, dst_port, &dst_port_u16) == 0)
        flt.have_dport = 1;

    if (options.verbose) {
        logger(0, "src -> dst: '%s' port %u -> '%s' port %u",
               flt.src.addr_str, src_port_u16, flt.dst.addr_str, dst_port_u16);
    }

    if (run_netfilter_block(&flt) != 0)
        return;
    if (run_netfilter_conntrack(&flt) != 0) {
        logger(1, "Netfilter Conntrack failed: src -> dst: '%s' port %u -> '%s' port %u",
               flt.src.addr_str, src_port_u16, flt.dst.addr_str, dst_port_u16);
        return;
    }
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
        struct nDPIsrvd_json_token const * const flow_risk = TOKEN_GET_SZ(sock, "ndpi", "flow_risk");
        if (flow_risk != NULL) {
            do_block++;
        }
    }
    {
        struct nDPIsrvd_json_token const * const flow_proto = TOKEN_GET_SZ(sock, "ndpi", "proto");
        if (flow_proto != NULL) {
            do_block++;
        }
    }
    {
        struct nDPIsrvd_json_token const * const flow_category = TOKEN_GET_SZ(sock, "ndpi", "category");
        if (flow_category != NULL) {
            do_block++;
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

        if (l3_proto == NULL || l4_proto == NULL)
            return CALLBACK_ERROR;
        if (src_ip == NULL || dst_ip == NULL)
            return CALLBACK_ERROR;

        run_netfilter(sock, l3_proto, src_ip, dst_ip, src_port, dst_port);
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
    nf_querier = nfct_open(CONNTRACK, 0);
    if (nf_querier == NULL)
    {
        logger(1, "Could not open Netfilter Conntrack (deleter handle): %s", strerror(errno));
        return 1;
    }

    errno = 0;
    nf_deleter = nfct_open(CONNTRACK, 0);
    if (nf_deleter == NULL)
    {
        logger(1, "Could not open Netfilter Conntrack (deleter handle): %s", strerror(errno));
        return 1;
    }

    if (parse_options(argc, argv) != 0)
    {
        return 1;
    }

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

    nfct_close(nf_deleter);
    nfct_close(nf_querier);

    return retval;
}
