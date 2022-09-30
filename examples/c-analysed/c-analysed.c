#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "nDPIsrvd.h"
#include "utils.h"

#define MIN(a, b) (a > b ? b : a)
#define BUFFER_REMAINING(siz) (NETWORK_BUFFER_MAX_SIZE - siz)

static int main_thread_shutdown = 0;
static struct nDPIsrvd_socket * sock = NULL;

static char * pidfile = NULL;
static char * serv_optarg = NULL;
static char * user = NULL;
static char * group = NULL;
static char * csv_outfile = NULL;
static FILE * csv_fp = NULL;

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
    fprintf(stderr, "%s", "nDPIsrvd MemoryProfiler: ");
    vfprintf(stderr, format, ap);
    fprintf(stderr, "%s\n", "");
    va_end(ap);
}
#endif

static void nDPIsrvd_write_flow_info_cb(struct nDPIsrvd_socket const * sock,
                                        struct nDPIsrvd_instance const * instance,
                                        struct nDPIsrvd_thread_data const * thread_data,
                                        struct nDPIsrvd_flow const * flow,
                                        void * user_data)
{
    (void)sock;
    (void)instance;
    (void)user_data;

    fprintf(stderr,
            "[Thread %2d][Flow %5llu][ptr: "
#ifdef __LP64__
            "0x%016llx"
#else
            "0x%08lx"
#endif
            "][last-seen: %13llu][idle-time: %7llu][time-until-timeout: %7llu]\n",
            flow->thread_id,
            flow->id_as_ull,
#ifdef __LP64__
            (unsigned long long int)flow,
#else
            (unsigned long int)flow,
#endif
            flow->last_seen,
            flow->idle_time,
            (flow->last_seen + flow->idle_time >= thread_data->most_recent_flow_time
                 ? flow->last_seen + flow->idle_time - thread_data->most_recent_flow_time
                 : 0));
}

static void nDPIsrvd_verify_flows_cb(struct nDPIsrvd_thread_data const * const thread_data,
                                     struct nDPIsrvd_flow const * const flow,
                                     void * user_data)
{
    (void)user_data;

    if (thread_data != NULL)
    {
        if (flow->last_seen + flow->idle_time >= thread_data->most_recent_flow_time)
        {
            fprintf(stderr,
                    "Thread %d / %d, Flow %llu verification failed\n",
                    thread_data->thread_key,
                    flow->thread_id,
                    flow->id_as_ull);
        }
        else
        {
            fprintf(stderr,
                    "Thread %d / %d, Flow %llu verification failed, diff: %llu\n",
                    thread_data->thread_key,
                    flow->thread_id,
                    flow->id_as_ull,
                    thread_data->most_recent_flow_time - flow->last_seen + flow->idle_time);
        }
    }
    else
    {
        fprintf(stderr, "Thread [UNKNOWN], Flow %llu verification failed\n", flow->id_as_ull);
    }
}

static void sighandler(int signum)
{
    struct nDPIsrvd_instance * current_instance;
    struct nDPIsrvd_instance * itmp;
    int verification_failed = 0;

    if (signum == SIGUSR1)
    {
        nDPIsrvd_flow_info(sock, nDPIsrvd_write_flow_info_cb, NULL);

        HASH_ITER(hh, sock->instance_table, current_instance, itmp)
        {
            if (nDPIsrvd_verify_flows(current_instance, nDPIsrvd_verify_flows_cb, NULL) != 0)
            {
                fprintf(stderr, "Flow verification failed for instance %d\n", current_instance->alias_source_key);
                verification_failed = 1;
            }
        }
        if (verification_failed == 0)
        {
            fprintf(stderr, "%s\n", "Flow verification succeeded.");
        }
        else
        {
            /* FATAL! */
            exit(EXIT_FAILURE);
        }
    }
    else if (main_thread_shutdown == 0)
    {
        main_thread_shutdown = 1;
    }
}

static void csv_buf_add(char csv_buf[NETWORK_BUFFER_MAX_SIZE + 1],
                        size_t * const csv_buf_used,
                        char const * const str,
                        size_t siz_len)
{
    size_t len;

    if (siz_len > 0 && str != NULL)
    {
        len = MIN(BUFFER_REMAINING(*csv_buf_used), siz_len);
        if (len == 0)
        {
            return;
        }
        strncat(csv_buf, str, len);
    }
    else
    {
        len = 0;
    }

    *csv_buf_used += len;
    if (BUFFER_REMAINING(*csv_buf_used) > 0)
    {
        csv_buf[*csv_buf_used] = ',';
        (*csv_buf_used)++;
    }
    csv_buf[*csv_buf_used] = '\0';
}

static int json_value_to_csv(struct nDPIsrvd_socket * const sock,
                             char csv_buf[NETWORK_BUFFER_MAX_SIZE + 1],
                             size_t * const csv_buf_used,
                             char const * const json_key,
                             ...)
{
    va_list ap;
    nDPIsrvd_hashkey key;
    struct nDPIsrvd_json_token const * token;
    size_t val_length = 0;
    char const * val;
    int ret = 0;

    va_start(ap, json_key);
    key = nDPIsrvd_vbuild_jsmn_key(json_key, ap);
    va_end(ap);

    token = nDPIsrvd_find_token(sock, key);
    if (token == NULL)
    {
        ret++;
    }

    val = TOKEN_GET_VALUE(sock, token, &val_length);
    if (val == NULL)
    {
        ret++;
    }

    csv_buf_add(csv_buf, csv_buf_used, val, val_length);

    return ret;
}

static int json_array_to_csv(struct nDPIsrvd_socket * const sock,
                             char csv_buf[NETWORK_BUFFER_MAX_SIZE + 1],
                             size_t * const csv_buf_used,
                             char const * const json_key,
                             ...)
{
    va_list ap;
    nDPIsrvd_hashkey key;
    struct nDPIsrvd_json_token const * token;
    int ret = 0;

    va_start(ap, json_key);
    key = nDPIsrvd_vbuild_jsmn_key(json_key, ap);
    va_end(ap);

    token = nDPIsrvd_find_token(sock, key);
    if (token == NULL)
    {
        ret++;
        csv_buf_add(csv_buf, csv_buf_used, NULL, 0);
    }

    {
        struct nDPIsrvd_json_token next = {};

        csv_buf_add(csv_buf, csv_buf_used, "\"", 1);
        csv_buf[--(*csv_buf_used)] = '\0';
        while (nDPIsrvd_token_iterate(sock, token, &next) == 0)
        {
            size_t val_length = 0;
            char const * const val = TOKEN_GET_VALUE(sock, &next, &val_length);

            csv_buf_add(csv_buf, csv_buf_used, val, val_length);
        }
        csv_buf[--(*csv_buf_used)] = '\0';
        csv_buf_add(csv_buf, csv_buf_used, "\"", 1);
    }

    return ret;
}

static enum nDPIsrvd_callback_return simple_json_callback(struct nDPIsrvd_socket * const sock,
                                                          struct nDPIsrvd_instance * const instance,
                                                          struct nDPIsrvd_thread_data * const thread_data,
                                                          struct nDPIsrvd_flow * const flow)
{
    char csv_buf[NETWORK_BUFFER_MAX_SIZE + 1];
    size_t csv_buf_used = 0;

    (void)instance;
    (void)thread_data;

    if (flow == NULL)
    {
        return CALLBACK_OK;
    }

    struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");
    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "analyse") == 0)
    {
        return CALLBACK_OK;
    }

    if (TOKEN_GET_SZ(sock, "data_analysis") == NULL)
    {
        return CALLBACK_ERROR;
    }

    csv_buf[0] = '\0';

    json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_datalink", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "l3_proto", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "src_ip", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "dst_ip", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "l4_proto", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "src_port", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "dst_port", NULL);

    if (json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_state", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_src_packets_processed", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_dst_packets_processed", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_first_seen", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_src_last_pkt_time", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_dst_last_pkt_time", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_src_min_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_dst_min_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_src_max_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_dst_max_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_src_tot_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "flow_dst_tot_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "midstream", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "iat", "min", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "iat", "avg", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "iat", "max", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "iat", "stddev", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "iat", "var", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "iat", "ent", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "iat", "data", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "pktlen", "min", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "pktlen", "avg", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "pktlen", "max", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "pktlen", "stddev", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "pktlen", "var", NULL) != 0 ||
        json_value_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "pktlen", "ent", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "pktlen", "data", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "bins", "c_to_s", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "bins", "s_to_c", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "directions", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, csv_buf, &csv_buf_used, "data_analysis", "entropies", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    json_value_to_csv(sock, csv_buf, &csv_buf_used, "ndpi", "proto", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "ndpi", "proto_id", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "ndpi", "encrypted", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "ndpi", "breed", NULL);
    json_value_to_csv(sock, csv_buf, &csv_buf_used, "ndpi", "category", NULL);
    {
        struct nDPIsrvd_json_token const * const token = TOKEN_GET_SZ(sock, "ndpi", "confidence");
        struct nDPIsrvd_json_token const * current = NULL;
        int next_child_index = -1;

        if (token == NULL)
        {
            csv_buf_add(csv_buf, &csv_buf_used, NULL, 0);
            csv_buf_add(csv_buf, &csv_buf_used, NULL, 0);
        }
        else
        {
            while ((current = nDPIsrvd_get_next_token(sock, token, &next_child_index)) != NULL)
            {
                size_t key_length = 0, value_length = 0;
                char const * const key = TOKEN_GET_KEY(sock, current, &key_length);
                char const * const value = TOKEN_GET_VALUE(sock, current, &value_length);

                csv_buf_add(csv_buf, &csv_buf_used, key, key_length);
                csv_buf_add(csv_buf, &csv_buf_used, value, value_length);
            }
        }
    }

    if (csv_buf_used > 0 && csv_buf[csv_buf_used - 1] == ',')
    {
        csv_buf[--csv_buf_used] = '\0';
    }

    fprintf(csv_fp, "%.*s\n", (int)csv_buf_used, csv_buf);

    return CALLBACK_OK;
}

static void print_usage(char const * const arg0)
{
    static char const usage[] =
        "Usage: %s "
        "[-d] [-p pidfile] [-s host]\n"
        "\t  \t[-u user] [-g group] [-o csv-outfile]\n\n"
        "\t-d\tForking into background after initialization.\n"
        "\t-p\tWrite the daemon PID to the given file path.\n"
        "\t-s\tDestination where nDPIsrvd is listening on.\n"
        "\t  \tCan be either a path to UNIX socket or an IPv4/TCP-Port IPv6/TCP-Port tuple.\n"
        "\t-u\tChange user.\n"
        "\t-g\tChange group.\n"
        "\t-o\tSpecify the CSV output file for analysis results\n\n";

    fprintf(stderr, usage, arg0);
}

static int parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "hdp:s:u:g:o:")) != -1)
    {
        switch (opt)
        {
            case 'd':
                daemonize_enable();
                break;
            case 'p':
                free(pidfile);
                pidfile = strdup(optarg);
                break;
            case 's':
                free(serv_optarg);
                serv_optarg = strdup(optarg);
                break;
            case 'u':
                free(user);
                user = strdup(optarg);
                break;
            case 'g':
                free(group);
                group = strdup(optarg);
                break;
            case 'o':
                free(csv_outfile);
                csv_outfile = strdup(optarg);
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (csv_outfile == NULL)
    {
        fprintf(stderr, "%s: Missing CSV output file (`-o')\n", argv[0]);
        return 1;
    }

    opt = 0;
    if (access(csv_outfile, F_OK) != 0 && errno == ENOENT)
    {
        opt = 1;
    }

    csv_fp = fopen(csv_outfile, "a+");
    if (csv_fp == NULL)
    {
        fprintf(stderr, "%s: Could not open file `%s' for appending\n", argv[0], csv_outfile);
        return 1;
    }

    if (opt != 0)
    {
        fprintf(csv_fp,
                "flow_datalink,l3_proto,src_ip,dst_ip,l4_proto,src_port,dst_port,flow_state,flow_src_packets_processed,"
                "flow_dst_packets_processed,flow_first_seen,flow_src_last_pkt_time,flow_dst_last_pkt_time,flow_src_min_"
                "l4_payload_len,flow_dst_min_l4_payload_len,flow_src_max_l4_payload_len,flow_dst_max_l4_payload_len,"
                "flow_src_tot_l4_payload_len,flow_dst_tot_l4_payload_len,midstream,iat_min,iat_avg,iat_max,iat_stddev,"
                "iat_var,iat_ent,iat_data,pktlen_min,pktlen_avg,pktlen_max,pktlen_stddev,pktlen_var,pktlen_ent,pktlen_"
                "data,bins_c_to_s,bins_s_to_c,directions,entropies,proto,proto_id,encrypted,breed,category,"
                "confidence_id,confidence\n");
    }

    if (serv_optarg == NULL)
    {
        serv_optarg = strdup(DISTRIBUTOR_UNIX_SOCKET);
    }

    if (nDPIsrvd_setup_address(&sock->address, serv_optarg) != 0)
    {
        fprintf(stderr, "%s: Could not parse address `%s'\n", argv[0], serv_optarg);
        return 1;
    }

    if (optind < argc)
    {
        fprintf(stderr, "Unexpected argument after options\n\n");
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}

int main(int argc, char ** argv)
{
    signal(SIGUSR1, sighandler);
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, sighandler);

    sock = nDPIsrvd_socket_init(0, 0, 0, 0, simple_json_callback, NULL, NULL);
    if (sock == NULL)
    {
        return 1;
    }

    if (parse_options(argc, argv) != 0)
    {
        return 1;
    }

    printf("Recv buffer size: %u\n", NETWORK_BUFFER_MAX_SIZE);
    printf("Connecting to `%s'..\n", serv_optarg);

    if (nDPIsrvd_connect(sock) != CONNECT_OK)
    {
        fprintf(stderr, "%s: nDPIsrvd socket connect to %s failed!\n", argv[0], serv_optarg);
        nDPIsrvd_socket_free(&sock);
        return 1;
    }

    signal(SIGUSR1, sighandler);
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, sighandler);

    if (daemonize_with_pidfile(pidfile) != 0)
    {
        return 1;
    }
    openlog("nDPIsrvd-analyzed", LOG_CONS, LOG_DAEMON);

    if (nDPIsrvd_set_read_timeout(sock, 180, 0) != 0)
    {
        return 1;
    }

    enum nDPIsrvd_read_return read_ret = READ_OK;
    while (main_thread_shutdown == 0)
    {
        read_ret = nDPIsrvd_read(sock);
        if (errno == EINTR)
        {
            continue;
        }
        if (read_ret == READ_TIMEOUT)
        {
            printf("No data received during the last %llu second(s).\n",
                   (long long unsigned int)sock->read_timeout.tv_sec);
            continue;
        }
        if (read_ret != READ_OK)
        {
            break;
        }

        enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(sock);
        if (parse_ret != PARSE_NEED_MORE_DATA)
        {
            printf("Could not parse json string: %s\n", nDPIsrvd_enum_to_string(parse_ret));
            break;
        }
    }

    if (main_thread_shutdown == 0 && read_ret != READ_OK)
    {
        printf("Parse read %s\n", nDPIsrvd_enum_to_string(read_ret));
    }

    nDPIsrvd_socket_free(&sock);
    daemonize_shutdown(pidfile);
    closelog();

    return read_ret;
}
