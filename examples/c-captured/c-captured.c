#include <arpa/inet.h>
#include <errno.h>
#include <linux/limits.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <ndpi_typedefs.h>
#include <ndpi_api.h>

#include "nDPIsrvd.h"
#include "utarray.h"
#include "utils.h"

//#define VERBOSE
#define DEFAULT_DATADIR "/tmp/nDPId-captured"

struct packet_data
{
    nDPIsrvd_ull packet_ts_sec;
    nDPIsrvd_ull packet_ts_usec;
    nDPIsrvd_ull packet_len;
    int base64_packet_size;
    union
    {
        char * base64_packet;
        char const * base64_packet_const;
    };
};

struct flow_user_data
{
    uint8_t flow_new_seen;
    uint8_t detection_finished;
    uint8_t guessed;
    uint8_t detected;
    uint8_t risky;
    uint8_t midstream;
    nDPIsrvd_ull flow_datalink;
    nDPIsrvd_ull flow_max_packets;
    nDPIsrvd_ull flow_tot_l4_payload_len;
    UT_array * packets;
};

static struct nDPIsrvd_socket * sock = NULL;
static int main_thread_shutdown = 0;

static char * pidfile = NULL;
static char * serv_optarg = NULL;
static nDPIsrvd_ull pcap_filename_rotation = 0;
static time_t pcap_filename_last_rotation = 0;
static struct tm pcap_filename_last_rotation_tm = {};
static char * user = NULL;
static char * group = NULL;
static char * datadir = NULL;
static uint8_t process_guessed = 0;
static uint8_t process_undetected = 0;
static ndpi_risk process_risky = NDPI_NO_RISK;
static uint8_t process_midstream = 0;
static uint8_t ignore_empty_flows = 0;

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

static void packet_data_copy(void * dst, const void * src)
{
    struct packet_data * const pd_dst = (struct packet_data *)dst;
    struct packet_data const * const pd_src = (struct packet_data *)src;
    *pd_dst = *pd_src;
    if (pd_src->base64_packet != NULL && pd_src->base64_packet_size > 0)
    {
        pd_dst->base64_packet = strndup(pd_src->base64_packet, pd_src->base64_packet_size);
    }
    else
    {
        pd_dst->base64_packet = NULL;
        pd_dst->base64_packet_size = 0;
    }
}

static void packet_data_dtor(void * elt)
{
    struct packet_data * const pd_elt = (struct packet_data *)elt;
    if (pd_elt->base64_packet != NULL)
    {
        free(pd_elt->base64_packet);
        pd_elt->base64_packet = NULL;
        pd_elt->base64_packet_size = 0;
    }
}

static const UT_icd packet_data_icd = {sizeof(struct packet_data), NULL, packet_data_copy, packet_data_dtor};

static void set_ndpi_risk(ndpi_risk * const risk, nDPIsrvd_ull risk_to_add)
{
    if (risk_to_add == 0)
    {
        *risk = (ndpi_risk)-1;
    }
    else
    {
        *risk |= 1ull << --risk_to_add;
    }
}

static void unset_ndpi_risk(ndpi_risk * const risk, nDPIsrvd_ull risk_to_del)
{
    if (risk_to_del == 0)
    {
        *risk = 0;
    }
    else
    {
        *risk &= ~(1ull << --risk_to_del);
    }
}

static int has_ndpi_risk(ndpi_risk * const risk, nDPIsrvd_ull risk_to_check)
{
    return (*risk & (1ull << --risk_to_check)) != 0;
}

static char * generate_pcap_filename(struct nDPIsrvd_flow const * const flow,
                                     struct flow_user_data const * const flow_user,
                                     char * const dest,
                                     size_t size)
{
    char appendix[32] = {};

    if (pcap_filename_rotation > 0)
    {
        time_t current_time = time(NULL);

        if (current_time >= pcap_filename_last_rotation + (time_t)pcap_filename_rotation)
        {
            pcap_filename_last_rotation = current_time;
            if (localtime_r(&pcap_filename_last_rotation, &pcap_filename_last_rotation_tm) == NULL)
            {
                return NULL;
            }
        }

        if (strftime(appendix, sizeof(appendix), "%d_%m_%y-%H_%M_%S", &pcap_filename_last_rotation_tm) == 0)
        {
            return NULL;
        }
    }
    else

    {
        if (snprintf(appendix, sizeof(appendix), "%llu", flow->id_as_ull) <= 0)
        {
            return NULL;
        }
    }

    if (flow_user->guessed != 0 || flow_user->detected == 0 || flow_user->risky != 0 || flow_user->midstream != 0)
    {
        char const * flow_type = NULL;

        if (flow_user->midstream != 0)
        {
            flow_type = "midstream";
        }
        else if (flow_user->guessed != 0)
        {
            flow_type = "guessed";
        }
        else if (flow_user->detected == 0)
        {
            flow_type = "undetected";
        }
        else if (flow_user->risky != 0)
        {
            flow_type = "risky";
        }
        else
        {
            flow_type = "unknown-type";
        }

        int ret = snprintf(dest, size, "%s/flow-%s-%s.pcap", datadir, flow_type, appendix);
        if (ret <= 0 || (size_t)ret > size)
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }

    return dest;
}

static int packet_write_pcap_file(UT_array const * const pd_array, int pkt_datalink, char const * const filename)
{
    size_t const max_packet_len = 65535;

    if (pd_array->icd.copy != packet_data_copy || pd_array->icd.dtor != packet_data_dtor)
    {
        return 1;
    }

    if (utarray_len(pd_array) == 0)
    {
        syslog(LOG_DAEMON, "no packets received via json, can not dump anything to pcap");
        return 0;
    }

    pcap_t * p = pcap_open_dead(pkt_datalink, max_packet_len);
    if (p == NULL)
    {
        return 1;
    }

    pcap_dumper_t * pd;
    if (access(filename, F_OK) == 0)
    {
        pd = pcap_dump_open_append(p, filename);
    }
    else
    {
        pd = pcap_dump_open(p, filename);
    }

    if (pd == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR, "pcap error %s", pcap_geterr(p));
        pcap_close(p);
        return 1;
    }

    struct packet_data * pd_elt = (struct packet_data *)utarray_front(pd_array);
    do
    {
        if (pd_elt == NULL)
        {
            break;
        }

        unsigned char pkt_buf[max_packet_len];
        size_t pkt_buf_len = sizeof(pkt_buf);
        if (nDPIsrvd_base64decode(pd_elt->base64_packet, pd_elt->base64_packet_size, pkt_buf, &pkt_buf_len) != 0 ||
            pkt_buf_len == 0)
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "packet base64 decode failed (%d bytes): %s",
                   pd_elt->base64_packet_size,
                   pd_elt->base64_packet);
        }
        else
        {
            struct pcap_pkthdr phdr;
            phdr.ts.tv_sec = pd_elt->packet_ts_sec;
            phdr.ts.tv_usec = pd_elt->packet_ts_usec;
            phdr.caplen = pkt_buf_len;
            phdr.len = pkt_buf_len;
            pcap_dump((unsigned char *)pd, &phdr, pkt_buf);
        }
    } while ((pd_elt = (struct packet_data *)utarray_next(pd_array, pd_elt)) != NULL);

    pcap_dump_close(pd);
    pcap_close(p);

    return 0;
}

#ifdef VERBOSE
static void packet_data_print(UT_array const * const pd_array)
{
    if (pd_array->icd.copy != packet_data_copy || pd_array->icd.dtor != packet_data_dtor)
    {
        return;
    }

    printf("packet-data array size(): %u\n", pd_array->n);
    struct packet_data * pd_elt = (struct packet_data *)utarray_front(pd_array);
    do
    {
        if (pd_elt == NULL)
        {
            break;
        }
        printf("\tpacket-data base64 length: %d\n", pd_elt->base64_packet_size);
    } while ((pd_elt = (struct packet_data *)utarray_next(pd_array, pd_elt)) != NULL);
}
#else
#define packet_data_print(pd_array)
#endif

static enum nDPIsrvd_conversion_return perror_ull(enum nDPIsrvd_conversion_return retval, char const * const prefix)
{
    switch (retval)
    {
        case CONVERSION_OK:
            break;

        case CONVERISON_KEY_NOT_FOUND:
            syslog(LOG_DAEMON | LOG_ERR, "%s: Key not found.", prefix);
            break;
        case CONVERSION_NOT_A_NUMBER:
            syslog(LOG_DAEMON | LOG_ERR, "%s: Not a valid number.", prefix);
            break;
        case CONVERSION_RANGE_EXCEEDED:
            syslog(LOG_DAEMON | LOG_ERR, "%s: Number too large.", prefix);
            break;

        default:
            syslog(LOG_DAEMON | LOG_ERR, "Internal error, invalid conversion return value.");
            break;
    }

    return retval;
}

static enum nDPIsrvd_callback_return captured_json_callback(struct nDPIsrvd_socket * const sock,
                                                            struct nDPIsrvd_instance * const instance,
                                                            struct nDPIsrvd_thread_data * const thread_data,
                                                            struct nDPIsrvd_flow * const flow)
{
    (void)instance;
    (void)thread_data;

    if (flow == NULL)
    {
        return CALLBACK_OK; // We do not care for non-flow events for NOW except for packet-flow events.
    }

    struct flow_user_data * const flow_user = (struct flow_user_data *)flow->flow_user_data;

    if (flow_user == NULL || flow_user->detection_finished != 0)
    {
        return CALLBACK_OK;
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, TOKEN_GET_SZ(sock, "packet_event_name"), "packet-flow") != 0)
    {
        struct nDPIsrvd_json_token const * const pkt = TOKEN_GET_SZ(sock, "pkt");
        if (pkt == NULL)
        {
            syslog(LOG_DAEMON | LOG_ERR, "%s", "No packet data available.");
            syslog(LOG_DAEMON | LOG_ERR, "JSON String: '%.*s'", nDPIsrvd_json_buffer_length(sock), nDPIsrvd_json_buffer_string(sock));
            return CALLBACK_OK;
        }
        if (flow_user->packets == NULL)
        {
            utarray_new(flow_user->packets, &packet_data_icd);
        }
        if (flow_user->packets == NULL)
        {
            syslog(LOG_DAEMON | LOG_ERR, "%s", "Memory allocation for captured packets failed.");
            return CALLBACK_ERROR;
        }

        nDPIsrvd_ull thread_ts_usec = 0ull;
        perror_ull(TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "thread_ts_usec"), &thread_ts_usec), "thread_ts_usec");

        nDPIsrvd_ull pkt_len = 0ull;
        perror_ull(TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "pkt_caplen"), &pkt_len), "pkt_caplen");

        nDPIsrvd_ull pkt_l4_len = 0ull;
        perror_ull(TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "pkt_l4_len"), &pkt_l4_len), "pkt_l4_len");

        nDPIsrvd_ull pkt_l4_offset = 0ull;
        perror_ull(TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "pkt_l4_offset"), &pkt_l4_offset), "pkt_l4_offset");

        struct packet_data pd = {.packet_ts_sec = thread_ts_usec / (1000 * 1000),
                                 .packet_ts_usec = (thread_ts_usec % (1000 * 1000)),
                                 .packet_len = pkt_len,
                                 .base64_packet_size = nDPIsrvd_get_token_size(sock, pkt),
                                 .base64_packet_const = nDPIsrvd_get_token_value(sock, pkt)};
        utarray_push_back(flow_user->packets, &pd);
    }

    {
        struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");

        if (flow_event_name != NULL)
        {
            nDPIsrvd_ull nmb = 0;

            perror_ull(TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_src_tot_l4_payload_len"), &nmb),
                       "flow_src_tot_l4_payload_len");
            flow_user->flow_tot_l4_payload_len += nmb;

            nmb = 0;

            perror_ull(TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_dst_tot_l4_payload_len"), &nmb),
                       "flow_dst_tot_l4_payload_len");
            flow_user->flow_tot_l4_payload_len += nmb;
        }

        if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "new") != 0)
        {
            flow_user->flow_new_seen = 1;
            perror_ull(TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_datalink"), &flow_user->flow_datalink),
                       "flow_datalink");
            perror_ull(TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_max_packets"), &flow_user->flow_max_packets),
                       "flow_max_packets");
            if (TOKEN_VALUE_EQUALS_SZ(sock, TOKEN_GET_SZ(sock, "midstream"), "1") != 0)
            {
                flow_user->midstream = 1;
            }

            return CALLBACK_OK;
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "guessed") != 0)
        {
            flow_user->guessed = 1;
            flow_user->detection_finished = 1;
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "not-detected") != 0)
        {
            flow_user->detected = 0;
            flow_user->detection_finished = 1;
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detected") != 0 ||
                 TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detection-update") != 0)
        {
            struct nDPIsrvd_json_token const * const flow_risk = TOKEN_GET_SZ(sock, "ndpi", "flow_risk");
            struct nDPIsrvd_json_token const * current = NULL;
            int next_child_index = -1;

            flow_user->detected = 1;
            flow_user->detection_finished = 1;

            if (flow_risk != NULL)
            {
                while ((current = nDPIsrvd_get_next_token(sock, flow_risk, &next_child_index)) != NULL)
                {
                    nDPIsrvd_ull numeric_risk_value = (nDPIsrvd_ull)-1;

                    if (str_value_to_ull(TOKEN_GET_KEY(sock, current, NULL), &numeric_risk_value) == CONVERSION_OK &&
                        numeric_risk_value < NDPI_MAX_RISK && has_ndpi_risk(&process_risky, numeric_risk_value) != 0)
                    {
                        flow_user->risky = 1;
                    }
                }
            }
        }

        if (flow_user->flow_new_seen == 0)
        {
            return CALLBACK_OK;
        }

        if (flow_user->packets == NULL || flow_user->flow_max_packets == 0 || utarray_len(flow_user->packets) == 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "flow %llu: No packets captured.", flow->id_as_ull);
            return CALLBACK_OK;
        }

        if (flow_user->detection_finished != 0 &&
            ((flow_user->guessed != 0 && process_guessed != 0) ||
             (flow_user->detected == 0 && process_undetected != 0) || (flow_user->risky != 0 && process_risky != 0) ||
             (flow_user->midstream != 0 && process_midstream != 0)))
        {
            packet_data_print(flow_user->packets);
            if (ignore_empty_flows == 0 || flow_user->flow_tot_l4_payload_len > 0)
            {
                char pcap_filename[PATH_MAX];
                if (generate_pcap_filename(flow, flow_user, pcap_filename, sizeof(pcap_filename)) == NULL)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "%s", "Internal error. Could not generate PCAP filename, exit ..");
                    return CALLBACK_ERROR;
                }
#ifdef VERBOSE
                printf("flow %llu saved to %s\n", flow->id_as_ull, pcap_filename);
#endif
                if (packet_write_pcap_file(flow_user->packets, flow_user->flow_datalink, pcap_filename) != 0)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Could not packet data to pcap file %s", pcap_filename);
                    return CALLBACK_ERROR;
                }
            }

            utarray_free(flow_user->packets);
            flow_user->packets = NULL;
        }
    }

    return CALLBACK_OK;
}

static void nDPIsrvd_write_flow_info_cb(struct nDPIsrvd_socket const * sock,
                                        struct nDPIsrvd_instance const * instance,
                                        struct nDPIsrvd_thread_data const * thread_data,
                                        struct nDPIsrvd_flow const * flow,
                                        void * user_data)
{
    (void)sock;
    (void)instance;
    (void)thread_data;
    (void)user_data;

    struct flow_user_data const * const flow_user = (struct flow_user_data const *)flow->flow_user_data;

    fprintf(stderr,
            "[Flow %4llu][ptr: "
#ifdef __LP64__
            "0x%016llx"
#else
            "0x%08lx"
#endif
            "][last-seen: %13llu][new-seen: %u][finished: %u][detected: %u][risky: "
            "%u][total-L4-payload-length: "
            "%4llu][packets-captured: %u]\n",
            flow->id_as_ull,
#ifdef __LP64__
            (unsigned long long int)flow,
#else
            (unsigned long int)flow,
#endif
            flow->last_seen,
            flow_user->flow_new_seen,
            flow_user->detection_finished,
            flow_user->detected,
            flow_user->risky,
            flow_user->flow_tot_l4_payload_len,
            flow_user->packets != NULL ? utarray_len(flow_user->packets) : 0);

    syslog(LOG_DAEMON,
           "[Flow %4llu][ptr: "
#ifdef __LP64__
           "0x%016llx"
#else
           "0x%08lx"
#endif
           "][last-seen: %13llu][new-seen: %u][finished: %u][detected: %u][risky: "
           "%u][total-L4-payload-length: "
           "%4llu][packets-captured: %u]",
           flow->id_as_ull,
#ifdef __LP64__
           (unsigned long long int)flow,
#else
           (unsigned long int)flow,
#endif
           flow->last_seen,
           flow_user->flow_new_seen,
           flow_user->detection_finished,
           flow_user->detected,
           flow_user->risky,
           flow_user->flow_tot_l4_payload_len,
           flow_user->packets != NULL ? utarray_len(flow_user->packets) : 0);
}

static void sighandler(int signum)
{
    if (signum == SIGUSR1)
    {
        nDPIsrvd_flow_info(sock, nDPIsrvd_write_flow_info_cb, NULL);
    }
    else if (main_thread_shutdown == 0)
    {
        main_thread_shutdown = 1;
    }
}

static void captured_flow_cleanup_callback(struct nDPIsrvd_socket * const sock,
                                           struct nDPIsrvd_instance * const instance,
                                           struct nDPIsrvd_thread_data * const thread_data,
                                           struct nDPIsrvd_flow * const flow,
                                           enum nDPIsrvd_cleanup_reason reason)
{
    (void)sock;
    (void)instance;
    (void)thread_data;
    (void)reason;

    struct flow_user_data * const ud = (struct flow_user_data *)flow->flow_user_data;
    if (ud != NULL && ud->packets != NULL)
    {
        utarray_free(ud->packets);
        ud->packets = NULL;
    }
}

static void print_usage(char const * const arg0)
{
    static char const usage[] =
        "Usage: %s "
        "[-d] [-p pidfile] [-s host] [-r rotate-every-n-seconds]\n"
        "\t  \t[-u user] [-g group] [-D dir] [-G] [-U] [-R risk] [-M]\n\n"
        "\t-d\tForking into background after initialization.\n"
        "\t-p\tWrite the daemon PID to the given file path.\n"
        "\t-s\tDestination where nDPIsrvd is listening on.\n"
        "\t  \tCan be either a path to UNIX socket or an IPv4/TCP-Port IPv6/TCP-Port tuple.\n"
        "\t-r\tRotate PCAP files every n seconds\n"
        "\t-u\tChange user.\n"
        "\t-g\tChange group.\n"
        "\t-D\tDatadir - Where to store PCAP files.\n"
        "\t-G\tGuessed - Dump guessed flows to a PCAP file.\n"
        "\t-U\tUndetected - Dump undetected flows to a PCAP file.\n"
        "\t-R\tRisky - Dump risky flows to a PCAP file. See additional help below.\n"
        "\t-M\tMidstream - Dump midstream flows to a PCAP file.\n"
        "\t-E\tEmpty - Ignore flows w/o any layer 4 payload\n\n"
        "\tPossible options for `-R' (can be specified multiple times, processed from left to right, ~ disables a "
        "risk):\n"
        "\t  \tExample: -R0 -R~15 would enable all risks except risk with id 15\n";

    fprintf(stderr, usage, arg0);
#ifndef LIBNDPI_STATIC
    fprintf(stderr, "\t\t%d - %s\n", 0, "Capture all risks");
#else
    fprintf(stderr, "\t\t%d - %s\n\t\t", 0, "Capture all risks");
#endif
    for (int risk = NDPI_NO_RISK + 1; risk < NDPI_MAX_RISK; ++risk)
    {
#ifndef LIBNDPI_STATIC
        fprintf(stderr, "\t\t%d - %s%s", risk, ndpi_risk2str(risk), (risk == NDPI_MAX_RISK - 1 ? "\n\n" : "\n"));
#else
        fprintf(stderr, "%d%s", risk, (risk == NDPI_MAX_RISK - 1 ? "\n" : ","));
#endif
    }
}

static int parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "hdp:s:r:u:g:D:GUR:ME")) != -1)
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
            case 'r':
                if (perror_ull(str_value_to_ull(optarg, &pcap_filename_rotation), "pcap_filename_rotation") !=
                    CONVERSION_OK)
                {
                    fprintf(stderr, "%s: Argument for `-r' is not a number: %s\n", argv[0], optarg);
                    return 1;
                }
                break;
            case 'u':
                free(user);
                user = strdup(optarg);
                break;
            case 'g':
                free(group);
                group = strdup(optarg);
                break;
            case 'D':
                free(datadir);
                datadir = strdup(optarg);
                break;
            case 'G':
                process_guessed = 1;
                break;
            case 'U':
                process_undetected = 1;
                break;
            case 'R':
            {
                char * value = (optarg[0] == '~' ? optarg + 1 : optarg);
                nDPIsrvd_ull risk;
                if (perror_ull(str_value_to_ull(value, &risk), "process_risky") != CONVERSION_OK)
                {
                    fprintf(stderr, "%s: Argument for `-R' is not a number: %s\n", argv[0], optarg);
                    return 1;
                }
                if (risk >= NDPI_MAX_RISK)
                {
                    fprintf(stderr, "%s: Invalid risk set: %s\n", argv[0], optarg);
                    return 1;
                }
                if (optarg[0] == '~')
                {
                    unset_ndpi_risk(&process_risky, risk);
                }
                else
                {
                    set_ndpi_risk(&process_risky, risk);
                }
                break;
            }
            case 'M':
                process_midstream = 1;
                break;
            case 'E':
                ignore_empty_flows = 1;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
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

    if (datadir == NULL)
    {
        datadir = strdup(DEFAULT_DATADIR);
    }

    if (process_guessed == 0 && process_undetected == 0 && process_risky == 0 && process_midstream == 0)
    {
        fprintf(stderr, "%s: Nothing to capture. Use at least one of -G / -U / -R / -M flags.\n", argv[0]);
        return 1;
    }

    if (optind < argc)
    {
        fprintf(stderr, "Unexpected argument after options\n\n");
        print_usage(argv[0]);
        return 1;
    }

    errno = 0;
    if (datadir[0] != '/')
    {
        fprintf(stderr,
                "%s: PCAP capture directory must be absolut i.e. starting with `/', path given: `%s'\n",
                argv[0],
                datadir);
        return 1;
    }
    if (mkdir(datadir, S_IRWXU) != 0 && errno != EEXIST)
    {
        fprintf(stderr, "%s: Could not create directory %s: %s\n", argv[0], datadir, strerror(errno));
        return 1;
    }

    return 0;
}

static int mainloop(void)
{
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
            syslog(LOG_DAEMON,
                   "No data received during the last %llu second(s).\n",
                   (long long unsigned int)sock->read_timeout.tv_sec);
            continue;
        }
        if (read_ret != READ_OK)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Could not read from socket: %s", nDPIsrvd_enum_to_string(read_ret));
            break;
        }

        enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(sock);
        if (parse_ret != PARSE_NEED_MORE_DATA)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Could not parse json string: %s", nDPIsrvd_enum_to_string(parse_ret));
            break;
        }
    }

    if (main_thread_shutdown == 0 && read_ret != READ_OK)
    {
        return 1;
    }

    return 0;
}

int main(int argc, char ** argv)
{
    sock = nDPIsrvd_socket_init(
        0, 0, 0, sizeof(struct flow_user_data), captured_json_callback, NULL, captured_flow_cleanup_callback);
    if (sock == NULL)
    {
        fprintf(stderr, "%s: nDPIsrvd socket memory allocation failed!\n", argv[0]);
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
    openlog("nDPIsrvd-captured", LOG_CONS, LOG_DAEMON);

    errno = 0;
    if (user != NULL && change_user_group(user, group, pidfile, datadir /* :D */, NULL) != 0)
    {
        if (errno != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Change user/group failed: %s", strerror(errno));
        }
        else
        {
            syslog(LOG_DAEMON | LOG_ERR, "Change user/group failed.");
        }
        return 1;
    }
    chmod(datadir, S_IRWXU);

    int retval = mainloop();

    nDPIsrvd_socket_free(&sock);
    daemonize_shutdown(pidfile);
    closelog();

    return retval;
}
