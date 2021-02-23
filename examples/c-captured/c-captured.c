#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "nDPIsrvd.h"
#include "utarray.h"

//#define VERBOSE

struct packet_data
{
    nDPIsrvd_ull packet_ts_sec;
    nDPIsrvd_ull packet_ts_usec;
    nDPIsrvd_ull packet_len;
    int base64_packet_size;
    union {
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
    nDPIsrvd_ull flow_datalink;
    nDPIsrvd_ull flow_max_packets;
    UT_array * packets;
};

struct nDPIsrvd_socket * sock = NULL;
static int main_thread_shutdown = 0;

static int daemonize = 0;
static char * pidfile = NULL;
static char * serv_optarg = NULL;
#ifdef pcap_dump_open_append
static time_t pcap_filename_rotation = 600;
static time_t pcap_filename_last_rotation = 0;
static struct tm pcap_filename_last_rotation_tm = {};
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

static char * generate_pcap_filename(struct nDPIsrvd_flow const * const flow,
                                     struct flow_user_data const * const flow_user,
                                     char * const dest,
                                     size_t size)
{
    char appendix[32] = {};

#ifdef pcap_dump_open_append
    if (pcap_filename_rotation > 0)
    {
        time_t current_time = time(NULL);

        if (current_time >= pcap_filename_last_rotation + pcap_filename_rotation)
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
    } else
#endif
    {
        if (snprintf(appendix, sizeof(appendix), "%llu", flow->id_as_ull) <= 0)
        {
            return NULL;
        }
    }

    if (flow_user->guessed != 0 || flow_user->detected == 0)
    {
        int ret =
            snprintf(dest, size, "flow-%s-%s.pcap",
                     (flow_user->guessed != 0 ? "guessed" : "undetected"),
                     appendix);
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
        printf("no packets received via json, can not dump anything to pcap\n");
        return 0;
    }

    pcap_t * p = pcap_open_dead(pkt_datalink, max_packet_len);
    if (p == NULL)
    {
        return 1;
    }

#ifdef pcap_dump_open_append
    pcap_dumper_t * pd = pcap_dump_open_append(p, filename);
#else
    pcap_dumper_t * pd = pcap_dump_open(p, filename);
#endif
    if (pd == NULL)
    {
        fprintf(stderr, "pcap error %s\n", pcap_geterr(p));
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
            printf("packet base64 decode failed (%d bytes): %s\n", pd_elt->base64_packet_size, pd_elt->base64_packet);
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

static void perror_ull(enum nDPIsrvd_conversion_return retval, char const * const prefix)
{
    switch (retval)
    {
        case CONVERSION_OK:
            return;

        case CONVERISON_KEY_NOT_FOUND:
            fprintf(stderr, "%s `: Key not found.\n", prefix);
            break;
        case CONVERSION_NOT_A_NUMBER:
            fprintf(stderr, "%s: Not a valid number.\n", prefix);
            break;
        case CONVERSION_RANGE_EXCEEDED:
            fprintf(stderr, "%s: Number too large.\n", prefix);
            break;

        default:
            fprintf(stderr, "Internal error, invalid conversion return value.\n");
    }
}

static enum nDPIsrvd_callback_return captured_json_callback(struct nDPIsrvd_socket * const sock,
                                                            struct nDPIsrvd_flow * const flow)
{
    struct flow_user_data * const flow_user = (struct flow_user_data *)flow->flow_user_data;

#ifdef VERBOSE
    struct nDPIsrvd_json_token * current_token = NULL;
    struct nDPIsrvd_json_token * jtmp = NULL;

    HASH_ITER(hh, sock->json.token_table, current_token, jtmp)
    {
        if (current_token->value != NULL)
        {
            printf("[%.*s : %.*s] ",
                   current_token->key_length, current_token->key,
                   current_token->value_length, current_token->value);
        }
    }
    printf("EoF\n");
#endif

    if (flow_user == NULL || flow_user->detection_finished != 0)
    {
        return CALLBACK_OK;
    }

    if (TOKEN_VALUE_EQUALS_SZ(TOKEN_GET_SZ(sock, "packet_event_name"), "packet-flow") != 0)
    {
        struct nDPIsrvd_json_token const * const pkt = TOKEN_GET_SZ(sock, "pkt");
        if (pkt == NULL)
        {
            return CALLBACK_ERROR;
        }
        if (flow_user->packets == NULL)
        {
            utarray_new(flow_user->packets, &packet_data_icd);
        }
        if (flow_user->packets == NULL)
        {
            return CALLBACK_ERROR;
        }

        nDPIsrvd_ull pkt_ts_sec = 0ull;
        perror_ull(TOKEN_VALUE_TO_ULL(TOKEN_GET_SZ(sock, "pkt_ts_sec"), &pkt_ts_sec), "pkt_ts_sec");

        nDPIsrvd_ull pkt_ts_usec = 0ull;
        perror_ull(TOKEN_VALUE_TO_ULL(TOKEN_GET_SZ(sock, "pkt_ts_usec"), &pkt_ts_usec), "pkt_ts_usec");

        nDPIsrvd_ull pkt_len = 0ull;
        perror_ull(TOKEN_VALUE_TO_ULL(TOKEN_GET_SZ(sock, "pkt_len"), &pkt_len), "pkt_len");

        nDPIsrvd_ull pkt_l4_len = 0ull;
        perror_ull(TOKEN_VALUE_TO_ULL(TOKEN_GET_SZ(sock, "pkt_l4_len"), &pkt_l4_len), "pkt_l4_len");

        nDPIsrvd_ull pkt_l4_offset = 0ull;
        perror_ull(TOKEN_VALUE_TO_ULL(TOKEN_GET_SZ(sock, "pkt_l4_offset"), &pkt_l4_offset), "pkt_l4_offset");

        struct packet_data pd = {
            .packet_ts_sec = pkt_ts_sec,
            .packet_ts_usec = pkt_ts_usec,
            .packet_len = pkt_len,
            .base64_packet_size = pkt->value_length,
            .base64_packet_const = pkt->value
        };
        utarray_push_back(flow_user->packets, &pd);
    }

    {
        struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");
        if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "new") != 0)
        {
            flow_user->flow_new_seen = 1;
            perror_ull(TOKEN_VALUE_TO_ULL(TOKEN_GET_SZ(sock, "flow_datalink"), &flow_user->flow_datalink), "flow_datalink");
            perror_ull(TOKEN_VALUE_TO_ULL(TOKEN_GET_SZ(sock, "flow_max_packets"), &flow_user->flow_max_packets), "flow_max_packets");

            return CALLBACK_OK;
        } else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "guessed") != 0)
        {
            flow_user->guessed = 1;
            flow_user->detection_finished = 1;
        } else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "not-detected") != 0)
        {
            flow_user->detected = 0;
            flow_user->detection_finished = 1;
        } else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "detected") != 0)
        {
            flow_user->detected = 1;
            flow_user->detection_finished = 1;
            if (flow_user->packets != NULL)
            {
                utarray_free(flow_user->packets);
                flow_user->packets = NULL;
            }

            return CALLBACK_OK;
        }

        if (flow_user->flow_new_seen == 0)
        {
            return CALLBACK_OK;
        }

        if (flow_user->packets == NULL || flow_user->flow_max_packets == 0 || utarray_len(flow_user->packets) == 0)
        {
            printf("flow %llu: No packets captured.\n", flow->id_as_ull);

            return CALLBACK_OK;
        }

        if (flow_user->detection_finished != 0 &&
            (flow_user->guessed != 0 || flow_user->detected == 0))
        {
            packet_data_print(flow_user->packets);
            {
                char pcap_filename[64];
                if (generate_pcap_filename(flow, flow_user, pcap_filename, sizeof(pcap_filename)) == NULL)
                {
                    fprintf(stderr, "%s\n", "Internal error, exit ..");
                    return CALLBACK_ERROR;
                }
                printf("flow %llu: save to %s\n", flow->id_as_ull, pcap_filename);
                if (packet_write_pcap_file(flow_user->packets, flow_user->flow_datalink, pcap_filename) != 0)
                {
                    return CALLBACK_ERROR;
                }
            }

            utarray_free(flow_user->packets);
            flow_user->packets = NULL;
        }
    }

    return CALLBACK_OK;
}

static void sighandler(int signum)
{
    (void)signum;

    if (main_thread_shutdown == 0)
    {
        main_thread_shutdown = 1;
    }
}

static void captured_flow_end_callback(struct nDPIsrvd_socket * const sock, struct nDPIsrvd_flow * const flow)
{
    (void)sock;

    struct flow_user_data * const ud = (struct flow_user_data *)flow->flow_user_data;
    if (ud != NULL && ud->packets != NULL)
    {
        utarray_free(ud->packets);
        ud->packets = NULL;
    }
}

static int parse_options(int argc, char ** argv)
{
    int opt;

    static char const usage[] =
        "Usage: %s "
        "[-d] [-p pidfile] [-s host] [-R rotate-every-n-seconds] [-g] [-u]\n";

    while ((opt = getopt(argc, argv, "hdp:s:R:g:u:")) != -1)
    {
        switch (opt)
        {
            case 'd':
                daemonize = 1;
                break;
            case 'p':
                break;
            case 's':
                free(serv_optarg);
                serv_optarg = strdup(optarg);
                break;
            case 'R':
                break;
            case 'g':
                break;
            case 'u':
                break;
            default:
                fprintf(stderr, usage, argv[0]);
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

    if (optind < argc)
    {
        fprintf(stderr, "Unexpected argument after options\n\n");
        fprintf(stderr, usage, argv[0]);
        return 1;
    }

    return 0;
}

int main(int argc, char ** argv)
{
    sock = nDPIsrvd_init(0, sizeof(struct flow_user_data), captured_json_callback, captured_flow_end_callback);
    if (sock == NULL)
    {
        fprintf(stderr, "%s: nDPIsrvd socket memory allocation failed!\n", argv[0]);
        return 1;
    }

    if (parse_options(argc, argv) != 0)
    {
        fprintf(stderr, "%s: Could not parse command line arguments.\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, sighandler);

    printf("Recv buffer size: %u\n", NETWORK_BUFFER_MAX_SIZE);
    printf("Connecting to `%s'..\n", serv_optarg);
    enum nDPIsrvd_connect_return connect_ret = nDPIsrvd_connect(sock);

    if (connect_ret != CONNECT_OK)
    {
        fprintf(stderr, "%s: nDPIsrvd socket connect to %s failed!\n", argv[0], serv_optarg);
        nDPIsrvd_free(&sock);
        return 1;
    }

    while (main_thread_shutdown == 0)
    {
        errno = 0;
        enum nDPIsrvd_read_return read_ret = nDPIsrvd_read(sock);
        if (read_ret != READ_OK)
        {
            fprintf(stderr, "%s: nDPIsrvd read failed with: %s\n", argv[0], nDPIsrvd_enum_to_string(read_ret));
            break;
        }

        enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse(sock);
        if (parse_ret != PARSE_OK)
        {
            fprintf(stderr, "%s: nDPIsrvd parse failed with: %s\n", argv[0], nDPIsrvd_enum_to_string(parse_ret));
            break;
        }
    }

    nDPIsrvd_free(&sock);

    return 0;
}
