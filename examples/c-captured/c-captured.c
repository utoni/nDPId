#include <arpa/inet.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "nDPIsrvd.h"
#include "utarray.h"

//#define VERBOSE

struct packet_data
{
    uint64_t packet_ts;
    size_t packet_len;
    size_t base64_packet_size;
    union {
        char * base64_packet;
        char const * base64_packet_const;
    };
};

struct flow_user_data
{
    uint8_t guessed;
    uint8_t detected;
    int pkt_datalink;
    UT_array * packets;
};

struct callback_tmp_data
{
    uint8_t guessed;
    uint8_t detected;
    int pkt_datalink;

    uint8_t flow_end_or_idle;
    uint8_t is_packet_flow;

    struct packet_data pkt;
};

struct callback_user_data
{
    struct nDPIsrvd_flow * flow_table;
    struct callback_tmp_data tmp;
};

struct nDPIsrvd_socket * sock = NULL;
static int main_thread_shutdown = 0;
static char const serv_listen_path[] = DISTRIBUTOR_UNIX_SOCKET;
static char const serv_listen_addr[INET_ADDRSTRLEN] = DISTRIBUTOR_HOST;
static uint16_t const serv_listen_port = DISTRIBUTOR_PORT;

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
    if (flow_user->guessed != 0 || flow_user->detected == 0)
    {
        int ret = snprintf(dest, size, "flow-%s-%s.pcap", (flow_user->guessed != 0 ? "guessed" : "undetected"), flow->id);
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
    pcap_dumper_t * pd = pcap_dump_open(p, filename);
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
            printf("packet base64 decode failed (%zu bytes): %s\n", pd_elt->base64_packet_size, pd_elt->base64_packet);
        }
        else
        {
            struct pcap_pkthdr phdr;
            phdr.ts.tv_sec = 0;
            phdr.ts.tv_usec = 0;
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
        printf("\tpacket-data base64 length: %zu\n", pd_elt->base64_packet_size);
    } while ((pd_elt = (struct packet_data *)utarray_next(pd_array, pd_elt)) != NULL);
}
#else
#define packet_data_print(pd_array)
#endif

enum nDPIsrvd_callback_return nDPIsrvd_json_callback(struct nDPIsrvd_socket * const sock, void * const user_data)
{
    struct callback_user_data * const cb_user_data = (struct callback_user_data *)user_data;
    struct nDPIsrvd_flow * flow = nDPIsrvd_get_flow(sock, &cb_user_data->flow_table, sizeof(struct flow_user_data));
    struct flow_user_data * flow_user = (struct flow_user_data *)(flow != NULL ? flow->user_data : NULL);

    if (token_is_start(sock) == 1) /* Start of a JSON string. */
    {
        memset(&cb_user_data->tmp, 0, sizeof(cb_user_data->tmp));
        cb_user_data->tmp.pkt_datalink = -1;
#ifdef VERBOSE
        printf("JSON ");
#endif
        return CALLBACK_OK;
    }
    else if (token_is_end(sock) == 1) /* End of a JSON string. */
    {
        if (flow != NULL)
        {
            if (cb_user_data->tmp.is_packet_flow == 1)
            {
                if (flow_user->packets == NULL)
                {
                    utarray_new(flow_user->packets, &packet_data_icd);
                }
                if (flow_user->packets != NULL)
                {
                    utarray_push_back(flow_user->packets, &cb_user_data->tmp.pkt);
                }
                flow_user->pkt_datalink = cb_user_data->tmp.pkt_datalink;
            } else {
                if (cb_user_data->tmp.guessed != 0) {
                    flow_user->guessed = cb_user_data->tmp.guessed;
                }
                if (cb_user_data->tmp.detected != 0) {
                    flow_user->detected = cb_user_data->tmp.detected;
                }
            }
            if (cb_user_data->tmp.flow_end_or_idle == 1 &&
                (flow_user->guessed != 0 || flow_user->detected == 0))
            {
                if (flow_user->packets != NULL)
                {
                    packet_data_print(flow_user->packets);
                    char pcap_filename[64];
                    if (generate_pcap_filename(flow, flow_user, pcap_filename, sizeof(pcap_filename)) == NULL)
                    {
                        fprintf(stderr, "%s\n", "Internal error, exit ..");
                        return CALLBACK_ERROR;
                    }
                    printf("dump flow with id %s to %s\n", flow->id, pcap_filename);
                    if (packet_write_pcap_file(flow_user->packets, flow_user->pkt_datalink, pcap_filename) != 0)
                    {
                        return CALLBACK_ERROR;
                    }
                    utarray_free(flow_user->packets);
                    flow_user->packets = NULL;
                }
            }
#ifdef VERBOSE
            printf("GUESSED: %u, DETECTED: %u ", flow_user->guessed, flow_user->detected);
#endif
        }
#ifdef VERBOSE
        printf("EoF\n");
#endif
        return CALLBACK_OK;
    }

    if (token_is_key_value_pair(sock) != 1)
    {
        fprintf(stderr, "%s\n", "Internal error, exit ..");
        return CALLBACK_ERROR;
    }

    if (key_equals(sock, "packet_event_name") == 1)
    {
        if (value_equals(sock, "packet-flow") == 1)
        {
            cb_user_data->tmp.is_packet_flow = 1;
        }
    }
    else if (key_equals(sock, "pkt") == 1)
    {
        cb_user_data->tmp.pkt.base64_packet_const = sock->jsmn.key_value.value;
        cb_user_data->tmp.pkt.base64_packet_size = sock->jsmn.key_value.value_length;
    }
    else if (key_equals(sock, "pkt_ts") == 1)
    {
        char * endptr = NULL;
        unsigned long long int value = strtoull(sock->jsmn.key_value.value, &endptr, 10);
        if (sock->jsmn.key_value.value == endptr)
        {
            fprintf(stderr,
                    "pkt_ts `%.*s': Value `%.*s' is not a valid number.\n",
                    sock->jsmn.key_value.key_length,
                    sock->jsmn.key_value.key,
                    sock->jsmn.key_value.value_length,
                    sock->jsmn.key_value.value);
            return CALLBACK_ERROR;
        }
        if (errno == ERANGE)
        {
            fprintf(stderr,
                    "pkt_ts `%.*s': Number too large.\n",
                    sock->jsmn.key_value.key_length,
                    sock->jsmn.key_value.key);
            return CALLBACK_ERROR;
        }
        cb_user_data->tmp.pkt.packet_ts = value;
    }
    else if (key_equals(sock, "pkt_len") == 1)
    {
        char * endptr = NULL;
        unsigned long long int value = strtoull(sock->jsmn.key_value.value, &endptr, 10);
        if (sock->jsmn.key_value.value == endptr)
        {
            fprintf(stderr,
                    "pkt_len `%.*s': Value `%.*s' is not a valid number.\n",
                    sock->jsmn.key_value.key_length,
                    sock->jsmn.key_value.key,
                    sock->jsmn.key_value.value_length,
                    sock->jsmn.key_value.value);
            return CALLBACK_ERROR;
        }
        if (errno == ERANGE)
        {
            fprintf(stderr,
                    "pkt_len `%.*s': Number too large.\n",
                    sock->jsmn.key_value.key_length,
                    sock->jsmn.key_value.key);
            return CALLBACK_ERROR;
        }
        cb_user_data->tmp.pkt.packet_len = value;
    }
    else if (key_equals(sock, "pkt_datalink") == 1)
    {
        char * endptr = NULL;
        unsigned long long int value = strtoull(sock->jsmn.key_value.value, &endptr, 10);
        if (sock->jsmn.key_value.value == endptr)
        {
            fprintf(stderr,
                    "pkt_datalink `%.*s': Value `%.*s' is not a valid number.\n",
                    sock->jsmn.key_value.key_length,
                    sock->jsmn.key_value.key,
                    sock->jsmn.key_value.value_length,
                    sock->jsmn.key_value.value);
            return CALLBACK_ERROR;
        }
        if (errno == ERANGE || value > (unsigned long long int)((uint32_t)-1))
        {
            fprintf(stderr,
                    "pkt_datalink `%.*s': Number too large.\n",
                    sock->jsmn.key_value.key_length,
                    sock->jsmn.key_value.key);
            return CALLBACK_ERROR;
        }
        cb_user_data->tmp.pkt_datalink = value;
    }
    else if (key_equals(sock, "flow_event_name") == 1)
    {
        if (value_equals(sock, "end") == 1 || value_equals(sock, "idle") == 1)
        {
            cb_user_data->tmp.flow_end_or_idle = 1;
        }
        else if (value_equals(sock, "guessed") == 1)
        {
            cb_user_data->tmp.guessed = 1;
        }
        else if (value_equals(sock, "detected") == 1)
        {
            cb_user_data->tmp.detected = 1;
        }
    }

#ifdef VERBOSE
    printf("[%.*s : %.*s] ",
           sock->jsmn.key_value.key_length,
           sock->jsmn.key_value.key,
           sock->jsmn.key_value.value_length,
           sock->jsmn.key_value.value);
#endif

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

int main(int argc, char ** argv)
{
    struct callback_user_data cb_user_data;

    memset(&cb_user_data, 0, sizeof(cb_user_data));
    sock = nDPIsrvd_init();
    if (sock == NULL)
    {
        fprintf(stderr, "%s: nDPIsrvd socket memory allocation failed!\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, sighandler);

    enum nDPIsrvd_connect_return connect_ret;

    if (argc == 2)
    {
        printf("Connecting to UNIX socket: %s\n", argv[1]);
        connect_ret = nDPIsrvd_connect_unix(sock, argv[1]);
    }
    else if (argc == 1)
    {
        if (access(serv_listen_path, R_OK) == 0)
        {
            printf("Connecting to %s\n", serv_listen_path);
            connect_ret = nDPIsrvd_connect_unix(sock, serv_listen_path);
        }
        else
        {
            printf("Connecting to %s:%u\n", serv_listen_addr, serv_listen_port);
            connect_ret = nDPIsrvd_connect_ip(sock, serv_listen_addr, serv_listen_port);
        }
    }

    if (connect_ret != CONNECT_OK)
    {
        fprintf(stderr, "%s: nDPIsrvd socket connect failed!\n", argv[0]);
        nDPIsrvd_free(&sock, &cb_user_data.flow_table);
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

        enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse(sock, nDPIsrvd_json_callback, &cb_user_data);
        if (parse_ret != PARSE_OK)
        {
            fprintf(stderr, "%s: nDPIsrvd parse failed with: %s\n", argv[0], nDPIsrvd_enum_to_string(parse_ret));
            break;
        }
    }

    struct nDPIsrvd_flow * current_flow;
    struct nDPIsrvd_flow * tmp;
    HASH_ITER(hh, cb_user_data.flow_table, current_flow, tmp)
    {
        struct flow_user_data * const ud = (struct flow_user_data *)current_flow->user_data;
        if (ud != NULL && ud->packets != NULL)
        {
            utarray_free(ud->packets);
            ud->packets = NULL;
        }
    }
    nDPIsrvd_free(&sock, &cb_user_data.flow_table);

    return 0;
}
