#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/un.h>
#include <netinet/in.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "utils.h"

#if (NDPI_MAJOR == 3 && NDPI_MINOR < 3) || NDPI_MAJOR < 3
#error "nDPI >= 3.3.0 requiired"
#endif

enum nDPId_l3_type
{
    L3_IP,
    L3_IP6
};

struct nDPId_flow_info
{
    uint32_t flow_id;
    unsigned long long int packets_processed;
    uint64_t first_seen;
    uint64_t last_seen;
    uint64_t hashval;

    enum nDPId_l3_type l3_type;

    union {
        struct
        {
            uint32_t src;
            uint32_t dst;
        } v4;
        struct
        {
            uint64_t src[2];
            uint64_t dst[2];
        } v6;
    } ip_tuple;

    uint16_t min_l4_data_len;
    uint16_t max_l4_data_len;
    unsigned long long int total_l4_data_len;
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t is_midstream_flow : 1;
    uint8_t flow_fin_rst_seen : 1;
    uint8_t detection_completed : 1;
    uint8_t reserved_00 : 5;
    uint8_t reserved_01[3];
    uint8_t l4_protocol;
    uint32_t last_ndpi_flow_struct_hash;

    struct ndpi_proto detected_l7_protocol;
    struct ndpi_proto guessed_l7_protocol;

    struct ndpi_flow_struct * ndpi_flow;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;
};

struct nDPId_workflow
{
    pcap_t * pcap_handle;

    uint8_t error_or_eof : 1;
    uint8_t reserved_00 : 7;
    uint8_t reserved_01[3];

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_l4_data_len;
    unsigned long long int detected_flow_protocols;

    uint64_t last_idle_scan_time;
    uint64_t last_time;

    void ** ndpi_flows_active;
    unsigned long long int max_active_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int total_active_flows;

    void ** ndpi_flows_idle;
    unsigned long long int max_idle_flows;
    unsigned long long int cur_idle_flows;
    unsigned long long int total_idle_flows;

    ndpi_serializer ndpi_serializer;
    struct ndpi_detection_module_struct * ndpi_struct;
};

struct nDPId_reader_thread
{
    struct nDPId_workflow * workflow;
    pthread_t thread_id;
    int json_sockfd;
    int json_sock_reconnect;
    int array_index;
};

enum packet_event
{
    PACKET_EVENT_INVALID = 0,

    PACKET_EVENT_PAYLOAD,
    PACKET_EVENT_PAYLOAD_FLOW,

    PACKET_EVENT_COUNT
};

enum flow_event
{
    FLOW_EVENT_INVALID = 0,

    FLOW_EVENT_NEW,
    FLOW_EVENT_END,
    FLOW_EVENT_IDLE,

    FLOW_EVENT_GUESSED,
    FLOW_EVENT_DETECTED,
    FLOW_EVENT_DETECTION_UPDATE,
    FLOW_EVENT_NOT_DETECTED,

    FLOW_EVENT_COUNT
};

enum basic_event
{
    BASIC_EVENT_INVALID = 0,

    UNKNOWN_DATALINK_LAYER,
    UNKNOWN_L3_PROTOCOL,
    NON_IP_PACKET,
    ETHERNET_PACKET_TOO_SHORT,
    ETHERNET_PACKET_UNKNOWN,
    IP4_PACKET_TOO_SHORT,
    IP4_SIZE_SMALLER_THAN_HEADER,
    IP4_L4_PAYLOAD_DETECTION_FAILED,
    IP6_PACKET_TOO_SHORT,
    IP6_SIZE_SMALLER_THAN_HEADER,
    IP6_L4_PAYLOAD_DETECTION_FAILED,
    TCP_PACKET_TOO_SHORT,
    UDP_PACKET_TOO_SHORT,
    CAPTURE_SIZE_SMALLER_THAN_PACKET_SIZE,
    MAX_FLOW_TO_TRACK,
    FLOW_MEMORY_ALLOCATION_FAILED,
    NDPI_FLOW_MEMORY_ALLOCATION_FAILED,
    NDPI_ID_MEMORY_ALLOCATION_FAILED,

    BASIC_EVENT_COUNT
};

enum daemon_event
{
    DAEMON_EVENT_INVALID = 0,

    DAEMON_EVENT_INIT,
    DAEMON_EVENT_RECONNECT,
    DAEMON_EVENT_SHUTDOWN,

    DAEMON_EVENT_COUNT
};

static char const * const packet_event_name_table[PACKET_EVENT_COUNT] = {[PACKET_EVENT_INVALID] = "invalid",
                                                                         [PACKET_EVENT_PAYLOAD] = "packet",
                                                                         [PACKET_EVENT_PAYLOAD_FLOW] = "packet-flow"};

static char const * const flow_event_name_table[FLOW_EVENT_COUNT] = {[FLOW_EVENT_INVALID] = "invalid",
                                                                     [FLOW_EVENT_NEW] = "new",
                                                                     [FLOW_EVENT_END] = "end",
                                                                     [FLOW_EVENT_IDLE] = "idle",
                                                                     [FLOW_EVENT_GUESSED] = "guessed",
                                                                     [FLOW_EVENT_DETECTED] = "detected",
                                                                     [FLOW_EVENT_DETECTION_UPDATE] = "detection-update",
                                                                     [FLOW_EVENT_NOT_DETECTED] = "not-detected"};
static char const * const basic_event_name_table[BASIC_EVENT_COUNT] = {
    [BASIC_EVENT_INVALID] = "invalid",
    [UNKNOWN_DATALINK_LAYER] = "Unknown datalink layer packet",
    [UNKNOWN_L3_PROTOCOL] = "Unknown L3 protocol",
    [NON_IP_PACKET] = "Non IP packet",
    [ETHERNET_PACKET_TOO_SHORT] = "Ethernet packet too short",
    [ETHERNET_PACKET_UNKNOWN] = "Unknown Ethernet packet type",
    [IP4_PACKET_TOO_SHORT] = "IP4 packet too short",
    [IP4_SIZE_SMALLER_THAN_HEADER] = "Packet smaller than IP4 header",
    [IP4_L4_PAYLOAD_DETECTION_FAILED] = "nDPI IPv4/L4 payload detection failed",
    [IP6_PACKET_TOO_SHORT] = "IP6 packet too short",
    [IP6_SIZE_SMALLER_THAN_HEADER] = "Packet smaller than IP6 header",
    [IP6_L4_PAYLOAD_DETECTION_FAILED] = "nDPI IPv6/L4 payload detection failed",
    [TCP_PACKET_TOO_SHORT] = "TCP packet smaller than expected",
    [UDP_PACKET_TOO_SHORT] = "UDP packet smaller than expected",
    [CAPTURE_SIZE_SMALLER_THAN_PACKET_SIZE] = "Captured packet size is smaller than packet size",
    [MAX_FLOW_TO_TRACK] = "Max flows to track reached",
    [FLOW_MEMORY_ALLOCATION_FAILED] = "Flow memory allocation failed",
    [NDPI_FLOW_MEMORY_ALLOCATION_FAILED] = "nDPI Flow memory allocation failed",
    [NDPI_ID_MEMORY_ALLOCATION_FAILED] = "Not enough memory for src id struct",
};

static char const * const daemon_event_name_table[DAEMON_EVENT_COUNT] = {
    [DAEMON_EVENT_INVALID] = "invalid",
    [DAEMON_EVENT_INIT] = "init",
    [DAEMON_EVENT_RECONNECT] = "reconnect",
    [DAEMON_EVENT_SHUTDOWN] = "shutdown",
};

static struct nDPId_reader_thread reader_threads[nDPId_MAX_READER_THREADS] = {};
int main_thread_shutdown = 0;
static uint32_t global_flow_id = 0;

static char * pcap_file_or_interface = NULL;
static int log_to_stderr = 0;
static char pidfile[UNIX_PATH_MAX] = nDPId_PIDFILE;
static char * user = "nobody";
static char * group = NULL;
static char json_sockpath[UNIX_PATH_MAX] = COLLECTOR_UNIX_SOCKET;

/* subopts */
static char * instance_alias = NULL;
static unsigned long long int max_flows_per_thread = nDPId_MAX_FLOWS_PER_THREAD / 2;
static unsigned long long int max_idle_flows_per_thread = nDPId_MAX_IDLE_FLOWS_PER_THREAD / 2;
static unsigned long long int tick_resolution = nDPId_TICK_RESOLUTION;
static unsigned long long int reader_thread_count = nDPId_MAX_READER_THREADS / 2;
static unsigned long long int idle_scan_period = nDPId_IDLE_SCAN_PERIOD;
static unsigned long long int max_idle_time = nDPId_IDLE_TIME;
static unsigned long long int max_post_end_flow_time = nDPId_POST_END_FLOW_TIME;
static unsigned long long int max_packets_per_flow_to_send = nDPId_PACKETS_PER_FLOW_TO_SEND;

enum nDPId_subopts
{
    MAX_FLOWS_PER_THREAD = 0,
    MAX_IDLE_FLOWS_PER_THREAD,
    TICK_RESOLUTION,
    MAX_READER_THREADS,
    IDLE_SCAN_PERIOD,
    MAX_IDLE_TIME,
    MAX_POST_END_FLOW_TIME,
    MAX_PACKETS_PER_FLOW_TO_SEND,
};
static char * const subopt_token[] = {[MAX_FLOWS_PER_THREAD] = "max-flows-per-thread",
                                      [MAX_IDLE_FLOWS_PER_THREAD] = "max-idle-flows-per-thread",
                                      [TICK_RESOLUTION] = "tick-resolution",
                                      [MAX_READER_THREADS] = "max-reader-threads",
                                      [IDLE_SCAN_PERIOD] = "idle-scan-period",
                                      [MAX_IDLE_TIME] = "max-idle-time",
                                      [MAX_POST_END_FLOW_TIME] = "max-post-end-flow-time",
                                      [MAX_PACKETS_PER_FLOW_TO_SEND] = "max-packets-per-flow-to-send",
                                      NULL};

static void free_workflow(struct nDPId_workflow ** const workflow);
static void serialize_and_send(struct nDPId_reader_thread * const reader_thread);
static void jsonize_flow_event(struct nDPId_reader_thread * const reader_thread,
                               struct nDPId_flow_info const * const flow,
                               enum flow_event event);

static struct nDPId_workflow * init_workflow(char const * const file_or_device)
{
    int pcap_argument_is_file = 0;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    struct nDPId_workflow * workflow = (struct nDPId_workflow *)ndpi_calloc(1, sizeof(*workflow));

    if (workflow == NULL)
    {
        return NULL;
    }

    errno = 0;
    if (access(file_or_device, R_OK) != 0 && errno == ENOENT)
    {
        workflow->pcap_handle = pcap_open_live(file_or_device, 65535, 1, 250, pcap_error_buffer);
    }
    else
    {
        workflow->pcap_handle =
            pcap_open_offline_with_tstamp_precision(file_or_device, PCAP_TSTAMP_PRECISION_MICRO, pcap_error_buffer);
        pcap_argument_is_file = 1;
    }

    if (workflow->pcap_handle == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               (pcap_argument_is_file == 0 ? "pcap_open_live: %.*s" : "pcap_open_offline_with_tstamp_precision: %.*s"),
               (int)PCAP_ERRBUF_SIZE,
               pcap_error_buffer);
        free_workflow(&workflow);
        return NULL;
    }

    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (workflow->ndpi_struct == NULL)
    {
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_active_flows = 0;
    workflow->max_active_flows = max_flows_per_thread;
    workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
    if (workflow->ndpi_flows_active == NULL)
    {
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_idle_flows = 0;
    workflow->max_idle_flows = max_idle_flows_per_thread;
    workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
    if (workflow->ndpi_flows_idle == NULL)
    {
        free_workflow(&workflow);
        return NULL;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
    ndpi_finalize_initalization(workflow->ndpi_struct);

    if (ndpi_init_serializer_ll(&workflow->ndpi_serializer, ndpi_serialization_format_json, NETWORK_BUFFER_MAX_SIZE) !=
        1)
    {
        return NULL;
    }

    return workflow;
}

static void ndpi_flow_info_freer(void * const node)
{
    struct nDPId_flow_info * const flow = (struct nDPId_flow_info *)node;

    ndpi_free(flow->ndpi_dst);
    ndpi_free(flow->ndpi_src);
    ndpi_flow_free(flow->ndpi_flow);
    ndpi_free(flow);
}

static void free_workflow(struct nDPId_workflow ** const workflow)
{
    struct nDPId_workflow * const w = *workflow;

    if (w == NULL)
    {
        return;
    }

    if (w->pcap_handle != NULL)
    {
        pcap_close(w->pcap_handle);
        w->pcap_handle = NULL;
    }

    if (w->ndpi_struct != NULL)
    {
        ndpi_exit_detection_module(w->ndpi_struct);
    }
    for (size_t i = 0; i < w->max_active_flows; i++)
    {
        ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_freer);
    }
    ndpi_free(w->ndpi_flows_active);
    ndpi_free(w->ndpi_flows_idle);
    ndpi_term_serializer(&w->ndpi_serializer);
    ndpi_free(w);
    *workflow = NULL;
}

static char * get_default_pcapdev(char * errbuf)
{
    char * ifname;
    pcap_if_t * all_devices = NULL;

    if (pcap_findalldevs(&all_devices, errbuf) != 0)
    {
        return NULL;
    }

    ifname = strdup(all_devices[0].name);
    pcap_freealldevs(all_devices);

    return ifname;
}

static int setup_reader_threads(void)
{
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    if (reader_thread_count > nDPId_MAX_READER_THREADS)
    {
        return 1;
    }

    if (pcap_file_or_interface == NULL)
    {
        pcap_file_or_interface = get_default_pcapdev(pcap_error_buffer);
        if (pcap_file_or_interface == NULL)
        {
            syslog(LOG_DAEMON | LOG_ERR, "pcap_lookupdev: %.*s", (int)PCAP_ERRBUF_SIZE, pcap_error_buffer);
            return 1;
        }
        syslog(LOG_DAEMON, "Capturing packets from default device: %s", pcap_file_or_interface);
    }

    for (unsigned long long int i = 0; i < reader_thread_count; ++i)
    {
        reader_threads[i].workflow = init_workflow(pcap_file_or_interface);
        if (reader_threads[i].workflow == NULL)
        {
            return 1;
        }
    }

    return 0;
}

static int ip_tuples_equal(struct nDPId_flow_info const * const A, struct nDPId_flow_info const * const B)
{
    // generate a warning if the enum changes
    switch (A->l3_type)
    {
        case L3_IP:
        case L3_IP6:
            break;
    }
    if (A->l3_type == L3_IP && B->l3_type == L3_IP6)
    {
        return A->ip_tuple.v4.src == B->ip_tuple.v4.src && A->ip_tuple.v4.dst == B->ip_tuple.v4.dst;
    }
    else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6)
    {
        return A->ip_tuple.v6.src[0] == B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] == B->ip_tuple.v6.src[1] &&
               A->ip_tuple.v6.dst[0] == B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] == B->ip_tuple.v6.dst[1];
    }
    return 0;
}

static int ip_tuples_compare(struct nDPId_flow_info const * const A, struct nDPId_flow_info const * const B)
{
    // generate a warning if the enum changes
    switch (A->l3_type)
    {
        case L3_IP:
        case L3_IP6:
            break;
    }
    if (A->l3_type == L3_IP && B->l3_type == L3_IP6)
    {
        if (A->ip_tuple.v4.src < B->ip_tuple.v4.src || A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
        {
            return -1;
        }
        if (A->ip_tuple.v4.src > B->ip_tuple.v4.src || A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
        {
            return 1;
        }
    }
    else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6)
    {
        if ((A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1]) ||
            (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1]))
        {
            return -1;
        }
        if ((A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] && A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1]) ||
            (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] && A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1]))
        {
            return 1;
        }
    }
    if (A->src_port < B->src_port || A->dst_port < B->dst_port)
    {
        return -1;
    }
    else if (A->src_port > B->src_port || A->dst_port > B->dst_port)
    {
        return 1;
    }
    return 0;
}

static void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    struct nDPId_workflow * const workflow = (struct nDPId_workflow *)user_data;
    struct nDPId_flow_info * const flow = *(struct nDPId_flow_info **)A;

    (void)depth;

    if (workflow == NULL || flow == NULL)
    {
        return;
    }

    if (workflow->cur_idle_flows == max_idle_flows_per_thread)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        if ((flow->flow_fin_rst_seen == 1 && flow->last_seen + max_post_end_flow_time < workflow->last_time) ||
            flow->last_seen + max_idle_time < workflow->last_time)
        {
            workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
            workflow->total_idle_flows++;
        }
    }
}

static int ndpi_workflow_node_cmp(void const * const A, void const * const B)
{
    struct nDPId_flow_info const * const flow_info_a = (struct nDPId_flow_info *)A;
    struct nDPId_flow_info const * const flow_info_b = (struct nDPId_flow_info *)B;

    if (flow_info_a->hashval < flow_info_b->hashval)
    {
        return (-1);
    }
    else if (flow_info_a->hashval > flow_info_b->hashval)
    {
        return (1);
    }

    /* Flows have the same hash */
    if (flow_info_a->l4_protocol < flow_info_b->l4_protocol)
    {
        return (-1);
    }
    else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol)
    {
        return (1);
    }

    if (ip_tuples_equal(flow_info_a, flow_info_b) != 0 && flow_info_a->src_port == flow_info_b->src_port &&
        flow_info_a->dst_port == flow_info_b->dst_port)
    {
        return (0);
    }

    return ip_tuples_compare(flow_info_a, flow_info_b);
}

static void process_idle_flow(struct nDPId_reader_thread * const reader_thread, size_t idle_scan_index)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    while (workflow->cur_idle_flows > 0)
    {
        struct nDPId_flow_info * const f =
            (struct nDPId_flow_info *)workflow->ndpi_flows_idle[--workflow->cur_idle_flows];

        if (f->detection_completed == 0)
        {
            uint8_t protocol_was_guessed = 0;

            if (ndpi_is_protocol_detected(workflow->ndpi_struct, f->guessed_l7_protocol) == 0)
            {
                f->guessed_l7_protocol =
                    ndpi_detection_giveup(workflow->ndpi_struct, f->ndpi_flow, 1, &protocol_was_guessed);
            }
            else
            {
                protocol_was_guessed = 1;
            }

            if (protocol_was_guessed != 0)
            {
                jsonize_flow_event(reader_thread, f, FLOW_EVENT_GUESSED);
            }
            else
            {
                jsonize_flow_event(reader_thread, f, FLOW_EVENT_NOT_DETECTED);
            }
        }
        if (f->flow_fin_rst_seen != 0)
        {
            jsonize_flow_event(reader_thread, f, FLOW_EVENT_END);
        }
        else
        {
            jsonize_flow_event(reader_thread, f, FLOW_EVENT_IDLE);
        }
        ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index], ndpi_workflow_node_cmp);
        ndpi_flow_info_freer(f);
        workflow->cur_active_flows--;
    }
}

static void check_for_idle_flows(struct nDPId_reader_thread * const reader_thread)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    if (workflow->last_idle_scan_time + idle_scan_period < workflow->last_time)
    {
        for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index)
        {
            ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);
            process_idle_flow(reader_thread, idle_scan_index);
        }

        workflow->last_idle_scan_time = workflow->last_time;
    }
}

static void jsonize_l3_l4(struct nDPId_workflow * const workflow, struct nDPId_flow_info const * const flow)
{
    ndpi_serializer * const serializer = &workflow->ndpi_serializer;
    char src_name[48] = {};
    char dst_name[48] = {};

    switch (flow->l3_type)
    {
        case L3_IP:
            ndpi_serialize_string_string(serializer, "l3_proto", "ip4");
            if (inet_ntop(AF_INET, &flow->ip_tuple.v4.src, src_name, sizeof(src_name)) == NULL)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Could not convert IPv4 source ip to string: %s", strerror(errno));
            }
            if (inet_ntop(AF_INET, &flow->ip_tuple.v4.dst, dst_name, sizeof(dst_name)) == NULL)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Could not convert IPv4 destination ip to string: %s", strerror(errno));
            }
            break;
        case L3_IP6:
            ndpi_serialize_string_string(serializer, "l3_proto", "ip6");
            if (inet_ntop(AF_INET6, &flow->ip_tuple.v6.src[0], src_name, sizeof(src_name)) == NULL)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Could not convert IPv6 source ip to string: %s", strerror(errno));
            }
            if (inet_ntop(AF_INET6, &flow->ip_tuple.v6.dst[0], dst_name, sizeof(dst_name)) == NULL)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Could not convert IPv6 destination ip to string: %s", strerror(errno));
            }

            /* For consistency across platforms replace :0: with :: */
            ndpi_patchIPv6Address(src_name), ndpi_patchIPv6Address(dst_name);
            break;
        default:
            ndpi_serialize_string_string(serializer, "l3_proto", "unknown");
    }

    ndpi_serialize_string_string(serializer, "src_ip", src_name);
    ndpi_serialize_string_string(serializer, "dst_ip", dst_name);
    if (flow->src_port)
    {
        ndpi_serialize_string_uint32(serializer, "src_port", flow->src_port);
    }
    if (flow->dst_port)
    {
        ndpi_serialize_string_uint32(serializer, "dst_port", flow->dst_port);
    }

    switch (flow->l4_protocol)
    {
        case IPPROTO_TCP:
            ndpi_serialize_string_string(serializer, "l4_proto", "tcp");
            break;
        case IPPROTO_UDP:
            ndpi_serialize_string_string(serializer, "l4_proto", "udp");
            break;
        case IPPROTO_ICMP:
            ndpi_serialize_string_string(serializer, "l4_proto", "icmp");
            break;
        case IPPROTO_ICMPV6:
            ndpi_serialize_string_string(serializer, "l4_proto", "icmp6");
            break;
        default:
            ndpi_serialize_string_uint32(serializer, "l4_proto", flow->l4_protocol);
            break;
    }
}

static void jsonize_basic(struct nDPId_reader_thread * const reader_thread)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    ndpi_serialize_string_int32(&workflow->ndpi_serializer, "thread_id", reader_thread->array_index);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "packet_id", workflow->packets_captured);
    ndpi_serialize_string_string(&workflow->ndpi_serializer, "source", pcap_file_or_interface);
    if (instance_alias != NULL)
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, "alias", instance_alias);
    }
}

static void jsonize_daemon(struct nDPId_reader_thread * const reader_thread, enum daemon_event event)
{
    char const ev[] = "daemon_event_name";
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    ndpi_serialize_string_int32(&workflow->ndpi_serializer, "daemon_event_id", event);
    if (event > DAEMON_EVENT_INVALID && event < DAEMON_EVENT_COUNT)
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, daemon_event_name_table[event]);
    }
    else
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, daemon_event_name_table[DAEMON_EVENT_INVALID]);
    }

    jsonize_basic(reader_thread);

    if (event == DAEMON_EVENT_INIT)
    {
        ndpi_serialize_string_int64(&workflow->ndpi_serializer, "max-flows-per-thread", max_flows_per_thread);
        ndpi_serialize_string_int64(&workflow->ndpi_serializer, "max-idle-flows-per-thread", max_idle_flows_per_thread);
        ndpi_serialize_string_int64(&workflow->ndpi_serializer, "tick-resolution", tick_resolution);
        ndpi_serialize_string_int64(&workflow->ndpi_serializer, "reader-thread-count", reader_thread_count);
        ndpi_serialize_string_int64(&workflow->ndpi_serializer, "idle-scan-period", idle_scan_period);
        ndpi_serialize_string_int64(&workflow->ndpi_serializer, "max-idle-time", max_idle_time);
        ndpi_serialize_string_int64(&workflow->ndpi_serializer, "max-post-end-flow-time", max_post_end_flow_time);
        ndpi_serialize_string_int64(&workflow->ndpi_serializer,
                                    "max-packets-per-flow-to-send",
                                    max_packets_per_flow_to_send);
    }
    serialize_and_send(reader_thread);
}

static void jsonize_flow(struct nDPId_workflow * const workflow, struct nDPId_flow_info const * const flow)
{
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "flow_id", flow->flow_id);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_packet_id", flow->packets_processed);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_first_seen", flow->first_seen);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_last_seen", flow->last_seen);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_tot_l4_data_len", flow->total_l4_data_len);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_min_l4_data_len", flow->min_l4_data_len);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_max_l4_data_len", flow->max_l4_data_len);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_avg_l4_data_len",
                                 (flow->packets_processed > 0 ? flow->total_l4_data_len / flow->packets_processed : 0));
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "midstream", flow->is_midstream_flow);
}

static int connect_to_json_socket(struct nDPId_reader_thread * const reader_thread)
{
    struct sockaddr_un saddr;

    close(reader_thread->json_sockfd);

    reader_thread->json_sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (reader_thread->json_sockfd < 0)
    {
        reader_thread->json_sock_reconnect = 1;
        return 1;
    }

    saddr.sun_family = AF_UNIX;
    if (snprintf(saddr.sun_path, sizeof(saddr.sun_path), "%s", json_sockpath) < 0 ||
        connect(reader_thread->json_sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        reader_thread->json_sock_reconnect = 1;
        return 1;
    }

    if (shutdown(reader_thread->json_sockfd, SHUT_RD) != 0)
    {
        return 1;
    }

    if (fcntl(reader_thread->json_sockfd, F_SETFL, fcntl(reader_thread->json_sockfd, F_GETFL, 0) | O_NONBLOCK) == -1)
    {
        reader_thread->json_sock_reconnect = 1;
        return 1;
    }

    reader_thread->json_sock_reconnect = 0;

    return 0;
}

static void send_to_json_sink(struct nDPId_reader_thread * const reader_thread,
                              char const * const json_str,
                              size_t json_str_len)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    int saved_errno;
    int s_ret;
    char newline_json_str[NETWORK_BUFFER_MAX_SIZE];

#if nDPIsrvd_JSON_BYTES != 4
#error "Please do not forget to change the format string if you've changed the value of nDPIsrvd_JSON_BYTES."
#endif
    s_ret =
        snprintf(newline_json_str, sizeof(newline_json_str), "%04zu%.*s", json_str_len, (int)json_str_len, json_str);
    if (s_ret < 0 || s_ret > (int)sizeof(newline_json_str))
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "[%8llu, %d] JSON buffer prepare failed: snprintf returned %d, buffer size %zu",
               workflow->packets_captured,
               reader_thread->array_index,
               s_ret,
               sizeof(newline_json_str));
        return;
    }

    if (reader_thread->json_sock_reconnect != 0)
    {
        if (connect_to_json_socket(reader_thread) == 0)
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "[%8llu, %d] Reconnected to JSON sink",
                   workflow->packets_captured,
                   reader_thread->array_index);
        }
    }

    errno = 0;
    if (reader_thread->json_sock_reconnect == 0 && write(reader_thread->json_sockfd, newline_json_str, s_ret) != s_ret)
    {
        saved_errno = errno;
        syslog(LOG_DAEMON | LOG_ERR,
               "[%8llu, %d] send data to JSON sink failed: %s",
               workflow->packets_captured,
               reader_thread->array_index,
               strerror(saved_errno));
        if (saved_errno == EPIPE)
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "[%8llu, %d] Lost connection to JSON sink",
                   workflow->packets_captured,
                   reader_thread->array_index);
        }
        if (saved_errno != EAGAIN)
        {
            reader_thread->json_sock_reconnect = 1;
        }
        else
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "[%8llu, %d] Possible data loss detected",
                   workflow->packets_captured,
                   reader_thread->array_index);
        }
    }
}

static void serialize_and_send(struct nDPId_reader_thread * const reader_thread)
{
    char * json_str;
    uint32_t json_str_len;

    json_str = ndpi_serializer_get_buffer(&reader_thread->workflow->ndpi_serializer, &json_str_len);
    if (json_str == NULL || json_str_len == 0)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "[%8llu, %d] jsonize failed, buffer length: %u",
               reader_thread->workflow->packets_captured,
               reader_thread->array_index,
               json_str_len);
    }
    else
    {
        send_to_json_sink(reader_thread, json_str, json_str_len);
    }
    ndpi_reset_serializer(&reader_thread->workflow->ndpi_serializer);
}

size_t base64_out_len(size_t in_len)
{
    return ((in_len + 2) / 3) * 4;
}

char * base64_encode(uint8_t const * in, size_t in_len, char * const out, size_t const out_len)
{
    static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = 0, ret_size;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    ret_size = base64_out_len(in_len);
    if (out_len < ret_size)
    {
        return NULL;
    }

    while (in_len-- != 0)
    {
        char_array_3[i++] = *(in++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
            {
                out[len++] = base64_table[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i != 0)
    {
        for (int j = i; j < 3; j++)
        {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int j = 0; (j < i + 1); j++)
        {
            out[len++] = base64_table[char_array_4[j]];
        }

        while ((i++ < 3))
        {
            out[len++] = '=';
        }
    }

    out[len++] = '\0';

    return out;
}

static void jsonize_packet_event(struct nDPId_reader_thread * const reader_thread,
                                 struct pcap_pkthdr const * const header,
                                 uint8_t const * const packet,
                                 uint16_t pkt_type,
                                 uint16_t pkt_ipoffset,
                                 struct nDPId_flow_info const * const flow,
                                 enum packet_event event)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    char const ev[] = "packet_event_name";

    if (event == PACKET_EVENT_PAYLOAD_FLOW)
    {
        if (flow == NULL)
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "[%8llu, %d] BUG: got a PACKET_EVENT_PAYLOAD_FLOW with a flow pointer equals NULL",
                   reader_thread->workflow->packets_captured,
                   reader_thread->array_index);
            return;
        }
        if (flow->packets_processed > max_packets_per_flow_to_send)
        {
            return;
        }
        ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "flow_id", flow->flow_id);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_packet_id", flow->packets_processed);
        ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "max_packets", max_packets_per_flow_to_send);
    }

    ndpi_serialize_string_int32(&workflow->ndpi_serializer, "packet_event_id", event);
    if (event > PACKET_EVENT_INVALID && event < PACKET_EVENT_COUNT)
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, packet_event_name_table[event]);
    }
    else
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, packet_event_name_table[PACKET_EVENT_INVALID]);
    }

    jsonize_basic(reader_thread);

    size_t base64_data_len = base64_out_len(header->caplen);
    char base64_data[NETWORK_BUFFER_MAX_SIZE];
    if (ndpi_serialize_string_boolean(&workflow->ndpi_serializer,
                                      "pkt_oversize",
                                      base64_data_len > sizeof(base64_data)) != 0 ||
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pkt_ts", header->ts.tv_sec) != 0 ||
        ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_len", header->len) != 0 ||
        ndpi_serialize_string_string(&workflow->ndpi_serializer,
                                     "pkt",
                                     base64_encode(packet, header->caplen, base64_data, sizeof(base64_data))) != 0 ||
        ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_caplen", header->caplen) != 0 ||
        ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_type", pkt_type) != 0 ||
        ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_ipoffset", pkt_ipoffset) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "[%8llu, %d] JSON serialize buffer failed",
               reader_thread->workflow->packets_captured,
               reader_thread->array_index);
    }
    serialize_and_send(reader_thread);
}

/* I decided against ndpi_flow2json as does not fulfill my needs. */
static void jsonize_flow_event(struct nDPId_reader_thread * const reader_thread,
                               struct nDPId_flow_info const * const flow,
                               enum flow_event event)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    char const ev[] = "flow_event_name";

    ndpi_serialize_string_int32(&workflow->ndpi_serializer, "flow_event_id", event);
    if (event > FLOW_EVENT_INVALID && event < FLOW_EVENT_COUNT)
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, flow_event_name_table[event]);
    }
    else
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, flow_event_name_table[FLOW_EVENT_INVALID]);
    }
    jsonize_basic(reader_thread);
    jsonize_flow(workflow, flow);
    jsonize_l3_l4(workflow, flow);

    switch (event)
    {
        case FLOW_EVENT_INVALID:
        case FLOW_EVENT_COUNT:
        case FLOW_EVENT_NEW:
        case FLOW_EVENT_END:
        case FLOW_EVENT_IDLE:
            break;

        case FLOW_EVENT_NOT_DETECTED:
        case FLOW_EVENT_GUESSED:
            if (ndpi_dpi2json(
                    workflow->ndpi_struct, flow->ndpi_flow, flow->guessed_l7_protocol, &workflow->ndpi_serializer) != 0)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "[%8llu, %4u] ndpi_dpi2json failed for not-detected/guessed flow",
                       workflow->packets_captured,
                       flow->flow_id);
            }
            break;

        case FLOW_EVENT_DETECTED:
        case FLOW_EVENT_DETECTION_UPDATE:
            if (ndpi_dpi2json(workflow->ndpi_struct,
                              flow->ndpi_flow,
                              flow->detected_l7_protocol,
                              &workflow->ndpi_serializer) != 0)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "[%8llu, %4u] ndpi_dpi2json failed for detected/detection-update flow",
                       workflow->packets_captured,
                       flow->flow_id);
            }
            break;
    }

    serialize_and_send(reader_thread);
}

static void jsonize_format_error(struct nDPId_reader_thread * const reader_thread, uint32_t format_index)
{
    ndpi_serialize_string_string(&reader_thread->workflow->ndpi_serializer, "serializer-error", "format");
    ndpi_serialize_string_uint32(&reader_thread->workflow->ndpi_serializer, "serializer-format-index", format_index);
    serialize_and_send(reader_thread);
}

static void vjsonize_basic_eventf(struct nDPId_reader_thread * const reader_thread, char const * format, va_list ap)
{
    uint8_t got_jsonkey = 0;
    uint8_t is_long_long = 0;
    char json_key[NETWORK_BUFFER_MAX_SIZE];
    uint32_t format_index = 0;

    while (*format)
    {
        if (got_jsonkey == 0)
        {
            json_key[0] = '\0';
        }

        switch (*format++)
        {
            case 's':
            {
                format_index++;
                char * value = va_arg(ap, char *);
                if (got_jsonkey == 0)
                {
                    snprintf(json_key, sizeof(json_key), "%s", value);
                    got_jsonkey = 1;
                }
                else
                {
                    ndpi_serialize_string_string(&reader_thread->workflow->ndpi_serializer, json_key, value);
                    got_jsonkey = 0;
                }
                break;
            }
            case 'f':
            {
                format_index++;
                if (got_jsonkey == 1)
                {
                    float value = va_arg(ap, double);
                    ndpi_serialize_string_float(&reader_thread->workflow->ndpi_serializer, json_key, value, "%.2f");
                    got_jsonkey = 0;
                }
                else
                {
                    jsonize_format_error(reader_thread, format_index);
                    return;
                }
                break;
            }
            case 'z':
            case 'l':
                format_index++;
                if (got_jsonkey != 1)
                {
                    jsonize_format_error(reader_thread, format_index);
                    return;
                }
                if (*format == 'l')
                {
                    format++;
                    is_long_long = 1;
                }
                else
                {
                    is_long_long = 0;
                }
                if (*format == 'd')
                {
                    long long int value;
                    if (is_long_long != 0)
                    {
                        value = va_arg(ap, long long int);
                    }
                    else
                    {
                        value = va_arg(ap, long int);
                    }
                    ndpi_serialize_string_int64(&reader_thread->workflow->ndpi_serializer, json_key, value);
                    got_jsonkey = 0;
                }
                else if (*format == 'u')
                {
                    unsigned long long int value;
                    if (is_long_long != 0)
                    {
                        value = va_arg(ap, unsigned long long int);
                    }
                    else
                    {
                        value = va_arg(ap, unsigned long int);
                    }
                    ndpi_serialize_string_uint64(&reader_thread->workflow->ndpi_serializer, json_key, value);
                    got_jsonkey = 0;
                }
                else
                {
                    jsonize_format_error(reader_thread, format_index);
                    return;
                }
                format++;
                break;
            case 'u':
                format_index++;
                if (got_jsonkey == 1)
                {
                    unsigned int value = va_arg(ap, unsigned int);
                    ndpi_serialize_string_uint32(&reader_thread->workflow->ndpi_serializer, json_key, value);
                    got_jsonkey = 0;
                }
                else
                {
                    jsonize_format_error(reader_thread, format_index);
                    return;
                }
                break;
            case 'd':
                format_index++;
                if (got_jsonkey == 1)
                {
                    int value = va_arg(ap, int);
                    ndpi_serialize_string_int32(&reader_thread->workflow->ndpi_serializer, json_key, value);
                    got_jsonkey = 0;
                }
                else
                {
                    jsonize_format_error(reader_thread, format_index);
                    return;
                }
                break;
            case ' ':
            case ',':
            case '%':
                break;
            default:
                jsonize_format_error(reader_thread, format_index);
                return;
        }
    }
}

__attribute__((format(printf, 3, 4))) static void jsonize_basic_eventf(struct nDPId_reader_thread * const reader_thread,
                                                                       enum basic_event event,
                                                                       char const * format,
                                                                       ...)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    va_list ap;
    char const ev[] = "basic_event_name";

    ndpi_serialize_string_int32(&reader_thread->workflow->ndpi_serializer, "basic_event_id", event);
    if (event > BASIC_EVENT_INVALID && event < BASIC_EVENT_COUNT)
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, basic_event_name_table[event]);
    }
    else
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, basic_event_name_table[BASIC_EVENT_INVALID]);
    }
    jsonize_basic(reader_thread);

    if (format != NULL)
    {
        va_start(ap, format);
        vjsonize_basic_eventf(reader_thread, format, ap);
        va_end(ap);
    }

    serialize_and_send(reader_thread);
}

/* See: https://en.wikipedia.org/wiki/MurmurHash#MurmurHash3 */
static inline uint32_t murmur_32_scramble(uint32_t k)
{
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    return k;
}

/* See: https://en.wikipedia.org/wiki/MurmurHash#MurmurHash3 */
static uint32_t murmur3_32(uint8_t const * key, size_t len, uint32_t seed)
{
    uint32_t h = seed;
    uint32_t k;
    /* Read in groups of 4. */
    for (size_t i = len >> 2; i; i--)
    {
        k = htole32(*(uint32_t *)key);
        key += sizeof(uint32_t);
        h ^= murmur_32_scramble(k);
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64;
    }
    /* Read the rest. */
    k = 0;
    for (size_t i = len & 3; i; i--)
    {
        k <<= 8;
        k |= key[i - 1];
    }
    // A swap is *not* necessary here because the preceding loop already
    // places the low bytes in the low places according to whatever endianness
    // we use. Swaps only apply when the memory is copied in a chunk.
    h ^= murmur_32_scramble(k);
    /* Finalize. */
    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

static uint32_t calculate_ndpi_flow_struct_hash(struct ndpi_flow_struct const * const ndpi_flow)
{
    /*
     * This is a kludge, but necessary for now as I do not want to spam nDPIsrvd and clients
     * with the same detection json string over and over again.
     * So we are building a hash over the more "stable" parts of the ndpi flow struct.
     * Stable in terms of they should only change if the detection changes for whatever reason.
     * At the time of writing, nDPI has no API function to check if the detection changed
     * or has some new information available. This is far from perfect.
     */
    uint32_t hash = murmur3_32((uint8_t const *)&ndpi_flow->protos, sizeof(ndpi_flow->protos), nDPId_FLOW_STRUCT_SEED);
    hash += ndpi_flow->category;
    hash += ndpi_flow->risk;

    const size_t protocol_bitmask_size = sizeof(ndpi_flow->src->detected_protocol_bitmask.fds_bits) /
                                         sizeof(ndpi_flow->src->detected_protocol_bitmask.fds_bits[0]);
    for (size_t i = 0; i < protocol_bitmask_size; ++i)
    {
        hash += ndpi_flow->src->detected_protocol_bitmask.fds_bits[i];
        hash += ndpi_flow->dst->detected_protocol_bitmask.fds_bits[i];
    }
    hash += strnlen((const char *)ndpi_flow->host_server_name, sizeof(ndpi_flow->host_server_name)); // ugly

    return hash;
}

static void ndpi_process_packet(uint8_t * const args,
                                struct pcap_pkthdr const * const header,
                                uint8_t const * const packet)
{
    struct nDPId_reader_thread * const reader_thread = (struct nDPId_reader_thread *)args;
    struct nDPId_workflow * workflow;
    struct nDPId_flow_info flow = {};

    size_t hashed_index;
    void * tree_result;
    struct nDPId_flow_info * flow_to_process;

    uint8_t direction_changed = 0;
    uint8_t is_new_flow = 0;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

    const struct ndpi_ethhdr * ethernet;
    const struct ndpi_iphdr * ip;
    struct ndpi_ipv6hdr * ip6;

    uint64_t time_ms;
    const uint16_t eth_offset = 0;
    uint16_t ip_offset;
    uint16_t ip_size;

    const uint8_t * l4_ptr = NULL;
    uint16_t l4_len = 0;

    uint16_t type;
    int thread_index = nDPId_THREAD_DISTRIBUTION_SEED; // generated with `dd if=/dev/random bs=1024 count=1 |& hd'

    if (reader_thread == NULL)
    {
        return;
    }
    workflow = reader_thread->workflow;

    if (workflow == NULL)
    {
        return;
    }

    workflow->packets_captured++;
    time_ms = ((uint64_t)header->ts.tv_sec) * tick_resolution + header->ts.tv_usec / (1000000 / tick_resolution);
    workflow->last_time = time_ms;

    check_for_idle_flows(reader_thread);

    /* process datalink layer */
    switch (pcap_datalink(workflow->pcap_handle))
    {
        case DLT_NULL:
        {
            uint32_t dlt_hdr = ntohl(*((uint32_t *)&packet[eth_offset]));

            if (dlt_hdr == 0x00000002)
            {
                type = ETH_P_IP;
            }
            else if (dlt_hdr == 0x00000024 || dlt_hdr == 0x00000028 || dlt_hdr == 0x00000030)
            {
                type = ETH_P_IPV6;
            }
            else
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(reader_thread,
                                     UNKNOWN_DATALINK_LAYER,
                                     "%s%u%s%u",
                                     "datalink",
                                     pcap_datalink(workflow->pcap_handle),
                                     "header",
                                     ntohl(*((uint32_t *)&packet[eth_offset])));
                return;
            }
            ip_offset = 4 + eth_offset;
            break;
        }
        case DLT_EN10MB:
            if (header->len < sizeof(struct ndpi_ethhdr))
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(reader_thread, ETHERNET_PACKET_TOO_SHORT, NULL);
                return;
            }
            ethernet = (struct ndpi_ethhdr *)&packet[eth_offset];
            ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
            type = ntohs(ethernet->h_proto);
            switch (type)
            {
                case ETH_P_IP: /* IPv4 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr))
                    {
                        jsonize_packet_event(
                            reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
                        jsonize_basic_eventf(reader_thread, IP4_PACKET_TOO_SHORT, NULL);
                        return;
                    }
                    break;
                case ETH_P_IPV6: /* IPV6 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr))
                    {
                        jsonize_packet_event(
                            reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
                        jsonize_basic_eventf(reader_thread, IP6_PACKET_TOO_SHORT, NULL);
                        return;
                    }
                    break;
                case ETH_P_ARP: /* ARP */
                    return;
                default:
                    jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
                    jsonize_basic_eventf(reader_thread, ETHERNET_PACKET_UNKNOWN, "%s%u", "type", type);
                    return;
            }
            break;
        case DLT_IPV4:
            type = ETH_P_IP;
            ip_offset = 0;
            break;
        case DLT_IPV6:
            type = ETH_P_IPV6;
            ip_offset = 0;
            break;
        default:
            jsonize_packet_event(reader_thread, header, packet, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, UNKNOWN_DATALINK_LAYER, "%s%u", "datalink", pcap_datalink(workflow->pcap_handle));
            return;
    }

    if (type == ETH_P_IP)
    {
        ip = (struct ndpi_iphdr *)&packet[ip_offset];
        ip6 = NULL;
    }
    else if (type == ETH_P_IPV6)
    {
        ip = NULL;
        ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    }
    else
    {
        jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
        jsonize_basic_eventf(reader_thread, UNKNOWN_L3_PROTOCOL, "%s%u", "protocol", type);
        return;
    }
    ip_size = header->len - ip_offset;

    if (type == ETH_P_IP && header->len >= ip_offset)
    {
        if (header->caplen < header->len)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 CAPTURE_SIZE_SMALLER_THAN_PACKET_SIZE,
                                 "%s%u %s%u",
                                 "caplen",
                                 header->caplen,
                                 "len",
                                 header->len);
        }
    }

    /* process layer3 e.g. IPv4 / IPv6 */
    if (ip != NULL && ip->version == 4)
    {
        if (ip_size < sizeof(*ip))
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, IP4_SIZE_SMALLER_THAN_HEADER, "%s%u %s%zu", "ip_size", ip_size, "expected", sizeof(*ip));
            return;
        }

        flow.l3_type = L3_IP;
        if (ndpi_detection_get_l4(
                (uint8_t *)ip, ip_size, &l4_ptr, &l4_len, &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, IP4_L4_PAYLOAD_DETECTION_FAILED, "%s%zu", "l4_data_len", ip_size - sizeof(*ip));
            return;
        }

        flow.ip_tuple.v4.src = ip->saddr;
        flow.ip_tuple.v4.dst = ip->daddr;
        uint32_t min_addr = (flow.ip_tuple.v4.src > flow.ip_tuple.v4.dst ? flow.ip_tuple.v4.dst : flow.ip_tuple.v4.src);
        thread_index = min_addr + ip->protocol;
    }
    else if (ip6 != NULL)
    {
        if (ip_size < sizeof(ip6->ip6_hdr))
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 IP6_SIZE_SMALLER_THAN_HEADER,
                                 "%s%u %s%zu",
                                 "ip_size",
                                 ip_size,
                                 "expected",
                                 sizeof(ip6->ip6_hdr));
            return;
        }

        flow.l3_type = L3_IP6;
        if (ndpi_detection_get_l4(
                (uint8_t *)ip6, ip_size, &l4_ptr, &l4_len, &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, IP6_L4_PAYLOAD_DETECTION_FAILED, "%s%zu", "l4_data_len", ip_size - sizeof(*ip));
            return;
        }

        flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
        uint64_t min_addr[2];
        if (flow.ip_tuple.v6.src[0] > flow.ip_tuple.v6.dst[0] && flow.ip_tuple.v6.src[1] > flow.ip_tuple.v6.dst[1])
        {
            min_addr[0] = flow.ip_tuple.v6.dst[0];
            min_addr[1] = flow.ip_tuple.v6.dst[0];
        }
        else
        {
            min_addr[0] = flow.ip_tuple.v6.src[0];
            min_addr[1] = flow.ip_tuple.v6.src[0];
        }
        thread_index = min_addr[0] + min_addr[1] + ip6->ip6_hdr.ip6_un1_nxt;
    }
    else
    {
        jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
        jsonize_basic_eventf(reader_thread, UNKNOWN_L3_PROTOCOL, "%s%u", "protocol", type);
        return;
    }

    /* process layer4 e.g. TCP / UDP */
    if (flow.l4_protocol == IPPROTO_TCP)
    {
        const struct ndpi_tcphdr * tcp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr))
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 TCP_PACKET_TOO_SHORT,
                                 "%s%u %s%zu",
                                 "header_len",
                                 header->len,
                                 "expected",
                                 (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
            return;
        }
        tcp = (struct ndpi_tcphdr *)l4_ptr;
        flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow.flow_fin_rst_seen = (tcp->fin == 1 || tcp->rst == 1 ? 1 : 0);
        flow.src_port = ntohs(tcp->source);
        flow.dst_port = ntohs(tcp->dest);
    }
    else if (flow.l4_protocol == IPPROTO_UDP)
    {
        const struct ndpi_udphdr * udp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_udphdr))
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 UDP_PACKET_TOO_SHORT,
                                 "%s%u %s%zu",
                                 "header_len",
                                 header->len,
                                 "expected",
                                 (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
            return;
        }
        udp = (struct ndpi_udphdr *)l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);
    }

    /* distribute flows to threads while keeping stability (same flow goes always to same thread) */
    thread_index += (flow.src_port < flow.dst_port ? flow.dst_port : flow.src_port);
    thread_index %= reader_thread_count;
    if (thread_index != reader_thread->array_index)
    {
        return;
    }
    workflow->packets_processed++;
    workflow->total_l4_data_len += l4_len;

    /* calculate flow hash for btree find, search(insert) */
    switch (flow.l3_type)
    {
        case L3_IP:
            if (ndpi_flowv4_flow_hash(flow.l4_protocol,
                                      flow.ip_tuple.v4.src,
                                      flow.ip_tuple.v4.dst,
                                      flow.src_port,
                                      flow.dst_port,
                                      0,
                                      0,
                                      (uint8_t *)&flow.hashval,
                                      sizeof(flow.hashval)) != 0)
            {
                flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst; // fallback
            }
            break;
        case L3_IP6:
            if (ndpi_flowv6_flow_hash(flow.l4_protocol,
                                      &ip6->ip6_src,
                                      &ip6->ip6_dst,
                                      flow.src_port,
                                      flow.dst_port,
                                      0,
                                      0,
                                      (uint8_t *)&flow.hashval,
                                      sizeof(flow.hashval)) != 0)
            {
                flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
                flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
            }
            break;
    }
    flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

    hashed_index = flow.hashval % workflow->max_active_flows;
    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
    if (tree_result == NULL)
    {
        /* flow not found in btree: switch src <-> dst and try to find it again */
        uint64_t orig_src_ip[2] = {flow.ip_tuple.v6.src[0], flow.ip_tuple.v6.src[1]};
        uint64_t orig_dst_ip[2] = {flow.ip_tuple.v6.dst[0], flow.ip_tuple.v6.dst[1]};
        uint16_t orig_src_port = flow.src_port;
        uint16_t orig_dst_port = flow.dst_port;

        flow.ip_tuple.v6.src[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.src[1] = orig_dst_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_src_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_src_ip[1];
        flow.src_port = orig_dst_port;
        flow.dst_port = orig_src_port;

        tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
        if (tree_result != NULL)
        {
            direction_changed = 1;
        }

        flow.ip_tuple.v6.src[0] = orig_src_ip[0];
        flow.ip_tuple.v6.src[1] = orig_src_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_dst_ip[1];
        flow.src_port = orig_src_port;
        flow.dst_port = orig_dst_port;
    }

    if (tree_result == NULL)
    {
        /* flow still not found, must be new */
        if (workflow->cur_active_flows == workflow->max_active_flows)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 MAX_FLOW_TO_TRACK,
                                 "%s%llu %s%llu %s%llu",
                                 "current_active",
                                 workflow->max_active_flows,
                                 "current_idle",
                                 workflow->cur_idle_flows,
                                 "max_active",
                                 workflow->max_active_flows);
            return;
        }

        flow_to_process = (struct nDPId_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
        if (flow_to_process == NULL)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, FLOW_MEMORY_ALLOCATION_FAILED, "%s%zu", "size", sizeof(*flow_to_process));
            return;
        }

        workflow->cur_active_flows++;
        workflow->total_active_flows++;
        memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
#ifdef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4
        flow_to_process->flow_id = __sync_fetch_and_add(&global_flow_id, 1);
#else
#warning "Compare and Fetch aka __sync_fetch_and_add not available on your platform/compiler, do not trust any flow_id!"
        flow_to_process->flow_id = global_flow_id++;
#endif

        flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
        if (flow_to_process->ndpi_flow == NULL)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 NDPI_FLOW_MEMORY_ALLOCATION_FAILED,
                                 "%s%u %s%zu",
                                 "flow_id",
                                 flow_to_process->flow_id,
                                 "size",
                                 SIZEOF_FLOW_STRUCT);
            return;
        }
        memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

        flow_to_process->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
        if (flow_to_process->ndpi_src == NULL)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 NDPI_ID_MEMORY_ALLOCATION_FAILED,
                                 "%s%u %s%zu %s%s",
                                 "flow_id",
                                 flow_to_process->flow_id,
                                 "size",
                                 SIZEOF_ID_STRUCT,
                                 "direction",
                                 "src");
            return;
        }

        flow_to_process->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
        if (flow_to_process->ndpi_dst == NULL)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 NDPI_ID_MEMORY_ALLOCATION_FAILED,
                                 "%s%u %s%zu %s%s",
                                 "flow_id",
                                 flow_to_process->flow_id,
                                 "size",
                                 SIZEOF_ID_STRUCT,
                                 "direction",
                                 "dst");
            return;
        }
        if (ndpi_tsearch(flow_to_process, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == NULL)
        {
            /* Possible Leak, but should not happen as we'd abort earlier. */
            return;
        }

        ndpi_src = flow_to_process->ndpi_src;
        ndpi_dst = flow_to_process->ndpi_dst;

        is_new_flow = 1;
    }
    else
    {
        flow_to_process = *(struct nDPId_flow_info **)tree_result;

        if (direction_changed != 0)
        {
            ndpi_src = flow_to_process->ndpi_dst;
            ndpi_dst = flow_to_process->ndpi_src;
        }
        else
        {
            ndpi_src = flow_to_process->ndpi_src;
            ndpi_dst = flow_to_process->ndpi_dst;
        }
    }

    flow_to_process->packets_processed++;
    flow_to_process->total_l4_data_len += l4_len;
    /* update timestamps, important for timeout handling */
    if (flow_to_process->first_seen == 0)
    {
        flow_to_process->first_seen = time_ms;
    }
    flow_to_process->last_seen = time_ms;

    if (l4_len > flow_to_process->max_l4_data_len)
    {
        flow_to_process->max_l4_data_len = l4_len;
    }
    if (l4_len < flow_to_process->min_l4_data_len)
    {
        flow_to_process->min_l4_data_len = l4_len;
    }

    if (is_new_flow != 0)
    {
        flow_to_process->max_l4_data_len = l4_len;
        flow_to_process->min_l4_data_len = l4_len;
        jsonize_flow_event(reader_thread, flow_to_process, FLOW_EVENT_NEW);
    }

    jsonize_packet_event(reader_thread, header, packet, type, ip_offset, flow_to_process, PACKET_EVENT_PAYLOAD_FLOW);

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    if (flow.flow_fin_rst_seen != 0)
    {
        flow_to_process->flow_fin_rst_seen = 1;
    }

    /* We currently process max. 254 packets per flow. TODO: The user should decide this! */
    if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFF)
    {
        return;
    }
    else if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFE)
    {
        if (flow_to_process->detection_completed != 0)
        {
            jsonize_flow_event(reader_thread, flow_to_process, FLOW_EVENT_DETECTED);
        }
        else
        {
            /* last chance to guess something, better then nothing */
            uint8_t protocol_was_guessed = 0;
            flow_to_process->guessed_l7_protocol =
                ndpi_detection_giveup(workflow->ndpi_struct, flow_to_process->ndpi_flow, 1, &protocol_was_guessed);
            if (protocol_was_guessed != 0)
            {
                jsonize_flow_event(reader_thread, flow_to_process, FLOW_EVENT_GUESSED);
            }
            else
            {
                jsonize_flow_event(reader_thread, flow_to_process, FLOW_EVENT_NOT_DETECTED);
            }
        }
    }

    flow_to_process->detected_l7_protocol = ndpi_detection_process_packet(workflow->ndpi_struct,
                                                                          flow_to_process->ndpi_flow,
                                                                          ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6,
                                                                          ip_size,
                                                                          time_ms,
                                                                          ndpi_src,
                                                                          ndpi_dst);

    if (ndpi_is_protocol_detected(workflow->ndpi_struct, flow_to_process->detected_l7_protocol) != 0 &&
        flow_to_process->detection_completed == 0)
    {
        flow_to_process->detection_completed = 1;
        workflow->detected_flow_protocols++;
        jsonize_flow_event(reader_thread, flow_to_process, FLOW_EVENT_DETECTED);
        flow_to_process->last_ndpi_flow_struct_hash = calculate_ndpi_flow_struct_hash(flow_to_process->ndpi_flow);
    }
    else if (flow_to_process->detection_completed == 1)
    {
        uint32_t hash = calculate_ndpi_flow_struct_hash(flow_to_process->ndpi_flow);
        if (hash != flow_to_process->last_ndpi_flow_struct_hash)
        {
            jsonize_flow_event(reader_thread, flow_to_process, FLOW_EVENT_DETECTION_UPDATE);
            flow_to_process->last_ndpi_flow_struct_hash = hash;
        }
    }
}

static void run_pcap_loop(struct nDPId_reader_thread const * const reader_thread)
{
    if (reader_thread->workflow != NULL && reader_thread->workflow->pcap_handle != NULL)
    {

        if (pcap_loop(reader_thread->workflow->pcap_handle, -1, &ndpi_process_packet, (uint8_t *)reader_thread) ==
            PCAP_ERROR)
        {

            syslog(LOG_DAEMON | LOG_ERR,
                   "Error while reading pcap file: '%s'",
                   pcap_geterr(reader_thread->workflow->pcap_handle));
            reader_thread->workflow->error_or_eof = 1;
        }
    }
}

static void break_pcap_loop(struct nDPId_reader_thread * const reader_thread)
{
    if (reader_thread->workflow != NULL && reader_thread->workflow->pcap_handle != NULL)
    {
        pcap_breakloop(reader_thread->workflow->pcap_handle);
    }
}

static void * processing_thread(void * const ndpi_thread_arg)
{
    struct nDPId_reader_thread * const reader_thread = (struct nDPId_reader_thread *)ndpi_thread_arg;

    reader_thread->json_sockfd = -1;
    reader_thread->json_sock_reconnect = 1;

    errno = 0;
    if (connect_to_json_socket(reader_thread) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "Thread %u: Could not connect to JSON sink %s, will try again later. Error: %s",
               reader_thread->array_index,
               json_sockpath,
               (errno != 0 ? strerror(errno) : "Internal Error."));
    }
    else
    {
        jsonize_daemon(reader_thread, DAEMON_EVENT_INIT);
    }

    run_pcap_loop(reader_thread);
    fcntl(reader_thread->json_sockfd, F_SETFL, fcntl(reader_thread->json_sockfd, F_GETFL, 0) & ~O_NONBLOCK);
    reader_thread->workflow->error_or_eof = 1;
    return NULL;
}

static int processing_threads_error_or_eof(void)
{
    for (unsigned long long int i = 0; i < reader_thread_count; ++i)
    {
        if (reader_threads[i].workflow->error_or_eof == 0)
        {
            return 0;
        }
    }
    return 1;
}

static int start_reader_threads(void)
{
    sigset_t thread_signal_set, old_signal_set;

    sigfillset(&thread_signal_set);
    sigdelset(&thread_signal_set, SIGINT);
    sigdelset(&thread_signal_set, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &thread_signal_set, &old_signal_set) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "pthread_sigmask: %s", strerror(errno));
        return 1;
    }

    if (daemonize_with_pidfile(pidfile) != 0)
    {
        return 1;
    }
    closelog();
    openlog("nDPId", LOG_CONS | (log_to_stderr != 0 ? LOG_PERROR : 0), LOG_DAEMON);

    errno = 0;
    if (change_user_group(user, group, pidfile, NULL, NULL) != 0)
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

    for (unsigned long long int i = 0; i < reader_thread_count; ++i)
    {
        reader_threads[i].array_index = i;

        if (reader_threads[i].workflow == NULL)
        {
            /* no more threads should be started */
            break;
        }

        if (pthread_create(&reader_threads[i].thread_id, NULL, processing_thread, &reader_threads[i]) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "pthread_create: %s", strerror(errno));
            return 1;
        }
    }

    if (pthread_sigmask(SIG_BLOCK, &old_signal_set, NULL) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "pthread_sigmask: %s", strerror(errno));
        return 1;
    }

    return 0;
}

static void ndpi_shutdown_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    struct nDPId_workflow * const workflow = (struct nDPId_workflow *)user_data;
    struct nDPId_flow_info * const flow = *(struct nDPId_flow_info **)A;

    (void)depth;

    if (workflow == NULL || flow == NULL)
    {
        return;
    }

    if (workflow->cur_idle_flows == max_idle_flows_per_thread)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
        workflow->total_idle_flows++;
    }
}

static int stop_reader_threads(void)
{
    unsigned long long int total_packets_processed = 0;
    unsigned long long int total_l4_data_len = 0;
    unsigned long long int total_flows_captured = 0;
    unsigned long long int total_flows_idle = 0;
    unsigned long long int total_flows_detected = 0;

    for (unsigned long long int i = 0; i < reader_thread_count; ++i)
    {
        break_pcap_loop(&reader_threads[i]);
    }

    printf("------------------------------------ Stopping reader threads\n");
    for (unsigned long long int i = 0; i < reader_thread_count; ++i)
    {
        if (reader_threads[i].workflow == NULL)
        {
            continue;
        }

        if (pthread_join(reader_threads[i].thread_id, NULL) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "pthread_join: %s", strerror(errno));
        }
    }

    printf("------------------------------------ Processing remaining flows\n");
    for (unsigned long long int i = 0; i < reader_thread_count; ++i)
    {
        for (size_t idle_scan_index = 0; idle_scan_index < reader_threads[i].workflow->max_active_flows;
             ++idle_scan_index)
        {
            ndpi_twalk(reader_threads[i].workflow->ndpi_flows_active[idle_scan_index],
                       ndpi_shutdown_walker,
                       reader_threads[i].workflow);
            process_idle_flow(&reader_threads[i], idle_scan_index);
        }

        jsonize_daemon(&reader_threads[i], DAEMON_EVENT_SHUTDOWN);
        fsync(reader_threads[i].json_sockfd);
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000};
        nanosleep(&ts, NULL); // ugly; make sure that DAEMON_EVENT_SHUTDOWN gets transmitted before close()

        close(reader_threads[i].json_sockfd);
        reader_threads[i].json_sockfd = -1;
    }

    printf("------------------------------------ Results\n");
    for (unsigned long long int i = 0; i < reader_thread_count; ++i)
    {
        if (reader_threads[i].workflow == NULL)
        {
            continue;
        }

        total_packets_processed += reader_threads[i].workflow->packets_processed;
        total_l4_data_len += reader_threads[i].workflow->total_l4_data_len;
        total_flows_captured += reader_threads[i].workflow->total_active_flows;
        total_flows_idle += reader_threads[i].workflow->total_idle_flows;
        total_flows_detected += reader_threads[i].workflow->detected_flow_protocols;

        printf(
            "Stopping Thread %d, processed %10llu packets, %12llu bytes, total flows: %8llu, "
            "idle flows: %8llu, detected flows: %8llu\n",
            reader_threads[i].array_index,
            reader_threads[i].workflow->packets_processed,
            reader_threads[i].workflow->total_l4_data_len,
            reader_threads[i].workflow->total_active_flows,
            reader_threads[i].workflow->total_idle_flows,
            reader_threads[i].workflow->detected_flow_protocols);
    }
    /* total packets captured: same value for all threads as packet2thread distribution happens later */
    printf("Total packets captured.: %llu\n", reader_threads[0].workflow->packets_captured);
    printf("Total packets processed: %llu\n", total_packets_processed);
    printf("Total layer4 data size.: %llu\n", total_l4_data_len);
    printf("Total flows captured...: %llu\n", total_flows_captured);
    printf("Total flows timed out..: %llu\n", total_flows_idle);
    printf("Total flows detected...: %llu\n", total_flows_detected);

    return 0;
}

static void free_reader_threads(void)
{
    for (unsigned long long int i = 0; i < reader_thread_count; ++i)
    {
        if (reader_threads[i].workflow == NULL)
        {
            continue;
        }

        free_workflow(&reader_threads[i].workflow);
    }
}

static void sighandler(int signum)
{
    syslog(LOG_DAEMON | LOG_NOTICE, "Received SIGNAL %d", signum);

    if (main_thread_shutdown == 0)
    {
        syslog(LOG_DAEMON | LOG_NOTICE, "Stopping reader threads.");
        main_thread_shutdown = 1;
        if (stop_reader_threads() != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Failed to stop reader threads!");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        syslog(LOG_DAEMON | LOG_NOTICE, "Reader threads are already shutting down, please be patient.");
    }
}

static void print_subopt_usage(void)
{
    enum nDPId_subopts index = 0;
    char * const * token = &subopt_token[0];

    fprintf(stderr, "\tsubopts:\n");
    do
    {
        if (*token != NULL)
        {
            fprintf(stderr, "\t\t%s = ", *token);
            switch (index++)
            {
                case MAX_FLOWS_PER_THREAD:
                    fprintf(stderr, "%llu\n", max_flows_per_thread);
                    break;
                case MAX_IDLE_FLOWS_PER_THREAD:
                    fprintf(stderr, "%llu\n", max_idle_flows_per_thread);
                    break;
                case TICK_RESOLUTION:
                    fprintf(stderr, "%llu\n", tick_resolution);
                    break;
                case MAX_READER_THREADS:
                    fprintf(stderr, "%llu\n", reader_thread_count);
                    break;
                case IDLE_SCAN_PERIOD:
                    fprintf(stderr, "%llu\n", idle_scan_period);
                    break;
                case MAX_IDLE_TIME:
                    fprintf(stderr, "%llu\n", max_idle_time);
                    break;
                case MAX_POST_END_FLOW_TIME:
                    fprintf(stderr, "%llu\n", max_post_end_flow_time);
                    break;
                case MAX_PACKETS_PER_FLOW_TO_SEND:
                    fprintf(stderr, "%llu\n", max_packets_per_flow_to_send);
                    break;
                default:
                    break;
            }
        }
        else
        {
            break;
        }
        token++;
    } while (1);
}

static int parse_options(int argc, char ** argv)
{
    int opt;

    static char const usage[] =
        "Usage: %s "
        "[-i pcap-file/interface ] "
        "[-l] [-c path-to-unix-sock] "
        "[-d] [-p pidfile] "
        "[-u user] [-g group] "
        "[-a instance-alias] "
        "[-o subopt=value]\n\n"
        "\t-i\tInterface or file from where to read packets from.\n"
        "\t-l\tLog all messages to stderr as well.\n"
        "\t-c\tPath to the Collector UNIX socket which acts as the JSON sink.\n"
        "\t-d\tForking into background after initialization.\n"
        "\t-p\tWrite the daemon PID to the given file path.\n"
        "\t-u\tChange UID to the numeric value of user.\n"
        "\t-g\tChange GID to the numeric value of group.\n"
        "\t-a\tSet an optional name of this daemon instance which will be part of every JSON message.\n"
        "\t-o\t(Carefully) Tune some daemon options. See subopts below.\n\n";

    while ((opt = getopt(argc, argv, "hi:lc:dp:u:g:a:o:")) != -1)
    {
        switch (opt)
        {
            case 'i':
                pcap_file_or_interface = strdup(optarg);
                break;
            case 'l':
                log_to_stderr = 1;
                if (setvbuf(stderr, NULL, _IOLBF, 0) != 0)
                {
                    fprintf(stderr,
                            "%s: Could not set stderr line-buffered, "
                            "console syslog() messages may appear weird.\n",
                            argv[0]);
                }
                break;
            case 'c':
                strncpy(json_sockpath, optarg, sizeof(json_sockpath) - 1);
                json_sockpath[sizeof(json_sockpath) - 1] = '\0';
                break;
            case 'd':
                daemonize_enable();
                break;
            case 'p':
                strncpy(pidfile, optarg, sizeof(pidfile) - 1);
                pidfile[sizeof(pidfile) - 1] = '\0';
                break;
            case 'u':
                user = strdup(optarg);
                break;
            case 'g':
                group = strdup(optarg);
                break;
            case 'a':
                instance_alias = strdup(optarg);
                break;
            case 'o':
            {
                int errfnd = 0;
                char * subopts = optarg;
                char * value;

                while (*subopts != '\0' && !errfnd)
                {
                    char * endptr;
                    int subopt = getsubopt(&subopts, subopt_token, &value);
                    if (subopt == -1)
                    {
                        fprintf(stderr, "Invalid subopt: %s\n\n", value);
                        fprintf(stderr, usage, argv[0]);
                        print_subopt_usage();
                        return 1;
                    }

                    long int value_llu = strtoull(value, &endptr, 10);
                    if (value == endptr)
                    {
                        fprintf(stderr,
                                "Subopt `%s': Value `%s' is not a valid number.\n",
                                subopt_token[subopt],
                                value);
                        return 1;
                    }
                    if (errno == ERANGE)
                    {
                        fprintf(stderr, "Subopt `%s': Number too large.\n", subopt_token[subopt]);
                        return 1;
                    }

                    switch ((enum nDPId_subopts)subopt)
                    {
                        case MAX_FLOWS_PER_THREAD:
                            max_flows_per_thread = value_llu;
                            break;
                        case MAX_IDLE_FLOWS_PER_THREAD:
                            max_idle_flows_per_thread = value_llu;
                            break;
                        case TICK_RESOLUTION:
                            tick_resolution = value_llu;
                            break;
                        case MAX_READER_THREADS:
                            reader_thread_count = value_llu;
                            break;
                        case IDLE_SCAN_PERIOD:
                            idle_scan_period = value_llu;
                            break;
                        case MAX_IDLE_TIME:
                            max_idle_time = value_llu;
                            break;
                        case MAX_POST_END_FLOW_TIME:
                            max_post_end_flow_time = value_llu;
                            break;
                        case MAX_PACKETS_PER_FLOW_TO_SEND:
                            max_packets_per_flow_to_send = value_llu;
                            break;
                    }
                }
                break;
            }
            default:
                fprintf(stderr, usage, argv[0]);
                print_subopt_usage();
                return 1;
        }
    }

    if (optind < argc)
    {
        fprintf(stderr, "Unexpected argument after options\n\n");
        fprintf(stderr, usage, argv[0]);
        print_subopt_usage();
        return 1;
    }

    return 0;
}

static int validate_options(char const * const arg0)
{
    int retval = 0;

    if (max_flows_per_thread < 128 || max_flows_per_thread > nDPId_MAX_FLOWS_PER_THREAD)
    {
        fprintf(stderr, "%s: 128 < max-flows-per-thread < %d\n", arg0, nDPId_MAX_FLOWS_PER_THREAD);
        retval = 1;
    }
    if (max_idle_flows_per_thread < 64 || max_idle_flows_per_thread > nDPId_MAX_IDLE_FLOWS_PER_THREAD)
    {
        fprintf(stderr, "%s: 64 < max-idle-flows-per-thread < %d\n", arg0, nDPId_MAX_IDLE_FLOWS_PER_THREAD);
        retval = 1;
    }
    if (tick_resolution < 100)
    {
        fprintf(stderr, "%s: tick-resolution > 100\n", arg0);
        retval = 1;
    }
    if (reader_thread_count < 1 || reader_thread_count > nDPId_MAX_READER_THREADS)
    {
        fprintf(stderr, "%s: 1 < reader-thread-count < %d\n", arg0, nDPId_MAX_READER_THREADS);
        retval = 1;
    }
    if (idle_scan_period < 1000)
    {
        fprintf(stderr, "%s: idle-scan-period > 1000\n", arg0);
        retval = 1;
    }
    if (max_idle_time < 60)
    {
        fprintf(stderr, "%s: max-idle-time > 60\n", arg0);
        retval = 1;
    }
    if (max_post_end_flow_time > max_idle_time)
    {
        fprintf(stderr, "%s: max-post-end-flow-time < max_idle_time\n", arg0);
        retval = 1;
    }

    return retval;
}

int main(int argc, char ** argv)
{
    if (argc == 0)
    {
        return 1;
    }

    if (parse_options(argc, argv) != 0)
    {
        return 1;
    }
    if (validate_options(argv[0]) != 0)
    {
        fprintf(stderr, "%s: Option validation failed.\n", argv[0]);
        return 1;
    }

    printf(
        "----------------------------------\n"
        "nDPI version: %s\n"
        " API version: %u\n"
        "pcap version: %s\n"
        "----------------------------------\n",
        ndpi_revision(),
        ndpi_get_api_version(),
        pcap_lib_version() + strlen("libpcap version "));
    if (ndpi_get_gcrypt_version() != NULL)
    {
        printf(
            "gcrypt version: %s\n"
            "----------------------------------\n",
            ndpi_get_gcrypt_version());
    }

    openlog("nDPId", LOG_CONS | LOG_PERROR, LOG_DAEMON);

    if (setup_reader_threads() != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "setup_reader_threads failed");
        return 1;
    }

    if (start_reader_threads() != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "start_reader_threads failed");
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    while (main_thread_shutdown == 0 && processing_threads_error_or_eof() == 0)
    {
        sleep(1);
    }

    if (main_thread_shutdown == 0 && stop_reader_threads() != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "stop_reader_threads");
        return 1;
    }
    free_reader_threads();

    daemonize_shutdown(pidfile);
    syslog(LOG_DAEMON | LOG_NOTICE, "Bye.");
    closelog();

    return 0;
}
