#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <net/if.h>
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
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#ifndef NO_MAIN
#include <syslog.h>
#endif
#include <unistd.h>
#ifdef ENABLE_ZLIB
#include <zlib.h>
#endif

#include "config.h"
#include "utils.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#ifndef ETHERTYPE_DCE
#define ETHERTYPE_DCE 0x8903
#endif

#ifndef ETHERTYPE_PAE
#define ETHERTYPE_PAE 0x888e
#endif

#if ((NDPI_MAJOR == 3 && NDPI_MINOR < 5) || NDPI_MAJOR < 3) && NDPI_API_VERSION < 4087
#error "nDPI >= 3.5.0 or API version >= 4087 required"
#endif

#if !defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4) || !defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)
#error "Compare and Swap aka __sync_fetch_and_add not available on your platform!"
#endif

#if nDPId_MAX_READER_THREADS <= 0
#error "Invalid value for nDPId_MAX_READER_THREADS"
#endif

#if nDPId_FLOW_SCAN_INTERVAL > nDPId_GENERIC_IDLE_TIME || nDPId_FLOW_SCAN_INTERVAL > nDPId_ICMP_IDLE_TIME ||           \
    nDPId_FLOW_SCAN_INTERVAL > nDPId_TCP_IDLE_TIME || nDPId_FLOW_SCAN_INTERVAL > nDPId_UDP_IDLE_TIME
#error "Invalid value for nDPId_FLOW_SCAN_INTERVAL"
#endif

enum nDPId_l3_type
{
    L3_IP,
    L3_IP6
};

union nDPId_ip
{
    struct
    {
        uint32_t ip;
    } v4;
    struct
    {
        union
        {
            uint64_t ip[2];
            uint32_t ip_u32[4];
        };
    } v6;
};

enum nDPId_flow_type
{
    FT_UNKNOWN = 0, // should never happen, bug otherwise
    FT_SKIPPED,     // flow should not be processed, see command line args -I and -E
    FT_FINISHED,    // detection done and detection data free'd
    FT_INFO         // detection in progress, detection data allocated
};

/*
 * Minimal per-flow information required for flow mgmt and timeout handling.
 */
struct nDPId_flow_basic
{
    enum nDPId_flow_type type;
    enum nDPId_l3_type l3_type;
    uint64_t hashval;
    union nDPId_ip src;
    union nDPId_ip dst;
    uint8_t l4_protocol;
    uint8_t tcp_fin_rst_seen : 1;
    uint8_t tcp_is_midstream_flow : 1;
    uint8_t reserved_00 : 6;
    uint8_t reserved_01[2];
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t last_seen;
};

/*
 * Information required for a full detection cycle.
 */
struct nDPId_flow_extended
{
    struct nDPId_flow_basic flow_basic;

    unsigned int long long flow_id;

    uint16_t min_l4_payload_len;
    uint16_t max_l4_payload_len;

    unsigned long long int packets_processed;
    uint64_t first_seen;
    uint64_t last_flow_update;

    unsigned long long int total_l4_payload_len;
};

/*
 * Skipped flows need at least some information.
 */
struct nDPId_flow_skipped
{
    struct nDPId_flow_basic flow_basic;
};

/*
 * Structure which is important for the detection process.
 * The structure is also a compression target, if activated.
 */
struct nDPId_detection_data
{
    uint32_t last_ndpi_flow_struct_hash;
    struct ndpi_proto detected_l7_protocol;
    struct ndpi_proto guessed_l7_protocol;
    struct ndpi_flow_struct flow;
    struct ndpi_id_struct src;
    struct ndpi_id_struct dst;
};

struct nDPId_flow_info
{
    struct nDPId_flow_extended flow_extended;

    uint8_t detection_completed : 1;
    uint8_t reserved_00 : 7;
    uint8_t reserved_01[1];
#ifdef ENABLE_ZLIB
    uint16_t detection_data_compressed_size;
#else
    uint16_t reserved_02;
#endif
    struct nDPId_detection_data * detection_data;
};

struct nDPId_flow_finished
{
    struct nDPId_flow_info flow_info;
};

struct nDPId_workflow
{
    pcap_t * pcap_handle;

    uint16_t error_or_eof;
    uint16_t is_pcap_file;

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_skipped_flows;
    unsigned long long int total_l4_data_len;

    unsigned long long int total_not_detected_flows;
    unsigned long long int total_guessed_flows;
    unsigned long long int total_detected_flows;
    unsigned long long int total_flow_detection_updates;
    unsigned long long int total_flow_updates;

#ifdef ENABLE_MEMORY_PROFILING
    uint64_t last_memory_usage_log_time;
#endif
#ifdef ENABLE_ZLIB
    uint64_t last_compression_scan_time;
#endif
    uint64_t last_scan_time;
    uint64_t last_time;

    void ** ndpi_flows_active;
    unsigned long long int max_active_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int total_active_flows;

    void ** ndpi_flows_idle;
    unsigned long long int max_idle_flows;
    unsigned long long int cur_idle_flows;
    unsigned long long int total_idle_flows;

    unsigned long long int total_events_serialized;

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

    PACKET_EVENT_PAYLOAD,      // A single packet that does not belong to a flow for whatever reasons.
                               // E.g. it could be malformed and thus no flow handling is done.
                               // There may be additional use-cases in the future.
    PACKET_EVENT_PAYLOAD_FLOW, // Special case; A packet event that belongs to a flow but does not include all
                               // information a flow event requires.

    PACKET_EVENT_COUNT
};

enum flow_event
{
    FLOW_EVENT_INVALID = 0,

    FLOW_EVENT_NEW,
    FLOW_EVENT_END,
    FLOW_EVENT_IDLE,
    FLOW_EVENT_UPDATE, // Inform distributor applications about flows with a long lifetime.

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
    UNSUPPORTED_DATALINK_LAYER,
    PACKET_TOO_SHORT,
    PACKET_TYPE_UNKNOWN,
    PACKET_HEADER_INVALID,
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

static char const * const packet_event_name_table[PACKET_EVENT_COUNT] = {
    [PACKET_EVENT_INVALID] = "invalid", [PACKET_EVENT_PAYLOAD] = "packet", [PACKET_EVENT_PAYLOAD_FLOW] = "packet-flow"};

static char const * const flow_event_name_table[FLOW_EVENT_COUNT] = {[FLOW_EVENT_INVALID] = "invalid",
                                                                     [FLOW_EVENT_NEW] = "new",
                                                                     [FLOW_EVENT_END] = "end",
                                                                     [FLOW_EVENT_IDLE] = "idle",
                                                                     [FLOW_EVENT_UPDATE] = "update",
                                                                     [FLOW_EVENT_GUESSED] = "guessed",
                                                                     [FLOW_EVENT_DETECTED] = "detected",
                                                                     [FLOW_EVENT_DETECTION_UPDATE] = "detection-update",
                                                                     [FLOW_EVENT_NOT_DETECTED] = "not-detected"};
static char const * const basic_event_name_table[BASIC_EVENT_COUNT] = {
    [BASIC_EVENT_INVALID] = "invalid",
    [UNKNOWN_DATALINK_LAYER] = "Unknown datalink layer packet",
    [UNKNOWN_L3_PROTOCOL] = "Unknown L3 protocol",
    [UNSUPPORTED_DATALINK_LAYER] = "Unsupported datalink layer",
    [PACKET_TOO_SHORT] = "Packet too short",
    [PACKET_TYPE_UNKNOWN] = "Unknown packet type",
    [PACKET_HEADER_INVALID] = "Packet header invalid",
    [IP4_PACKET_TOO_SHORT] = "IP4 packet too short",
    [IP4_SIZE_SMALLER_THAN_HEADER] = "Packet smaller than IP4 header",
    [IP4_L4_PAYLOAD_DETECTION_FAILED] = "nDPI IPv4/L4 payload detection failed",
    [IP6_PACKET_TOO_SHORT] = "IP6 packet too short",
    [IP6_SIZE_SMALLER_THAN_HEADER] = "Packet smaller than IP6 header",
    [IP6_L4_PAYLOAD_DETECTION_FAILED] = "nDPI IPv6/L4 payload detection failed",
    [TCP_PACKET_TOO_SHORT] = "TCP packet smaller than expected",
    [UDP_PACKET_TOO_SHORT] = "UDP packet smaller than expected",
    [CAPTURE_SIZE_SMALLER_THAN_PACKET_SIZE] = "Captured packet size is smaller than expected packet size",
    [MAX_FLOW_TO_TRACK] = "Max flows to track reached",
    [FLOW_MEMORY_ALLOCATION_FAILED] = "Flow memory allocation failed",
};

static char const * const daemon_event_name_table[DAEMON_EVENT_COUNT] = {
    [DAEMON_EVENT_INVALID] = "invalid",
    [DAEMON_EVENT_INIT] = "init",
    [DAEMON_EVENT_RECONNECT] = "reconnect",
    [DAEMON_EVENT_SHUTDOWN] = "shutdown",
};

static struct nDPId_reader_thread reader_threads[nDPId_MAX_READER_THREADS] = {};
static int nDPId_main_thread_shutdown = 0;
static uint64_t global_flow_id = 1;
static int ip4_interface_avail = 0, ip6_interface_avail = 0;

#ifdef ENABLE_MEMORY_PROFILING
static uint64_t ndpi_memory_alloc_count = 0;
static uint64_t ndpi_memory_alloc_bytes = 0;
static uint64_t ndpi_memory_free_count = 0;
static uint64_t ndpi_memory_free_bytes = 0;
#ifdef ENABLE_ZLIB
static uint64_t zlib_compressions = 0;
static uint64_t zlib_decompressions = 0;
static uint64_t zlib_compression_diff = 0;
#endif
#endif

static struct
{
    /* opts */
    char * pcap_file_or_interface;
    union nDPId_ip pcap_dev_ip4, pcap_dev_ip6;
    union nDPId_ip pcap_dev_netmask4, pcap_dev_netmask6;
    union nDPId_ip pcap_dev_subnet4, pcap_dev_subnet6;
    uint8_t process_internal_initial_direction;
    uint8_t process_external_initial_direction;
    char * bpf_str;
    int log_to_stderr;
    char pidfile[UNIX_PATH_MAX];
    char * user;
    char * group;
    char * custom_protocols_file;
    char * custom_categories_file;
    char * custom_ja3_file;
    char * custom_sha1_file;
    char json_sockpath[UNIX_PATH_MAX];
#ifdef ENABLE_ZLIB
    uint8_t enable_zlib_compression;
#endif
    /* subopts */
    char * instance_alias;
    unsigned long long int max_flows_per_thread;
    unsigned long long int max_idle_flows_per_thread;
    unsigned long long int tick_resolution;
    unsigned long long int reader_thread_count;
#ifdef ENABLE_MEMORY_PROFILING
    unsigned long long int memory_profiling_log_interval;
#endif
#ifdef ENABLE_ZLIB
    unsigned long long int compression_scan_interval;
    unsigned long long int compression_flow_inactivity;
#endif
    unsigned long long int flow_scan_interval;
    unsigned long long int generic_max_idle_time;
    unsigned long long int icmp_max_idle_time;
    unsigned long long int udp_max_idle_time;
    unsigned long long int tcp_max_idle_time;
    unsigned long long int tcp_max_post_end_flow_time;
    unsigned long long int max_packets_per_flow_to_send;
    unsigned long long int max_packets_per_flow_to_process;
} nDPId_options = {.pidfile = nDPId_PIDFILE,
                   .user = "nobody",
                   .json_sockpath = COLLECTOR_UNIX_SOCKET,
                   .max_flows_per_thread = nDPId_MAX_FLOWS_PER_THREAD / 2,
                   .max_idle_flows_per_thread = nDPId_MAX_IDLE_FLOWS_PER_THREAD / 2,
                   .tick_resolution = nDPId_TICK_RESOLUTION,
                   .reader_thread_count = nDPId_MAX_READER_THREADS / 2,
#ifdef ENABLE_MEMORY_PROFILING
                   .memory_profiling_log_interval = nDPId_MEMORY_PROFILING_LOG_INTERVAL,
#endif
#ifdef ENABLE_ZLIB
                   .compression_scan_interval = nDPId_COMPRESSION_SCAN_INTERVAL,
                   .compression_flow_inactivity = nDPId_COMPRESSION_FLOW_INACTIVITY,
#endif
                   .flow_scan_interval = nDPId_FLOW_SCAN_INTERVAL,
                   .generic_max_idle_time = nDPId_GENERIC_IDLE_TIME,
                   .icmp_max_idle_time = nDPId_ICMP_IDLE_TIME,
                   .udp_max_idle_time = nDPId_UDP_IDLE_TIME,
                   .tcp_max_idle_time = nDPId_TCP_IDLE_TIME,
                   .tcp_max_post_end_flow_time = nDPId_TCP_POST_END_FLOW_TIME,
                   .max_packets_per_flow_to_send = nDPId_PACKETS_PER_FLOW_TO_SEND,
                   .max_packets_per_flow_to_process = nDPId_PACKETS_PER_FLOW_TO_PROCESS};

enum nDPId_subopts
{
    MAX_FLOWS_PER_THREAD = 0,
    MAX_IDLE_FLOWS_PER_THREAD,
    TICK_RESOLUTION,
    MAX_READER_THREADS,
#ifdef ENABLE_MEMORY_PROFILING
    MEMORY_PROFILING_LOG_INTERVAL,
#endif
#ifdef ENABLE_ZLIB
    COMPRESSION_SCAN_INTERVAL,
    COMPRESSION_FLOW_INACTIVITY,
#endif
    FLOW_SCAN_INTVERAL,
    GENERIC_MAX_IDLE_TIME,
    ICMP_MAX_IDLE_TIME,
    UDP_MAX_IDLE_TIME,
    TCP_MAX_IDLE_TIME,
    TCP_MAX_POST_END_FLOW_TIME,
    MAX_PACKETS_PER_FLOW_TO_SEND,
    MAX_PACKETS_PER_FLOW_TO_PROCESS,
};
static char * const subopt_token[] = {[MAX_FLOWS_PER_THREAD] = "max-flows-per-thread",
                                      [MAX_IDLE_FLOWS_PER_THREAD] = "max-idle-flows-per-thread",
                                      [TICK_RESOLUTION] = "tick-resolution",
                                      [MAX_READER_THREADS] = "max-reader-threads",
#ifdef ENABLE_MEMORY_PROFILING
                                      [MEMORY_PROFILING_LOG_INTERVAL] = "memory-profiling-log-interval",
#endif
#ifdef ENABLE_ZLIB
                                      [COMPRESSION_SCAN_INTERVAL] = "compression-scan-interval",
                                      [COMPRESSION_FLOW_INACTIVITY] = "compression-flow-activity",
#endif
                                      [FLOW_SCAN_INTVERAL] = "flow-scan-interval",
                                      [GENERIC_MAX_IDLE_TIME] = "generic-max-idle-time",
                                      [ICMP_MAX_IDLE_TIME] = "icmp-max-idle-time",
                                      [UDP_MAX_IDLE_TIME] = "udp-max-idle-time",
                                      [TCP_MAX_IDLE_TIME] = "tcp-max-idle-time",
                                      [TCP_MAX_POST_END_FLOW_TIME] = "tcp-max-post-end-flow-time",
                                      [MAX_PACKETS_PER_FLOW_TO_SEND] = "max-packets-per-flow-to-send",
                                      [MAX_PACKETS_PER_FLOW_TO_PROCESS] = "max-packets-per-flow-to-process",
                                      NULL};

static int processing_threads_error_or_eof(void);
static void free_workflow(struct nDPId_workflow ** const workflow);
static void serialize_and_send(struct nDPId_reader_thread * const reader_thread);
static void jsonize_flow_event(struct nDPId_reader_thread * const reader_thread,
                               struct nDPId_flow_extended * const flow_ext,
                               enum flow_event event);
static void jsonize_flow_detection_event(struct nDPId_reader_thread * const reader_thread,
                                         struct nDPId_flow_info * const flow_info,
                                         enum flow_event event);

#ifdef ENABLE_ZLIB
static int zlib_deflate(const void * const src, int srcLen, void * dst, int dstLen)
{
    z_stream strm = {0};
    strm.total_in = strm.avail_in = srcLen;
    strm.total_out = strm.avail_out = dstLen;
    strm.next_in = (Bytef *)src;
    strm.next_out = (Bytef *)dst;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    int err = -1;
    int ret = -1;

    err = deflateInit(&strm, Z_BEST_COMPRESSION);
    if (err == Z_OK)
    {
        err = deflate(&strm, Z_FINISH);
        if (err == Z_STREAM_END)
        {
            ret = strm.total_out;
#ifdef ENABLE_MEMORY_PROFILING
            __sync_fetch_and_add(&zlib_compressions, 1);
            __sync_fetch_and_add(&zlib_compression_diff, srcLen - ret);
#endif
        }
        else
        {
            deflateEnd(&strm);
            return err;
        }
    }
    else
    {
        deflateEnd(&strm);
        return err;
    }

    deflateEnd(&strm);
    return ret;
}

static int zlib_inflate(const void * src, int srcLen, void * dst, int dstLen)
{
    z_stream strm = {0};
    strm.total_in = strm.avail_in = srcLen;
    strm.total_out = strm.avail_out = dstLen;
    strm.next_in = (Bytef *)src;
    strm.next_out = (Bytef *)dst;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    int err = -1;
    int ret = -1;

    err = inflateInit2(&strm, (15 + 32)); // 15 window bits, and the +32 tells zlib to to detect if using gzip or zlib
    if (err == Z_OK)
    {
        err = inflate(&strm, Z_FINISH);
        if (err == Z_STREAM_END)
        {
            ret = strm.total_out;
#ifdef ENABLE_MEMORY_PROFILING
            __sync_fetch_and_add(&zlib_decompressions, 1);
            __sync_fetch_and_sub(&zlib_compression_diff, ret - srcLen);
#endif
        }
        else
        {
            inflateEnd(&strm);
            return err;
        }
    }
    else
    {
        inflateEnd(&strm);
        return err;
    }

    inflateEnd(&strm);
    return ret;
}

static int detection_data_deflate(struct nDPId_flow_info * const flow_info)
{
    uint8_t tmpOut[sizeof(*flow_info->detection_data)];
    int ret;

    if (flow_info->detection_data_compressed_size > 0)
    {
        return -7;
    }

    ret = zlib_deflate(flow_info->detection_data, sizeof(*flow_info->detection_data), tmpOut, sizeof(tmpOut));
    if (ret <= 0)
    {
        return ret;
    }

    struct nDPId_detection_data * const new_det_data = ndpi_malloc(ret);
    if (new_det_data == NULL)
    {
        return -8;
    }
    ndpi_free(flow_info->detection_data);
    flow_info->detection_data = new_det_data;

    memcpy(flow_info->detection_data, tmpOut, ret);
    flow_info->detection_data_compressed_size = ret;

    return ret;
}

static int detection_data_inflate(struct nDPId_flow_info * const flow_info)
{
    uint8_t tmpOut[sizeof(*flow_info->detection_data)];
    int ret;

    if (flow_info->detection_data_compressed_size == 0)
    {
        return -7;
    }

    ret = zlib_inflate(flow_info->detection_data, flow_info->detection_data_compressed_size, tmpOut, sizeof(tmpOut));
    if (ret <= 0)
    {
        return ret;
    }

    struct nDPId_detection_data * const new_det_data = ndpi_malloc(ret);
    if (new_det_data == NULL)
    {
        return -8;
    }
    ndpi_free(flow_info->detection_data);
    flow_info->detection_data = new_det_data;

    memcpy(flow_info->detection_data, tmpOut, ret);
    flow_info->detection_data_compressed_size = 0;

    /*
     * The ndpi_id_struct's from ndpi_flow may not be valid anymore.
     * nDPI only updates those pointers while processing packets!
     * This is especially important when using compression
     * to prevent use of dangling pointers.
     */
    flow_info->detection_data->flow.src = &flow_info->detection_data->src;
    flow_info->detection_data->flow.dst = &flow_info->detection_data->dst;

    return ret;
}

static void ndpi_comp_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    struct nDPId_workflow * const workflow = (struct nDPId_workflow *)user_data;
    struct nDPId_flow_basic * const flow_basic = *(struct nDPId_flow_basic **)A;

    (void)depth;

    if (workflow == NULL || flow_basic == NULL)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        switch (flow_basic->type)
        {
            case FT_UNKNOWN:
            case FT_SKIPPED:
            case FT_FINISHED:
                break;

            case FT_INFO:
            {
                if (flow_basic->last_seen + nDPId_options.compression_flow_inactivity < workflow->last_time)
                {
                    struct nDPId_flow_info * const flow_info = (struct nDPId_flow_info *)flow_basic;

                    if (flow_info->detection_data_compressed_size > 0)
                    {
                        break;
                    }

                    int ret = detection_data_deflate(flow_info);

                    if (ret <= 0)
                    {
                        syslog(LOG_DAEMON | LOG_ERR,
                               "zLib compression failed for flow %llu with error code: %d",
                               flow_info->flow_extended.flow_id,
                               ret);
                    }
                }
                break;
            }
        }
    }
}

static void check_for_compressable_flows(struct nDPId_reader_thread * const reader_thread)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    if (workflow->last_compression_scan_time + nDPId_options.compression_scan_interval < workflow->last_time)
    {
        for (size_t comp_scan_index = 0; comp_scan_index < workflow->max_active_flows; ++comp_scan_index)
        {
            ndpi_twalk(workflow->ndpi_flows_active[comp_scan_index], ndpi_comp_scan_walker, workflow);
        }

        workflow->last_compression_scan_time = workflow->last_time;
    }
}
#endif

static void ip_netmask_to_subnet(union nDPId_ip const * const ip,
                                 union nDPId_ip const * const netmask,
                                 union nDPId_ip * const subnet,
                                 enum nDPId_l3_type type)
{
    switch (type)
    {
        case L3_IP:
            subnet->v4.ip = ip->v4.ip & netmask->v4.ip;
            break;
        case L3_IP6:
            subnet->v6.ip[0] = ip->v6.ip[0] & netmask->v6.ip[0];
            subnet->v6.ip[1] = ip->v6.ip[1] & netmask->v6.ip[1];
            break;
    }
}

static int is_ip_in_subnet(union nDPId_ip const * const cmp_ip,
                           union nDPId_ip const * const netmask,
                           union nDPId_ip const * const cmp_subnet,
                           enum nDPId_l3_type const type)
{
    switch (type)
    {
        case L3_IP:
            return (cmp_ip->v4.ip & netmask->v4.ip) == cmp_subnet->v4.ip;
        case L3_IP6:
            return (cmp_ip->v6.ip[0] & netmask->v6.ip[0]) == cmp_subnet->v6.ip[0] &&
                   (cmp_ip->v6.ip[1] & netmask->v6.ip[1]) == cmp_subnet->v6.ip[1];
    }

    return 0;
}

static void get_ip4_from_sockaddr(struct sockaddr_in const * const saddr, union nDPId_ip * dest)
{
    switch (saddr->sin_family)
    {
        case AF_INET:
            dest->v4.ip = saddr->sin_addr.s_addr;
            break;
        case AF_INET6:
            return;
    }
}

static void get_ip6_from_sockaddr(struct sockaddr_in6 const * const saddr, union nDPId_ip * dest)
{
    switch (saddr->sin6_family)
    {
        case AF_INET6:
            dest->v6.ip_u32[0] = saddr->sin6_addr.s6_addr32[0];
            dest->v6.ip_u32[1] = saddr->sin6_addr.s6_addr32[1];
            dest->v6.ip_u32[2] = saddr->sin6_addr.s6_addr32[2];
            dest->v6.ip_u32[3] = saddr->sin6_addr.s6_addr32[3];
            break;
        default:
            return;
    }
}

static int get_ip6_address_and_netmask(char const * const ifa_name, size_t ifnamelen)
{
    FILE * f;
    char addr6[INET6_ADDRSTRLEN], netmask6[INET6_ADDRSTRLEN], subnet6[INET6_ADDRSTRLEN], devname[21];
    struct sockaddr_in6 sap;
    int plen, scope, dad_status, if_idx, retval = 0;
    char addr6p[8][5];

    f = fopen("/proc/net/if_inet6", "r");
    if (f == NULL)
    {
        return 1;
    }

    while (fscanf(f,
                  "%4s%4s%4s%4s%4s%4s%4s%4s %08x %02x %02x %02x %20s\n",
                  addr6p[0],
                  addr6p[1],
                  addr6p[2],
                  addr6p[3],
                  addr6p[4],
                  addr6p[5],
                  addr6p[6],
                  addr6p[7],
                  &if_idx,
                  &plen,
                  &scope,
                  &dad_status,
                  devname) != EOF)
    {
        if (strncmp(devname, ifa_name, ifnamelen) == 0)
        {
            sprintf(addr6,
                    "%s:%s:%s:%s:%s:%s:%s:%s",
                    addr6p[0],
                    addr6p[1],
                    addr6p[2],
                    addr6p[3],
                    addr6p[4],
                    addr6p[5],
                    addr6p[6],
                    addr6p[7]);

            memset(&sap, 0, sizeof(sap));
            if (inet_pton(AF_INET6, addr6, (struct sockaddr *)&sap.sin6_addr) != 1)
            {
                retval = 1;
                goto error;
            }
            inet_ntop(AF_INET6, &sap.sin6_addr, addr6, sizeof(addr6));
            sap.sin6_family = AF_INET6;
            get_ip6_from_sockaddr(&sap, &nDPId_options.pcap_dev_ip6);

            memset(&sap, 0, sizeof(sap));
            memset(&sap.sin6_addr.s6_addr, 0xFF, plen / 8);
            if (plen < 128 && (plen % 32) != 0)
            {
                sap.sin6_addr.s6_addr32[plen / 32] = 0xFFFFFFFF << (32 - (plen % 32));
            }
            inet_ntop(AF_INET6, &sap.sin6_addr, netmask6, sizeof(netmask6));
            sap.sin6_family = AF_INET6;
            get_ip6_from_sockaddr(&sap, &nDPId_options.pcap_dev_netmask6);

            ip_netmask_to_subnet(&nDPId_options.pcap_dev_ip6,
                                 &nDPId_options.pcap_dev_netmask6,
                                 &nDPId_options.pcap_dev_subnet6,
                                 L3_IP6);
            inet_ntop(AF_INET6, &nDPId_options.pcap_dev_subnet6.v6, subnet6, sizeof(subnet6));

            syslog(LOG_DAEMON,
                   "%s IPv6 address/prefix netmask subnet: %s/%u %s %s",
                   nDPId_options.pcap_file_or_interface,
                   addr6,
                   plen,
                   netmask6,
                   subnet6);
        }
    }

error:
    fclose(f);

    return retval;
}

static int get_ip4_address_and_netmask(char const * const ifa_name, size_t ifnamelen)
{
    int retval = 0;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct ifreq ifr;

    if (sock < 0)
    {
        retval = 1;
        goto error;
    }
    if (ifnamelen >= sizeof(ifr.ifr_name))
    {
        retval = 1;
        goto error;
    }

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifa_name, ifnamelen);
    ifr.ifr_name[ifnamelen] = '\0';
    ifr.ifr_netmask.sa_family = AF_INET;
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) == -1)
    {
        retval = 1;
        goto error;
    }
    get_ip4_from_sockaddr((struct sockaddr_in *)&ifr.ifr_netmask, &nDPId_options.pcap_dev_netmask4);

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifa_name, ifnamelen);
    ifr.ifr_name[ifnamelen] = '\0';
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(sock, SIOCGIFADDR, &ifr) == -1)
    {
        retval = 1;
        goto error;
    }
    get_ip4_from_sockaddr((struct sockaddr_in *)&ifr.ifr_netmask, &nDPId_options.pcap_dev_ip4);

    ip_netmask_to_subnet(&nDPId_options.pcap_dev_ip4,
                         &nDPId_options.pcap_dev_netmask4,
                         &nDPId_options.pcap_dev_subnet4,
                         L3_IP);

    {
        char addr[INET_ADDRSTRLEN];
        char netm[INET_ADDRSTRLEN];
        char subn[INET_ADDRSTRLEN];
        void * saddr = &nDPId_options.pcap_dev_ip4.v4.ip;
        void * snetm = &nDPId_options.pcap_dev_netmask4.v4.ip;
        void * ssubn = &nDPId_options.pcap_dev_subnet4.v4.ip;
        syslog(LOG_DAEMON,
               "%s IPv4 address netmask subnet: %s %s %s",
               nDPId_options.pcap_file_or_interface,
               inet_ntop(AF_INET, saddr, addr, sizeof(addr)),
               inet_ntop(AF_INET, snetm, netm, sizeof(netm)),
               inet_ntop(AF_INET, ssubn, subn, sizeof(subn)));
    }

error:
    close(sock);
    return retval;
}

static int get_ip_netmask_from_pcap_dev(char const * const pcap_dev)
{
    int retval = 0, found_dev = 0;
    struct ifaddrs * ifaddrs = NULL;
    struct ifaddrs * ifa;

    if (getifaddrs(&ifaddrs) != 0 || ifaddrs == NULL)
    {
        return 1;
    }

    for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL || (ifa->ifa_flags & IFF_RUNNING) == 0)
        {
            continue;
        }

        size_t ifnamelen = strnlen(ifa->ifa_name, IFNAMSIZ);
        if (strncmp(ifa->ifa_name, pcap_dev, IFNAMSIZ) == 0 && ifnamelen == strnlen(pcap_dev, IFNAMSIZ))
        {
            found_dev = 1;
            switch (ifa->ifa_addr->sa_family)
            {
                case AF_INET:
                    if (ip4_interface_avail == 0 && get_ip4_address_and_netmask(ifa->ifa_name, ifnamelen) != 0)
                    {
                        retval = 1;
                    }
                    ip4_interface_avail = 1;
                    break;
                case AF_INET6:
                    if (ip6_interface_avail == 0 && get_ip6_address_and_netmask(ifa->ifa_name, ifnamelen) != 0)
                    {
                        retval = 1;
                    }
                    ip6_interface_avail = 1;
                    break;
                default:
                    break;
            }
        }
    }

    if (found_dev != 0 &&
        (nDPId_options.process_internal_initial_direction != 0 ||
         nDPId_options.process_external_initial_direction != 0) &&
        ip4_interface_avail == 0 && ip6_interface_avail == 0)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "Interface %s does not have any IPv4 / IPv6 address set, -I / -E won't work.",
               pcap_dev);
        retval = 1;
    }

    freeifaddrs(ifaddrs);
    return retval;
}

#ifdef ENABLE_MEMORY_PROFILING
static void * ndpi_malloc_wrapper(size_t const size)
{
    void * p = malloc(sizeof(uint64_t) + size);

    if (p == NULL)
    {
        return NULL;
    }
    *(uint64_t *)p = size;

    __sync_fetch_and_add(&ndpi_memory_alloc_count, 1);
    __sync_fetch_and_add(&ndpi_memory_alloc_bytes, size);

    return (uint8_t *)p + sizeof(uint64_t);
}

static void ndpi_free_wrapper(void * const freeable)
{
    void * p = (uint8_t *)freeable - sizeof(uint64_t);

    __sync_fetch_and_add(&ndpi_memory_free_count, 1);
    __sync_fetch_and_add(&ndpi_memory_free_bytes, *(uint64_t *)p);

    free(p);
}

static void log_memory_usage(struct nDPId_reader_thread const * const reader_thread)
{
    if (reader_thread->array_index == 0)
    {
        uint64_t alloc_count = __sync_fetch_and_add(&ndpi_memory_alloc_count, 0);
        uint64_t free_count = __sync_fetch_and_add(&ndpi_memory_free_count, 0);
        uint64_t alloc_bytes = __sync_fetch_and_add(&ndpi_memory_alloc_bytes, 0);
        uint64_t free_bytes = __sync_fetch_and_add(&ndpi_memory_free_bytes, 0);

        syslog(LOG_DAEMON,
               "MemoryProfiler: %llu allocs, %llu frees, %llu bytes allocated, %llu bytes freed, %llu blocks in "
               "use, "
               "%llu bytes in use",
               (long long unsigned int)alloc_count,
               (long long unsigned int)free_count,
               (long long unsigned int)alloc_bytes,
               (long long unsigned int)free_bytes,
               (long long unsigned int)(alloc_count - free_count),
               (long long unsigned int)(alloc_bytes - free_bytes));
#ifdef ENABLE_ZLIB
        uint64_t zlib_compression_count = __sync_fetch_and_add(&zlib_compressions, 0);
        uint64_t zlib_decompression_count = __sync_fetch_and_add(&zlib_decompressions, 0);
        uint64_t zlib_bytes_diff = __sync_fetch_and_add(&zlib_compression_diff, 0);

        syslog(LOG_DAEMON,
               "MemoryProfiler (zLib): %llu compressions, %llu decompressions, %llu compressed blocks in use, %llu "
               "bytes "
               "diff",
               (long long unsigned int)zlib_compression_count,
               (long long unsigned int)zlib_decompression_count,
               (long long unsigned int)zlib_compression_count - (long long unsigned int)zlib_decompression_count,
               (long long unsigned int)zlib_bytes_diff);
#endif
    }
}

struct log_flows_user_data
{
    struct nDPId_workflow * workflow;
    unsigned long long int flows_ukn;
    unsigned long long int flows_skp;
    unsigned long long int flows_fin;
    unsigned long long int flows_inf;
    struct nDPId_flow_basic const * flows_active_fin[nDPId_MAX_FLOWS_PER_THREAD];
    struct nDPId_flow_basic const * flows_active_inf[nDPId_MAX_FLOWS_PER_THREAD];
};

static void log_flows_flow_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    struct log_flows_user_data * const log_user_data = (struct log_flows_user_data *)user_data;
    struct nDPId_flow_basic * const flow_basic = *(struct nDPId_flow_basic **)A;

    (void)depth;

    if (log_user_data->workflow == NULL || flow_basic == NULL)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        switch (flow_basic->type)
        {
            case FT_UNKNOWN:
                log_user_data->flows_ukn++;
                break;

            case FT_SKIPPED:
                log_user_data->flows_skp++;
                break;

            case FT_FINISHED:
            {
                log_user_data->flows_fin++;
                log_user_data->flows_active_fin[log_user_data->flows_fin - 1] = flow_basic;
                break;
            }

            case FT_INFO:
            {
                log_user_data->flows_inf++;
                log_user_data->flows_active_inf[log_user_data->flows_inf - 1] = flow_basic;
                break;
            }
        }
    }
}

static size_t log_flows_to_str(struct nDPId_flow_basic const * flows[nDPId_MAX_FLOWS_PER_THREAD],
                               unsigned long long int flows_used,
                               char output[BUFSIZ])
{
    size_t output_used = 0;
    int written;

    output[0] = '\0';

    for (size_t flow_index = 0; flow_index < flows_used; ++flow_index)
    {
        struct nDPId_flow_basic const * const flow_basic = flows[flow_index];

        written = -1;

        switch (flow_basic->type)
        {
            case FT_UNKNOWN:
            case FT_SKIPPED:
                written = 0;
                break;

            case FT_FINISHED:
            {
                struct nDPId_flow_finished const * const flow_finished = (struct nDPId_flow_finished const *)flow_basic;

#if 1
                written = snprintf(output + output_used,
                                   BUFSIZ - output_used,
                                   "%llu,",
                                   flow_finished->flow_info.flow_extended.flow_id);
#else
                written =
                    snprintf(output + output_used,
                             BUFSIZ - output_used,
                             "[%llu, %u, %llu],",
                             flow_finished->flow_info.flow_extended.flow_id,
                             flow_finished->flow_info.flow_extended.flow_basic.l4_protocol,
                             (unsigned long long int const)flow_finished->flow_info.flow_extended.flow_basic.last_seen);
#endif
                break;
            }

            case FT_INFO:
            {
                struct nDPId_flow_info const * const flow_info = (struct nDPId_flow_info const *)flow_basic;

#if 1
                written =
                    snprintf(output + output_used, BUFSIZ - output_used, "%llu,", flow_info->flow_extended.flow_id);
#else
                written = snprintf(output + output_used,
                                   BUFSIZ - output_used,
                                   "[%llu, %u, %llu],",
                                   flow_info->flow_extended.flow_id,
                                   flow_info->flow_extended.flow_basic.l4_protocol,
                                   (unsigned long long int const)flow_info->flow_extended.flow_basic.last_seen);
#endif
                break;
            }
        }

        if (written <= 0)
        {
            break;
        }
        else
        {
            output_used += written;
            if (output_used >= BUFSIZ)
            {
                break;
            }
        }
    }

    return (output_used > 0 ? output_used - 1 : 0);
}

static void log_flows(struct nDPId_reader_thread const * const reader_thread)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    struct log_flows_user_data log_user_data;
    char flows_log_str[BUFSIZ];
    size_t flows_log_str_used;

    log_user_data.workflow = reader_thread->workflow;
    log_user_data.flows_ukn = 0;
    log_user_data.flows_skp = 0;
    log_user_data.flows_fin = 0;
    log_user_data.flows_inf = 0;

    for (size_t scan_index = 0; scan_index < workflow->max_active_flows; ++scan_index)
    {
        ndpi_twalk(workflow->ndpi_flows_active[scan_index], log_flows_flow_walker, &log_user_data);
    }

    syslog(LOG_DAEMON,
           "MemoryProfiler flow stats: [thread: %d][unknown: %llu][skipped: %llu][finished: %llu][info: %llu]",
           reader_thread->array_index,
           log_user_data.flows_ukn,
           log_user_data.flows_skp,
           log_user_data.flows_fin,
           log_user_data.flows_inf);

    flows_log_str_used = log_flows_to_str(log_user_data.flows_active_fin, log_user_data.flows_fin, flows_log_str);
    if (flows_log_str_used > 0)
    {
        syslog(LOG_DAEMON,
               "MemoryProfiler flows active (finished): [thread: %d][%.*s]",
               reader_thread->array_index,
               (int)flows_log_str_used,
               flows_log_str);
    }

    flows_log_str_used = log_flows_to_str(log_user_data.flows_active_inf, log_user_data.flows_inf, flows_log_str);
    if (flows_log_str_used > 0)
    {
        syslog(LOG_DAEMON,
               "MemoryProfiler flows active (info): [thread: %d][%.*s]",
               reader_thread->array_index,
               (int)flows_log_str_used,
               flows_log_str);
    }
}
#endif

static struct nDPId_workflow * init_workflow(char const * const file_or_device)
{
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    struct nDPId_workflow * workflow;

#ifdef ENABLE_MEMORY_PROFILING
    set_ndpi_malloc(ndpi_malloc_wrapper);
    set_ndpi_free(ndpi_free_wrapper);
    set_ndpi_flow_malloc(NULL);
    set_ndpi_flow_free(NULL);
#endif

    workflow = (struct nDPId_workflow *)ndpi_calloc(1, sizeof(*workflow));
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
        workflow->is_pcap_file = 1;
    }

    if (workflow->pcap_handle == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               (workflow->is_pcap_file == 0 ? "pcap_open_live: %.*s" : "pcap_open_offline_with_tstamp_precision: %.*s"),
               (int)PCAP_ERRBUF_SIZE,
               pcap_error_buffer);
        free_workflow(&workflow);
        return NULL;
    }

    if (workflow->is_pcap_file == 0 && pcap_setnonblock(workflow->pcap_handle, 1, pcap_error_buffer) == PCAP_ERROR)
    {
        syslog(LOG_DAEMON | LOG_ERR, "pcap_setnonblock: %.*s", (int)PCAP_ERRBUF_SIZE, pcap_error_buffer);
        free_workflow(&workflow);
        return NULL;
    }

    if (nDPId_options.bpf_str != NULL)
    {
        struct bpf_program fp;
        if (pcap_compile(workflow->pcap_handle, &fp, nDPId_options.bpf_str, 1, PCAP_NETMASK_UNKNOWN) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "pcap_compile: %s", pcap_geterr(workflow->pcap_handle));
            free_workflow(&workflow);
            return NULL;
        }
        if (pcap_setfilter(workflow->pcap_handle, &fp) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "pcap_setfilter: %s", pcap_geterr(workflow->pcap_handle));
            free_workflow(&workflow);
            pcap_freecode(&fp);
            return NULL;
        }
        pcap_freecode(&fp);
    }

    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (workflow->ndpi_struct == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR, "%s", "BUG: Could not init ndpi detection module");
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_skipped_flows = 0;
    workflow->total_active_flows = 0;
    workflow->max_active_flows = nDPId_options.max_flows_per_thread;
    workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
    if (workflow->ndpi_flows_active == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "Could not allocate %llu bytes for (active) flow tracking",
               workflow->max_active_flows * sizeof(void *));
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_idle_flows = 0;
    workflow->max_idle_flows = nDPId_options.max_idle_flows_per_thread;
    workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
    if (workflow->ndpi_flows_idle == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "Could not allocate %llu bytes for (idle) flow tracking",
               workflow->max_idle_flows * sizeof(void *));
        free_workflow(&workflow);
        return NULL;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
    if (nDPId_options.custom_protocols_file != NULL)
    {
        ndpi_load_protocols_file(workflow->ndpi_struct, nDPId_options.custom_protocols_file);
    }
    if (nDPId_options.custom_categories_file != NULL)
    {
        ndpi_load_categories_file(workflow->ndpi_struct, nDPId_options.custom_categories_file);
    }
    if (nDPId_options.custom_ja3_file != NULL)
    {
        ndpi_load_malicious_ja3_file(workflow->ndpi_struct, nDPId_options.custom_ja3_file);
    }
    if (nDPId_options.custom_sha1_file != NULL)
    {
        ndpi_load_malicious_sha1_file(workflow->ndpi_struct, nDPId_options.custom_sha1_file);
    }
    ndpi_finalize_initialization(workflow->ndpi_struct);

    ndpi_set_detection_preferences(workflow->ndpi_struct, ndpi_pref_enable_tls_block_dissection, 1);

    if (ndpi_init_serializer_ll(&workflow->ndpi_serializer, ndpi_serialization_format_json, NETWORK_BUFFER_MAX_SIZE) !=
        0)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "BUG: Could not init JSON serializer with buffer size: %u bytes",
               NETWORK_BUFFER_MAX_SIZE);
        free_workflow(&workflow);
        return NULL;
    }

    return workflow;
}

static void free_detection_data(struct nDPId_flow_info * const flow_info)
{
    ndpi_free_flow_data(&flow_info->detection_data->flow);
    ndpi_free(flow_info->detection_data);
    flow_info->detection_data = NULL;
}

static int alloc_detection_data(struct nDPId_flow_info * const flow_info)
{
    flow_info->detection_data = (struct nDPId_detection_data *)ndpi_flow_malloc(sizeof(*flow_info->detection_data));

    if (flow_info->detection_data == NULL)
    {
        goto error;
    }

    memset(flow_info->detection_data, 0, sizeof(*flow_info->detection_data));

    return 0;
error:
    free_detection_data(flow_info);
    return 1;
}

static void ndpi_flow_info_freer(void * const node)
{
    struct nDPId_flow_basic * const flow_basic = (struct nDPId_flow_basic *)node;

    switch (flow_basic->type)
    {
        case FT_UNKNOWN:
        case FT_SKIPPED:
        case FT_FINISHED:
            break;

        case FT_INFO:
        {
            struct nDPId_flow_info * const flow_info = (struct nDPId_flow_info *)flow_basic;
            free_detection_data(flow_info);
            break;
        }
    }
    ndpi_free(flow_basic);
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

    if (nDPId_options.reader_thread_count > nDPId_MAX_READER_THREADS)
    {
        return 1;
    }

    if (nDPId_options.pcap_file_or_interface == NULL)
    {
        nDPId_options.pcap_file_or_interface = get_default_pcapdev(pcap_error_buffer);
        if (nDPId_options.pcap_file_or_interface == NULL)
        {
            syslog(LOG_DAEMON | LOG_ERR, "pcap_lookupdev: %.*s", (int)PCAP_ERRBUF_SIZE, pcap_error_buffer);
            return 1;
        }
        syslog(LOG_DAEMON, "Capturing packets from default device: %s", nDPId_options.pcap_file_or_interface);
    }

    errno = 0;
    if (access(nDPId_options.pcap_file_or_interface, R_OK) != 0 && errno == ENOENT)
    {
        errno = 0;
        if (get_ip_netmask_from_pcap_dev(nDPId_options.pcap_file_or_interface) != 0)
        {
            if (errno != 0)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "Could not get netmask for pcap device %s: %s",
                       nDPId_options.pcap_file_or_interface,
                       strerror(errno));
            }
            return 1;
        }
    }
    else
    {
        if (nDPId_options.process_internal_initial_direction != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "You are processing a PCAP file, `-I' ignored");
            nDPId_options.process_internal_initial_direction = 0;
        }
        if (nDPId_options.process_external_initial_direction != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "You are processing a PCAP file, `-E' ignored");
            nDPId_options.process_external_initial_direction = 0;
        }
    }

    for (unsigned long long int i = 0; i < nDPId_options.reader_thread_count; ++i)
    {
        reader_threads[i].workflow = init_workflow(nDPId_options.pcap_file_or_interface);
        if (reader_threads[i].workflow == NULL)
        {
            return 1;
        }
    }

    return 0;
}

static int ip_tuples_compare(struct nDPId_flow_basic const * const A, struct nDPId_flow_basic const * const B)
{
    // generate a warning if the enum changes
    switch (A->l3_type)
    {
        case L3_IP:
        case L3_IP6:
            break;
    }

    if (A->l3_type == L3_IP && B->l3_type == L3_IP)
    {
        if (A->src.v4.ip < B->src.v4.ip)
        {
            return -1;
        }
        if (A->src.v4.ip > B->src.v4.ip)
        {
            return 1;
        }
        if (A->dst.v4.ip < B->dst.v4.ip)
        {
            return -1;
        }
        if (A->dst.v4.ip > B->dst.v4.ip)
        {
            return 1;
        }
    }
    else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6)
    {
        if (A->src.v6.ip[0] < B->src.v6.ip[0] && A->src.v6.ip[1] < B->src.v6.ip[1])
        {
            return -1;
        }
        if (A->src.v6.ip[0] > B->src.v6.ip[0] && A->src.v6.ip[1] > B->src.v6.ip[1])
        {
            return 1;
        }
        if (A->dst.v6.ip[0] < B->dst.v6.ip[0] && A->dst.v6.ip[1] < B->dst.v6.ip[1])
        {
            return -1;
        }
        if (A->dst.v6.ip[0] > B->dst.v6.ip[0] && A->dst.v6.ip[1] > B->dst.v6.ip[1])
        {
            return 1;
        }
    }

    if (A->src_port < B->src_port)
    {
        return -1;
    }
    if (A->src_port > B->src_port)
    {
        return 1;
    }
    if (A->dst_port < B->dst_port)
    {
        return -1;
    }
    if (A->dst_port > B->dst_port)
    {
        return 1;
    }

    return 0;
}

static uint64_t get_l4_protocol_idle_time(uint8_t l4_protocol)
{
    switch (l4_protocol)
    {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            return nDPId_options.icmp_max_idle_time;
        case IPPROTO_TCP:
            return nDPId_options.tcp_max_idle_time;
        case IPPROTO_UDP:
            return nDPId_options.udp_max_idle_time;
        default:
            return nDPId_options.generic_max_idle_time;
    }
}

static int is_l4_protocol_timed_out(struct nDPId_workflow const * const workflow,
                                    struct nDPId_flow_basic const * const flow_basic)
{
    uint64_t sdiff = flow_basic->last_seen % nDPId_options.flow_scan_interval;
    uint64_t itime = get_l4_protocol_idle_time(flow_basic->l4_protocol) - sdiff;

    return (flow_basic->last_seen + itime <= workflow->last_time) ||
           (flow_basic->tcp_fin_rst_seen == 1 &&
            flow_basic->last_seen + nDPId_options.tcp_max_post_end_flow_time - sdiff <= workflow->last_time);
}

static int is_flow_update_required(struct nDPId_workflow const * const workflow,
                                   struct nDPId_flow_extended const * const flow_ext)
{
    uint64_t itime = get_l4_protocol_idle_time(flow_ext->flow_basic.l4_protocol) / 2;

    if (is_l4_protocol_timed_out(workflow, &flow_ext->flow_basic) != 0)
    {
        return 0;
    }

    return flow_ext->last_flow_update + itime <= workflow->last_time;
}

static void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    struct nDPId_workflow * const workflow = (struct nDPId_workflow *)user_data;
    struct nDPId_flow_basic * const flow_basic = *(struct nDPId_flow_basic **)A;

    (void)depth;

    if (workflow == NULL || flow_basic == NULL)
    {
        return;
    }

    if (workflow->cur_idle_flows == nDPId_options.max_idle_flows_per_thread)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        if (is_l4_protocol_timed_out(workflow, flow_basic) != 0)
        {
            workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow_basic;
            switch (flow_basic->type)
            {
                case FT_UNKNOWN:
                case FT_SKIPPED:
                    break;

                case FT_FINISHED:
                case FT_INFO:
                    workflow->total_idle_flows++;
                    break;
            }
        }
    }
}

static int ndpi_workflow_node_cmp(void const * const A, void const * const B)
{
    struct nDPId_flow_basic const * const flow_basic_a = (struct nDPId_flow_basic *)A;
    struct nDPId_flow_basic const * const flow_basic_b = (struct nDPId_flow_basic *)B;

    if (flow_basic_a->hashval < flow_basic_b->hashval)
    {
        return -1;
    }
    else if (flow_basic_a->hashval > flow_basic_b->hashval)
    {
        return 1;
    }

    /* flows have the same hash */
    if (flow_basic_a->l4_protocol < flow_basic_b->l4_protocol)
    {
        return -1;
    }
    else if (flow_basic_a->l4_protocol > flow_basic_b->l4_protocol)
    {
        return 1;
    }

    return ip_tuples_compare(flow_basic_a, flow_basic_b);
}

static void process_idle_flow(struct nDPId_reader_thread * const reader_thread, size_t idle_scan_index)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    while (workflow->cur_idle_flows > 0)
    {
        struct nDPId_flow_basic * const flow_basic =
            (struct nDPId_flow_basic *)workflow->ndpi_flows_idle[--workflow->cur_idle_flows];

        switch (flow_basic->type)
        {
            case FT_UNKNOWN:
            case FT_SKIPPED:
                break;

            case FT_FINISHED:
            {
                struct nDPId_flow_finished * const flow_finished = (struct nDPId_flow_finished *)flow_basic;

                if (flow_basic->tcp_fin_rst_seen != 0)
                {
                    jsonize_flow_event(reader_thread, &flow_finished->flow_info.flow_extended, FLOW_EVENT_END);
                }
                else
                {
                    jsonize_flow_event(reader_thread, &flow_finished->flow_info.flow_extended, FLOW_EVENT_IDLE);
                }
                break;
            }

            case FT_INFO:
            {
                struct nDPId_flow_info * const flow_info = (struct nDPId_flow_info *)flow_basic;

#ifdef ENABLE_ZLIB
                if (nDPId_options.enable_zlib_compression != 0 && flow_info->detection_data_compressed_size > 0)
                {
                    int ret = detection_data_inflate(flow_info);
                    if (ret <= 0)
                    {
                        syslog(LOG_DAEMON | LOG_ERR, "zLib decompression failed with error code: %d", ret);
                        return;
                    }
                }
#endif

                if (flow_info->detection_completed == 0)
                {
                    uint8_t protocol_was_guessed = 0;

                    if (ndpi_is_protocol_detected(workflow->ndpi_struct,
                                                  flow_info->detection_data->guessed_l7_protocol) == 0)
                    {
                        flow_info->detection_data->guessed_l7_protocol = ndpi_detection_giveup(
                            workflow->ndpi_struct, &flow_info->detection_data->flow, 1, &protocol_was_guessed);
                    }
                    else
                    {
                        protocol_was_guessed = 1;
                    }

                    if (protocol_was_guessed != 0)
                    {
                        workflow->total_guessed_flows++;
                        jsonize_flow_detection_event(reader_thread, flow_info, FLOW_EVENT_GUESSED);
                    }
                    else
                    {
                        workflow->total_not_detected_flows++;
                        jsonize_flow_detection_event(reader_thread, flow_info, FLOW_EVENT_NOT_DETECTED);
                    }
                }
                if (flow_basic->tcp_fin_rst_seen != 0)
                {
                    jsonize_flow_event(reader_thread, &flow_info->flow_extended, FLOW_EVENT_END);
                }
                else
                {
                    jsonize_flow_event(reader_thread, &flow_info->flow_extended, FLOW_EVENT_IDLE);
                }
                break;
            }
        }

        ndpi_tdelete(flow_basic, &workflow->ndpi_flows_active[idle_scan_index], ndpi_workflow_node_cmp);
        ndpi_flow_info_freer(flow_basic);
        workflow->cur_active_flows--;
    }
}

static void check_for_idle_flows(struct nDPId_reader_thread * const reader_thread)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index)
    {
        ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);
        process_idle_flow(reader_thread, idle_scan_index);
    }
}

static void ndpi_flow_update_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    struct nDPId_reader_thread * const reader_thread = (struct nDPId_reader_thread *)user_data;
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    struct nDPId_flow_basic * const flow_basic = *(struct nDPId_flow_basic **)A;

    (void)depth;

    if (workflow == NULL || flow_basic == NULL)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        switch (flow_basic->type)
        {
            case FT_UNKNOWN:
            case FT_SKIPPED:
                break;

            case FT_FINISHED:
            case FT_INFO:
            {
                struct nDPId_flow_extended * const flow_ext = (struct nDPId_flow_extended *)flow_basic;

                if (is_flow_update_required(workflow, flow_ext) != 0)
                {
                    workflow->total_flow_updates++;
                    jsonize_flow_event(reader_thread, flow_ext, FLOW_EVENT_UPDATE);
                    flow_ext->last_flow_update = workflow->last_time;
                }
                break;
            }
        }
    }
}

static void check_for_flow_updates(struct nDPId_reader_thread * const reader_thread)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    for (size_t update_scan_index = 0; update_scan_index < workflow->max_active_flows; ++update_scan_index)
    {
        ndpi_twalk(workflow->ndpi_flows_active[update_scan_index], ndpi_flow_update_scan_walker, reader_thread);
    }
}

static void jsonize_l3_l4(struct nDPId_workflow * const workflow, struct nDPId_flow_basic const * const flow_basic)
{
    ndpi_serializer * const serializer = &workflow->ndpi_serializer;
    char src_name[48] = {};
    char dst_name[48] = {};

    switch (flow_basic->l3_type)
    {
        case L3_IP:
            ndpi_serialize_string_string(serializer, "l3_proto", "ip4");
            if (inet_ntop(AF_INET, &flow_basic->src.v4.ip, src_name, sizeof(src_name)) == NULL)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Could not convert IPv4 source ip to string: %s", strerror(errno));
            }
            if (inet_ntop(AF_INET, &flow_basic->dst.v4.ip, dst_name, sizeof(dst_name)) == NULL)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Could not convert IPv4 destination ip to string: %s", strerror(errno));
            }
            break;
        case L3_IP6:
            ndpi_serialize_string_string(serializer, "l3_proto", "ip6");
            if (inet_ntop(AF_INET6, &flow_basic->src.v6.ip[0], src_name, sizeof(src_name)) == NULL)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Could not convert IPv6 source ip to string: %s", strerror(errno));
            }
            if (inet_ntop(AF_INET6, &flow_basic->dst.v6.ip[0], dst_name, sizeof(dst_name)) == NULL)
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
    if (flow_basic->src_port)
    {
        ndpi_serialize_string_uint32(serializer, "src_port", flow_basic->src_port);
    }
    if (flow_basic->dst_port)
    {
        ndpi_serialize_string_uint32(serializer, "dst_port", flow_basic->dst_port);
    }

    switch (flow_basic->l4_protocol)
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
            ndpi_serialize_string_uint32(serializer, "l4_proto", flow_basic->l4_protocol);
            break;
    }
}

static void jsonize_basic(struct nDPId_reader_thread * const reader_thread)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    ndpi_serialize_string_int32(&workflow->ndpi_serializer, "thread_id", reader_thread->array_index);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "packet_id", workflow->packets_captured);
    ndpi_serialize_string_string(&workflow->ndpi_serializer, "source", nDPId_options.pcap_file_or_interface);
    ndpi_serialize_string_string(&workflow->ndpi_serializer, "alias", nDPId_options.instance_alias);
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
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "max-flows-per-thread",
                                     nDPId_options.max_flows_per_thread);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "max-idle-flows-per-thread",
                                     nDPId_options.max_idle_flows_per_thread);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "tick-resolution", nDPId_options.tick_resolution);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "reader-thread-count",
                                     nDPId_options.reader_thread_count);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "flow-scan-interval",
                                     nDPId_options.flow_scan_interval);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "generic-max-idle-time",
                                     nDPId_options.generic_max_idle_time);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "icmp-max-idle-time",
                                     nDPId_options.icmp_max_idle_time);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "udp-max-idle-time", nDPId_options.udp_max_idle_time);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "tcp-max-idle-time",
                                     nDPId_options.tcp_max_idle_time + nDPId_options.tcp_max_post_end_flow_time);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "max-packets-per-flow-to-send",
                                     nDPId_options.max_packets_per_flow_to_send);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "max-packets-per-flow-to-process",
                                     nDPId_options.max_packets_per_flow_to_process);
    }
    else if (event == DAEMON_EVENT_SHUTDOWN)
    {
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "total-events-serialized",
                                     workflow->total_events_serialized +
                                         1 /* DAEMON_EVENT_SHUTDOWN is an event as well */);
    }
    serialize_and_send(reader_thread);
}

static void jsonize_flow(struct nDPId_workflow * const workflow, struct nDPId_flow_extended const * const flow_ext)
{
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_id", flow_ext->flow_id);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_packets_processed", flow_ext->packets_processed);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_first_seen", flow_ext->first_seen);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_last_seen", flow_ext->flow_basic.last_seen);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_idle_time",
                                 get_l4_protocol_idle_time(flow_ext->flow_basic.l4_protocol));
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_min_l4_payload_len", flow_ext->min_l4_payload_len);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_max_l4_payload_len", flow_ext->max_l4_payload_len);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_tot_l4_payload_len", flow_ext->total_l4_payload_len);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_avg_l4_payload_len",
                                 (flow_ext->packets_processed > 0
                                      ? flow_ext->total_l4_payload_len / flow_ext->packets_processed
                                      : 0));
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "midstream", flow_ext->flow_basic.tcp_is_midstream_flow);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "ts_msec", workflow->last_time);
}

static int connect_to_json_socket(struct nDPId_reader_thread * const reader_thread)
{
    struct sockaddr_un saddr;

    if (reader_thread->json_sockfd >= 0)
    {
        close(reader_thread->json_sockfd);
    }

    reader_thread->json_sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (reader_thread->json_sockfd < 0)
    {
        reader_thread->json_sock_reconnect = 1;
        return 1;
    }

    int opt = NETWORK_BUFFER_MAX_SIZE * 16;
    if (setsockopt(reader_thread->json_sockfd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0)
    {
        return 1;
    }

    saddr.sun_family = AF_UNIX;
    if (snprintf(saddr.sun_path, sizeof(saddr.sun_path), "%s", nDPId_options.json_sockpath) < 0 ||
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

    s_ret = snprintf(newline_json_str,
                     sizeof(newline_json_str),
                     "%0" NETWORK_BUFFER_LENGTH_DIGITS_STR "zu%.*s\n",
                     json_str_len + 1,
                     (int)json_str_len,
                     json_str);

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
                   "[%8llu, %d] Reconnected to nDPIsrvd Collector",
                   workflow->packets_captured,
                   reader_thread->array_index);
            jsonize_daemon(reader_thread, DAEMON_EVENT_RECONNECT);
        }
    }

    errno = 0;
    ssize_t written;
    if (reader_thread->json_sock_reconnect == 0 &&
        (written = write(reader_thread->json_sockfd, newline_json_str, s_ret)) != s_ret)
    {
        saved_errno = errno;
        if (saved_errno == EPIPE)
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "[%8llu, %d] Lost connection to nDPIsrvd Collector",
                   workflow->packets_captured,
                   reader_thread->array_index);
        }
        if (saved_errno != EAGAIN)
        {
            reader_thread->json_sock_reconnect = 1;
        }
        else
        {
            fcntl(reader_thread->json_sockfd, F_SETFL, fcntl(reader_thread->json_sockfd, F_GETFL, 0) & ~O_NONBLOCK);
            off_t pos = (written < 0 ? 0 : written);
            while ((written = write(reader_thread->json_sockfd, newline_json_str + pos, s_ret - pos)) != s_ret - pos)
            {
                if (written < 0)
                {
                    syslog(LOG_DAEMON | LOG_ERR,
                           "[%8llu, %d] Send data (blocking I/O) to nDPIsrvd Collector failed: %s",
                           workflow->packets_captured,
                           reader_thread->array_index,
                           strerror(saved_errno));
                    reader_thread->json_sock_reconnect = 1;
                    break;
                }
                else
                {
                    pos += written;
                }
            }
            fcntl(reader_thread->json_sockfd, F_SETFL, fcntl(reader_thread->json_sockfd, F_GETFL, 0) & O_NONBLOCK);
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
        reader_thread->workflow->total_events_serialized++;
        send_to_json_sink(reader_thread, json_str, json_str_len);
    }
    ndpi_reset_serializer(&reader_thread->workflow->ndpi_serializer);
}

/* Slightly modified code from: https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64 */
static char const * const base64_ret_strings[] = {"Success", "Buffer too small"};
static int base64encode(uint8_t const * const data_buf,
                        size_t dataLength,
                        char * const result,
                        size_t * const resultSize)
{
    const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const uint8_t * data = (const uint8_t *)data_buf;
    size_t resultIndex = 0;
    size_t x;
    uint32_t n = 0;
    int padCount = dataLength % 3;
    uint8_t n0, n1, n2, n3;

    /* increment over the length of the string, three characters at a time */
    for (x = 0; x < dataLength; x += 3)
    {
        /* these three 8-bit (ASCII) characters become one 24-bit number */
        n = ((uint32_t)data[x]) << 16; // parenthesis needed, compiler depending on flags can do the shifting before
                                       // conversion to uint32_t, resulting to 0

        if ((x + 1) < dataLength)
        {
            n += ((uint32_t)data[x + 1]) << 8; // parenthesis needed, compiler depending on flags can do the shifting
                                               // before conversion to uint32_t, resulting to 0
        }

        if ((x + 2) < dataLength)
        {
            n += data[x + 2];
        }

        /* this 24-bit number gets separated into four 6-bit numbers */
        n0 = (uint8_t)(n >> 18) & 63;
        n1 = (uint8_t)(n >> 12) & 63;
        n2 = (uint8_t)(n >> 6) & 63;
        n3 = (uint8_t)n & 63;

        /*
         * if we have one byte available, then its encoding is spread
         * out over two characters
         */
        if (resultIndex >= *resultSize)
        {
            return 1; /* indicate failure: buffer too small */
        }
        result[resultIndex++] = base64chars[n0];
        if (resultIndex >= *resultSize)
        {
            return 1; /* indicate failure: buffer too small */
        }
        result[resultIndex++] = base64chars[n1];

        /*
         * if we have only two bytes available, then their encoding is
         * spread out over three chars
         */
        if ((x + 1) < dataLength)
        {
            if (resultIndex >= *resultSize)
            {
                return 1; /* indicate failure: buffer too small */
            }
            result[resultIndex++] = base64chars[n2];
        }

        /*
         * if we have all three bytes available, then their encoding is spread
         * out over four characters
         */
        if ((x + 2) < dataLength)
        {
            if (resultIndex >= *resultSize)
            {
                return 1; /* indicate failure: buffer too small */
            }
            result[resultIndex++] = base64chars[n3];
        }
    }

    /*
     * create and add padding that is required if we did not have a multiple of 3
     * number of characters available
     */
    if (padCount > 0)
    {
        for (; padCount < 3; padCount++)
        {
            if (resultIndex >= *resultSize)
            {
                return 1; /* indicate failure: buffer too small */
            }
            result[resultIndex++] = '=';
        }
    }
    if (resultIndex >= *resultSize)
    {
        return 1; /* indicate failure: buffer too small */
    }

    result[resultIndex] = 0;
    *resultSize = resultIndex;
    return 0; /* indicate success */
}

static void jsonize_packet_event(struct nDPId_reader_thread * const reader_thread,
                                 struct pcap_pkthdr const * const header,
                                 uint8_t const * const packet,
                                 uint16_t pkt_type,
                                 uint16_t pkt_l3_offset,
                                 uint16_t pkt_l4_offset,
                                 uint16_t pkt_l4_len,
                                 struct nDPId_flow_extended const * const flow_ext,
                                 enum packet_event event)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    char const ev[] = "packet_event_name";

    if (event == PACKET_EVENT_PAYLOAD_FLOW)
    {
        if (flow_ext == NULL)
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "[%8llu, %d] BUG: got a PACKET_EVENT_PAYLOAD_FLOW with a flow pointer equals NULL",
                   reader_thread->workflow->packets_captured,
                   reader_thread->array_index);
            return;
        }
        if (flow_ext->packets_processed > nDPId_options.max_packets_per_flow_to_send)
        {
            return;
        }
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

    if (event == PACKET_EVENT_PAYLOAD_FLOW)
    {
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_id", flow_ext->flow_id);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_packet_id", flow_ext->packets_processed);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_last_seen", flow_ext->flow_basic.last_seen);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "flow_idle_time",
                                     get_l4_protocol_idle_time(flow_ext->flow_basic.l4_protocol));
    }

    char base64_data[NETWORK_BUFFER_MAX_SIZE];
    size_t base64_data_len = sizeof(base64_data);
    int base64_retval = base64encode(packet, header->caplen, base64_data, &base64_data_len);

    ndpi_serialize_string_boolean(&workflow->ndpi_serializer, "pkt_oversize", base64_data_len > sizeof(base64_data));
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_caplen", header->caplen);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_type", pkt_type);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_l3_offset", pkt_l3_offset);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_l4_offset", pkt_l4_offset);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_len", header->caplen);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_l4_len", pkt_l4_len);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "ts_msec", workflow->last_time);

    if (base64_retval == 0 && base64_data_len > 0)
    {
        if (ndpi_serialize_string_binary(&workflow->ndpi_serializer, "pkt", base64_data, base64_data_len) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "[%8llu, %d] JSON serializing base64 packet buffer failed",
                   reader_thread->workflow->packets_captured,
                   reader_thread->array_index);
        }
    }
    else
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "[%8llu, %d] Base64 encoding failed with: %s.",
               reader_thread->workflow->packets_captured,
               reader_thread->array_index,
               base64_ret_strings[base64_retval]);
    }
    serialize_and_send(reader_thread);
}

/* I decided against ndpi_flow2json as it does not fulfill my needs. */
static void jsonize_flow_event(struct nDPId_reader_thread * const reader_thread,
                               struct nDPId_flow_extended * const flow_ext,
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
    jsonize_flow(workflow, flow_ext);
    jsonize_l3_l4(workflow, &flow_ext->flow_basic);

    switch (event)
    {
        case FLOW_EVENT_INVALID:
        case FLOW_EVENT_COUNT:
            break;

        case FLOW_EVENT_NEW:
        case FLOW_EVENT_END:
        case FLOW_EVENT_IDLE:
        case FLOW_EVENT_UPDATE:
            ndpi_serialize_string_int32(&workflow->ndpi_serializer,
                                        "flow_datalink",
                                        pcap_datalink(reader_thread->workflow->pcap_handle));
            ndpi_serialize_string_uint32(&workflow->ndpi_serializer,
                                         "flow_max_packets",
                                         nDPId_options.max_packets_per_flow_to_send);
            break;

        case FLOW_EVENT_NOT_DETECTED:
        case FLOW_EVENT_GUESSED:
        case FLOW_EVENT_DETECTED:
        case FLOW_EVENT_DETECTION_UPDATE:
            syslog(LOG_DAEMON | LOG_ERR,
                   "[%8llu, %4llu] internal error / invalid function call",
                   workflow->packets_captured,
                   flow_ext->flow_id);
            break;
    }

    serialize_and_send(reader_thread);
}

static void jsonize_flow_detection_event(struct nDPId_reader_thread * const reader_thread,
                                         struct nDPId_flow_info * const flow_info,
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
    jsonize_flow(workflow, &flow_info->flow_extended);
    jsonize_l3_l4(workflow, &flow_info->flow_extended.flow_basic);

    switch (event)
    {
        case FLOW_EVENT_INVALID:
        case FLOW_EVENT_COUNT:
            break;

        case FLOW_EVENT_NEW:
        case FLOW_EVENT_END:
        case FLOW_EVENT_IDLE:
        case FLOW_EVENT_UPDATE:
            syslog(LOG_DAEMON | LOG_ERR,
                   "[%8llu, %4llu] internal error / invalid function call",
                   workflow->packets_captured,
                   flow_info->flow_extended.flow_id);
            break;

        case FLOW_EVENT_NOT_DETECTED:
        case FLOW_EVENT_GUESSED:
            if (ndpi_dpi2json(workflow->ndpi_struct,
                              &flow_info->detection_data->flow,
                              flow_info->detection_data->guessed_l7_protocol,
                              &workflow->ndpi_serializer) != 0)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "[%8llu, %4llu] ndpi_dpi2json failed for not-detected/guessed flow",
                       workflow->packets_captured,
                       flow_info->flow_extended.flow_id);
            }
            break;

        case FLOW_EVENT_DETECTED:
        case FLOW_EVENT_DETECTION_UPDATE:
            if (ndpi_dpi2json(workflow->ndpi_struct,
                              &flow_info->detection_data->flow,
                              flow_info->detection_data->detected_l7_protocol,
                              &workflow->ndpi_serializer) != 0)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "[%8llu, %4llu] ndpi_dpi2json failed for detected/detection-update flow",
                       workflow->packets_captured,
                       flow_info->flow_extended.flow_id);
            }
            break;
    }

    serialize_and_send(reader_thread);
}

static void internal_format_error(ndpi_serializer * const serializer, char const * const format, uint32_t format_index)
{
    syslog(LOG_DAEMON | LOG_ERR,
           "BUG: Internal error detected for format string `%s' at format index %u",
           format,
           format_index);
    ndpi_reset_serializer(serializer);
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
                    internal_format_error(&reader_thread->workflow->ndpi_serializer, format, format_index);
                    return;
                }
                break;
            }
            case 'z':
            case 'l':
                format_index++;
                if (got_jsonkey != 1)
                {
                    internal_format_error(&reader_thread->workflow->ndpi_serializer, format, format_index);
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
                    internal_format_error(&reader_thread->workflow->ndpi_serializer, format, format_index);
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
                    internal_format_error(&reader_thread->workflow->ndpi_serializer, format, format_index);
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
                    internal_format_error(&reader_thread->workflow->ndpi_serializer, format, format_index);
                    return;
                }
                break;
            /* format string separators */
            case ' ':
            case ',':
            case '%':
                break;
            default:
                internal_format_error(&reader_thread->workflow->ndpi_serializer, format, format_index);
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
    ndpi_serialize_string_int32(&reader_thread->workflow->ndpi_serializer,
                                "datalink",
                                pcap_datalink(reader_thread->workflow->pcap_handle));

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

    size_t host_server_name_len =
        strnlen((const char *)ndpi_flow->host_server_name, sizeof(ndpi_flow->host_server_name));
    hash += host_server_name_len;
    hash += murmur3_32((uint8_t const *)&ndpi_flow->host_server_name,
                       sizeof(ndpi_flow->host_server_name),
                       nDPId_FLOW_STRUCT_SEED);

    return hash;
}

/* Some constants stolen from ndpiReader. */
#define SNAP 0xaa
/* mask for FCF */
#define WIFI_DATA 0x2
#define FCF_TYPE(fc) (((fc) >> 2) & 0x3) /* 0000 0011 = 0x3 */
#define FCF_TO_DS(fc) ((fc)&0x0100)
#define FCF_FROM_DS(fc) ((fc)&0x0200)
/* mask for Bad FCF presence */
#define BAD_FCS 0x50 /* 0101 0000 */
static int process_datalink_layer(struct nDPId_reader_thread * const reader_thread,
                                  struct pcap_pkthdr const * const header,
                                  uint8_t const * const packet,
                                  uint16_t * ip_offset,
                                  uint16_t * layer3_type)
{
    const uint16_t eth_offset = 0;
    const int datalink_type = pcap_datalink(reader_thread->workflow->pcap_handle);
    const struct ndpi_ethhdr * ethernet;

    switch (datalink_type)
    {
        case DLT_NULL:
        {
            /* DLT header values can be stored as big or little endian. */

            uint32_t dlt_hdr = *((uint32_t *)&packet[eth_offset]);

            if (dlt_hdr == 0x02000000 || dlt_hdr == 0x02)
            {
                *layer3_type = ETH_P_IP;
            }
            else if (dlt_hdr == 0x24000000 || dlt_hdr == 0x24 || dlt_hdr == 0x28000000 || dlt_hdr == 0x28 ||
                     dlt_hdr == 0x30000000 || dlt_hdr == 0x30)
            {
                *layer3_type = ETH_P_IPV6;
            }
            else
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(reader_thread,
                                     UNKNOWN_DATALINK_LAYER,
                                     "%s%u",
                                     "layer_type",
                                     ntohl(*((uint32_t *)&packet[eth_offset])));
                return 1;
            }
            *ip_offset = sizeof(dlt_hdr) + eth_offset;
            break;
        }
        case DLT_PPP_SERIAL:
        {
            if (header->caplen < sizeof(struct ndpi_chdlc))
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(reader_thread,
                                     PACKET_TOO_SHORT,
                                     "%s%u %s%zu",
                                     "size",
                                     header->caplen,
                                     "expected",
                                     sizeof(struct ndpi_chdlc));
                return 1;
            }

            struct ndpi_chdlc const * const chdlc = (struct ndpi_chdlc const * const) & packet[eth_offset];
            *ip_offset = sizeof(struct ndpi_chdlc);
            *layer3_type = ntohs(chdlc->proto_code);
            break;
        }
        case DLT_C_HDLC:
        case DLT_PPP:
            if (header->caplen < sizeof(struct ndpi_chdlc))
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(reader_thread,
                                     PACKET_TOO_SHORT,
                                     "%s%u %s%zu",
                                     "size",
                                     header->caplen,
                                     "expected",
                                     sizeof(struct ndpi_chdlc));
                return 1;
            }

            if (packet[0] == 0x0f || packet[0] == 0x8f)
            {
                struct ndpi_chdlc const * const chdlc = (struct ndpi_chdlc const * const) & packet[eth_offset];
                *ip_offset = sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
                *layer3_type = ntohs(chdlc->proto_code);
            }
            else
            {
                *ip_offset = 2;
                *layer3_type = ntohs(*((u_int16_t *)&packet[eth_offset]));
            }
            break;
        case DLT_LINUX_SLL:
            if (header->caplen < 16)
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(
                    reader_thread, PACKET_TOO_SHORT, "%s%u %s%u", "size", header->caplen, "expected", 16);
                return 1;
            }

            *layer3_type = (packet[eth_offset + 14] << 8) + packet[eth_offset + 15];
            *ip_offset = 16 + eth_offset;
            break;
        case DLT_IEEE802_11_RADIO:
        {
            if (header->caplen < sizeof(struct ndpi_radiotap_header))
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(reader_thread,
                                     PACKET_TOO_SHORT,
                                     "%s%u %s%zu",
                                     "size",
                                     header->caplen,
                                     "expected",
                                     sizeof(struct ndpi_radiotap_header));
                return 1;
            }

            struct ndpi_radiotap_header const * const radiotap =
                (struct ndpi_radiotap_header const * const) & packet[eth_offset];
            uint16_t radio_len = radiotap->len;

            /* Check Bad FCS presence */
            if ((radiotap->flags & BAD_FCS) == BAD_FCS)
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(reader_thread, PACKET_HEADER_INVALID, "%s%s", "reason", "Bad FCS presence");
                return 1;
            }

            if (header->caplen < (eth_offset + radio_len + sizeof(struct ndpi_wifi_header)))
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(reader_thread,
                                     PACKET_TOO_SHORT,
                                     "%s%u %s%zu",
                                     "size",
                                     header->caplen,
                                     "expected",
                                     (eth_offset + radio_len + sizeof(struct ndpi_wifi_header)));
                return 1;
            }

            /* Calculate 802.11 header length (variable) */
            struct ndpi_wifi_header const * const wifi =
                (struct ndpi_wifi_header const * const)(packet + eth_offset + radio_len);
            uint16_t fc = wifi->fc;
            int wifi_len = 0;

            /* check wifi data presence */
            if (FCF_TYPE(fc) == WIFI_DATA)
            {
                if ((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) || (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
                {
                    wifi_len = 26; /* + 4 byte fcs */
                }
            }
            else
            {
                /* no data frames */
                break;
            }

            /* Check ether_type from LLC */
            if (header->caplen < (eth_offset + wifi_len + radio_len + sizeof(struct ndpi_llc_header_snap)))
            {
                return 1;
            }

            struct ndpi_llc_header_snap const * const llc =
                (struct ndpi_llc_header_snap const * const)(packet + eth_offset + wifi_len + radio_len);
            if (llc->dsap == SNAP)
            {
                *layer3_type = ntohs(llc->snap.proto_ID);
            }

            /* Set IP header offset */
            *ip_offset = wifi_len + radio_len + sizeof(struct ndpi_llc_header_snap) + eth_offset;
            break;
        }
        case DLT_RAW:
            jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread, UNSUPPORTED_DATALINK_LAYER, NULL);
            return 1;
        case DLT_EN10MB:
            if (header->caplen < sizeof(struct ndpi_ethhdr))
            {
                jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                jsonize_basic_eventf(reader_thread,
                                     PACKET_TOO_SHORT,
                                     "%s%u %s%zu",
                                     "size",
                                     header->caplen,
                                     "expected",
                                     sizeof(struct ndpi_ethhdr));
                return 1;
            }

            ethernet = (struct ndpi_ethhdr *)&packet[eth_offset];
            *ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
            *layer3_type = ntohs(ethernet->h_proto);

            /* Cisco FabricPath (data center ethernet devices) */
            if (*layer3_type == ETHERTYPE_DCE)
            {
                if (header->caplen < sizeof(struct ndpi_ethhdr) + 20 /* sizeof(Ethernet/DCE-header) */)
                {
                    jsonize_packet_event(
                        reader_thread, header, packet, *layer3_type, *ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                    jsonize_basic_eventf(reader_thread,
                                         PACKET_TOO_SHORT,
                                         "%s%u %s%zu",
                                         "size",
                                         header->caplen,
                                         "expected",
                                         sizeof(struct ndpi_ethhdr) + 2);
                    return 1;
                }
                ethernet = (struct ndpi_ethhdr *)&packet[eth_offset + 20];
                *ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
                *layer3_type = ntohs(ethernet->h_proto);
            }

            /* 802.1Q VLAN */
            if (*layer3_type == ETHERTYPE_VLAN)
            {
                if (header->caplen < sizeof(struct ndpi_ethhdr) + 4 /* sizeof(802.1Q-header) */)
                {
                    jsonize_packet_event(
                        reader_thread, header, packet, *layer3_type, *ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                    jsonize_basic_eventf(reader_thread,
                                         PACKET_TOO_SHORT,
                                         "%s%u %s%zu",
                                         "size",
                                         header->caplen,
                                         "expected",
                                         sizeof(struct ndpi_ethhdr) + 4);
                    return 1;
                }
                *layer3_type = ntohs(*(uint16_t *)&packet[*ip_offset + 2]);
                *ip_offset += 4;
            }

            switch (*layer3_type)
            {
                case ETH_P_IP: /* IPv4 */
                    if (header->caplen < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr))
                    {
                        jsonize_packet_event(
                            reader_thread, header, packet, *layer3_type, *ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                        jsonize_basic_eventf(reader_thread,
                                             IP4_PACKET_TOO_SHORT,
                                             "%s%u %s%zu",
                                             "size",
                                             header->caplen,
                                             "expected",
                                             sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr));
                        return 1;
                    }
                    break;
                case ETH_P_IPV6: /* IPV6 */
                    if (header->caplen < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr))
                    {
                        jsonize_packet_event(
                            reader_thread, header, packet, *layer3_type, *ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                        jsonize_basic_eventf(reader_thread,
                                             IP6_PACKET_TOO_SHORT,
                                             "%s%u %s%zu",
                                             "size",
                                             header->caplen,
                                             "expected",
                                             sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr));
                        return 1;
                    }
                    break;
                case ETHERTYPE_PAE: /* 802.1X Authentication */
                    return 1;
                case ETH_P_ARP: /* ARP */
                    return 1;
                default:
                    jsonize_packet_event(
                        reader_thread, header, packet, *layer3_type, *ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                    jsonize_basic_eventf(reader_thread, PACKET_TYPE_UNKNOWN, "%s%u", "layer_type", *layer3_type);
                    return 1;
            }
            break;
        case DLT_IPV4:
            *layer3_type = ETH_P_IP;
            *ip_offset = 0;
            break;
        case DLT_IPV6:
            *layer3_type = ETH_P_IPV6;
            *ip_offset = 0;
            break;
        default:
            jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, UNKNOWN_DATALINK_LAYER, "%s%u", "layer_type", ntohl(*((uint32_t *)&packet[eth_offset])));
            return 1;
    }

    return 0;
}

static struct nDPId_flow_basic * add_new_flow(struct nDPId_workflow * const workflow,
                                              struct nDPId_flow_basic * orig_flow_basic,
                                              enum nDPId_flow_type type,
                                              size_t hashed_index)
{
    size_t s;

    switch (type)
    {
        case FT_UNKNOWN:
        case FT_FINISHED: // do not allocate something for FT_FINISHED as we are re-using memory allocated by FT_INFO
            return NULL;

        case FT_SKIPPED:
            workflow->total_skipped_flows++;
            s = sizeof(struct nDPId_flow_skipped);
            break;

        case FT_INFO:
            s = sizeof(struct nDPId_flow_info);
            break;
    }

    struct nDPId_flow_basic * flow_basic = (struct nDPId_flow_basic *)ndpi_malloc(s);
    if (flow_basic == NULL)
    {
        return NULL;
    }
    memset(flow_basic, 0, s);
    *flow_basic = *orig_flow_basic;
    flow_basic->type = type;
    if (ndpi_tsearch(flow_basic, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == NULL)
    {
        ndpi_free(flow_basic);
        return NULL;
    }

    return flow_basic;
}

static void do_periodically_work(struct nDPId_reader_thread * const reader_thread)
{
    if (reader_thread->workflow->last_scan_time + nDPId_options.flow_scan_interval <=
        reader_thread->workflow->last_time)
    {
        check_for_idle_flows(reader_thread);
        check_for_flow_updates(reader_thread);
        reader_thread->workflow->last_scan_time = reader_thread->workflow->last_time;
    }
#ifdef ENABLE_MEMORY_PROFILING
    if (reader_thread->workflow->last_memory_usage_log_time + nDPId_options.memory_profiling_log_interval <=
        reader_thread->workflow->last_time)
    {
        log_memory_usage(reader_thread);
        log_flows(reader_thread);
        reader_thread->workflow->last_memory_usage_log_time = reader_thread->workflow->last_time;
    }
#endif
}

static void ndpi_process_packet(uint8_t * const args,
                                struct pcap_pkthdr const * const header,
                                uint8_t const * const packet)
{
    struct nDPId_reader_thread * const reader_thread = (struct nDPId_reader_thread *)args;
    struct nDPId_workflow * workflow;
    struct nDPId_flow_basic flow_basic = {};

    size_t hashed_index;
    void * tree_result;
    struct nDPId_flow_info * flow_to_process;

    uint8_t direction_changed = 0;
    uint8_t is_new_flow = 0;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

    const struct ndpi_iphdr * ip;
    struct ndpi_ipv6hdr * ip6;

    uint64_t time_ms;
    uint16_t ip_offset = 0;
    uint16_t ip_size;

    const uint8_t * l4_ptr = NULL;
    uint16_t l4_len = 0;
    uint16_t l4_payload_len = 0;

    uint16_t type = 0;
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
    time_ms = ((uint64_t)header->ts.tv_sec) * nDPId_options.tick_resolution +
              header->ts.tv_usec / (1000000 / nDPId_options.tick_resolution);
    if (workflow->last_time < time_ms)
    {
        workflow->last_time = time_ms;
    }

    do_periodically_work(reader_thread);

    if (process_datalink_layer(reader_thread, header, packet, &ip_offset, &type) != 0)
    {
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
        jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
        jsonize_basic_eventf(reader_thread, UNKNOWN_L3_PROTOCOL, "%s%u", "protocol", type);
        return;
    }
    ip_size = header->caplen - ip_offset;

    if (type == ETH_P_IP && header->caplen >= ip_offset)
    {
        if (header->caplen < header->len)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 CAPTURE_SIZE_SMALLER_THAN_PACKET_SIZE,
                                 "%s%u %s%u",
                                 "size",
                                 header->caplen,
                                 "expected",
                                 header->len);
        }
    }

    /* process layer3 e.g. IPv4 / IPv6 */
    if (ip != NULL && ip->version == 4)
    {
        if (ip_size < sizeof(*ip))
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, IP4_SIZE_SMALLER_THAN_HEADER, "%s%u %s%zu", "size", ip_size, "expected", sizeof(*ip));
            return;
        }

        flow_basic.l3_type = L3_IP;

        if (ndpi_detection_get_l4(
                (uint8_t *)ip, ip_size, &l4_ptr, &l4_len, &flow_basic.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, IP4_L4_PAYLOAD_DETECTION_FAILED, "%s%zu", "l4_data_len", ip_size - sizeof(*ip));
            return;
        }

        flow_basic.src.v4.ip = ip->saddr;
        flow_basic.dst.v4.ip = ip->daddr;
        uint32_t min_addr = (flow_basic.src.v4.ip > flow_basic.dst.v4.ip ? flow_basic.dst.v4.ip : flow_basic.src.v4.ip);
        thread_index = min_addr + ip->protocol;
    }
    else if (ip6 != NULL)
    {
        if (ip_size < sizeof(ip6->ip6_hdr))
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 IP6_SIZE_SMALLER_THAN_HEADER,
                                 "%s%u %s%zu",
                                 "size",
                                 ip_size,
                                 "expected",
                                 sizeof(ip6->ip6_hdr));
            return;
        }

        flow_basic.l3_type = L3_IP6;
        if (ndpi_detection_get_l4(
                (uint8_t *)ip6, ip_size, &l4_ptr, &l4_len, &flow_basic.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
        {
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, IP6_L4_PAYLOAD_DETECTION_FAILED, "%s%zu", "l4_data_len", ip_size - sizeof(*ip));
            return;
        }

        flow_basic.src.v6.ip[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow_basic.src.v6.ip[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow_basic.dst.v6.ip[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow_basic.dst.v6.ip[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];

        uint64_t min_addr[2];
        if (flow_basic.src.v6.ip[0] > flow_basic.dst.v6.ip[0] ||
            (flow_basic.src.v6.ip[0] == flow_basic.dst.v6.ip[0] && flow_basic.src.v6.ip[1] > flow_basic.dst.v6.ip[1]))
        {
            min_addr[0] = flow_basic.dst.v6.ip[0];
            min_addr[1] = flow_basic.dst.v6.ip[1];
        }
        else
        {
            min_addr[0] = flow_basic.src.v6.ip[0];
            min_addr[1] = flow_basic.src.v6.ip[1];
        }
        thread_index = min_addr[0] + min_addr[1] + ip6->ip6_hdr.ip6_un1_nxt;
    }
    else
    {
        jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
        jsonize_basic_eventf(reader_thread, UNKNOWN_L3_PROTOCOL, "%s%u", "protocol", type);
        return;
    }

    /* process layer4 e.g. TCP / UDP */
    if (flow_basic.l4_protocol == IPPROTO_TCP)
    {
        const struct ndpi_tcphdr * tcp;

        if (header->caplen < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr))
        {
            jsonize_packet_event(
                reader_thread, header, packet, type, ip_offset, (l4_ptr - packet), l4_len, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 TCP_PACKET_TOO_SHORT,
                                 "%s%u %s%zu",
                                 "size",
                                 header->caplen,
                                 "expected",
                                 (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
            return;
        }
        tcp = (struct ndpi_tcphdr *)l4_ptr;
        l4_payload_len = ndpi_max(0, l4_len - 4 * tcp->doff);
        flow_basic.tcp_fin_rst_seen = (tcp->fin == 1 || tcp->rst == 1 ? 1 : 0);
        flow_basic.tcp_is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow_basic.src_port = ntohs(tcp->source);
        flow_basic.dst_port = ntohs(tcp->dest);
    }
    else if (flow_basic.l4_protocol == IPPROTO_UDP)
    {
        const struct ndpi_udphdr * udp;

        if (header->caplen < (l4_ptr - packet) + sizeof(struct ndpi_udphdr))
        {
            jsonize_packet_event(
                reader_thread, header, packet, type, ip_offset, (l4_ptr - packet), l4_len, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 UDP_PACKET_TOO_SHORT,
                                 "%s%u %s%zu",
                                 "size",
                                 header->caplen,
                                 "expected",
                                 (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
            return;
        }
        udp = (struct ndpi_udphdr *)l4_ptr;
        l4_payload_len = (l4_len > sizeof(struct ndpi_udphdr)) ? l4_len - sizeof(struct ndpi_udphdr) : 0;
        flow_basic.src_port = ntohs(udp->source);
        flow_basic.dst_port = ntohs(udp->dest);
    }
    else
    {
        /* Use layer4 length returned from libnDPI. */
        l4_payload_len = l4_len;
    }

    /* distribute flows to threads while keeping stability (same flow goes always to same thread) */
    thread_index += (flow_basic.src_port < flow_basic.dst_port ? flow_basic.dst_port : flow_basic.src_port);
    thread_index %= nDPId_options.reader_thread_count;
    if (thread_index != reader_thread->array_index)
    {
        return;
    }

    /* calculate flow hash for btree find, search(insert) */
    switch (flow_basic.l3_type)
    {
        case L3_IP:
            if (ndpi_flowv4_flow_hash(flow_basic.l4_protocol,
                                      flow_basic.src.v4.ip,
                                      flow_basic.dst.v4.ip,
                                      flow_basic.src_port,
                                      flow_basic.dst_port,
                                      0,
                                      0,
                                      (uint8_t *)&flow_basic.hashval,
                                      sizeof(flow_basic.hashval)) != 0)
            {
                flow_basic.hashval = flow_basic.src.v4.ip + flow_basic.dst.v4.ip; // fallback
            }
            break;
        case L3_IP6:
            if (ndpi_flowv6_flow_hash(flow_basic.l4_protocol,
                                      &ip6->ip6_src,
                                      &ip6->ip6_dst,
                                      flow_basic.src_port,
                                      flow_basic.dst_port,
                                      0,
                                      0,
                                      (uint8_t *)&flow_basic.hashval,
                                      sizeof(flow_basic.hashval)) != 0)
            {
                flow_basic.hashval = flow_basic.src.v6.ip[0] + flow_basic.src.v6.ip[1];
                flow_basic.hashval += flow_basic.dst.v6.ip[0] + flow_basic.dst.v6.ip[1];
            }
            break;
    }
    flow_basic.hashval += flow_basic.l4_protocol + flow_basic.src_port + flow_basic.dst_port;

    hashed_index = flow_basic.hashval % workflow->max_active_flows;
    tree_result = ndpi_tfind(&flow_basic, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
    if (tree_result == NULL)
    {
        /* flow not found in btree: switch src <-> dst and try to find it again */
        uint64_t orig_src_ip[2] = {flow_basic.src.v6.ip[0], flow_basic.src.v6.ip[1]};
        uint64_t orig_dst_ip[2] = {flow_basic.dst.v6.ip[0], flow_basic.dst.v6.ip[1]};
        uint16_t orig_src_port = flow_basic.src_port;
        uint16_t orig_dst_port = flow_basic.dst_port;

        flow_basic.src.v6.ip[0] = orig_dst_ip[0];
        flow_basic.src.v6.ip[1] = orig_dst_ip[1];
        flow_basic.dst.v6.ip[0] = orig_src_ip[0];
        flow_basic.dst.v6.ip[1] = orig_src_ip[1];
        flow_basic.src_port = orig_dst_port;
        flow_basic.dst_port = orig_src_port;

        tree_result = ndpi_tfind(&flow_basic, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
        if (tree_result != NULL)
        {
            direction_changed = 1;
        }

        flow_basic.src.v6.ip[0] = orig_src_ip[0];
        flow_basic.src.v6.ip[1] = orig_src_ip[1];
        flow_basic.dst.v6.ip[0] = orig_dst_ip[0];
        flow_basic.dst.v6.ip[1] = orig_dst_ip[1];
        flow_basic.src_port = orig_src_port;
        flow_basic.dst_port = orig_dst_port;
    }

    if (tree_result == NULL)
    {
        /* flow still not found, must be new or midstream */

        union nDPId_ip const * netmask = NULL;
        union nDPId_ip const * subnet = NULL;
        switch (flow_basic.l3_type)
        {
            case L3_IP:
                netmask = &nDPId_options.pcap_dev_netmask4;
                subnet = &nDPId_options.pcap_dev_subnet4;
                break;
            case L3_IP6:
                netmask = &nDPId_options.pcap_dev_netmask6;
                subnet = &nDPId_options.pcap_dev_subnet6;
                break;
        }
        if (nDPId_options.process_internal_initial_direction != 0 && flow_basic.tcp_is_midstream_flow == 0)
        {
            if (is_ip_in_subnet(&flow_basic.src, netmask, subnet, flow_basic.l3_type) == 0)
            {
                if (add_new_flow(workflow, &flow_basic, FT_SKIPPED, hashed_index) == NULL)
                {
                    jsonize_packet_event(reader_thread,
                                         header,
                                         packet,
                                         type,
                                         ip_offset,
                                         (l4_ptr - packet),
                                         l4_len,
                                         NULL,
                                         PACKET_EVENT_PAYLOAD);
                    jsonize_basic_eventf(reader_thread,
                                         FLOW_MEMORY_ALLOCATION_FAILED,
                                         "%s%zu",
                                         "size",
                                         sizeof(struct nDPId_flow_skipped));
                }
                return;
            }
        }
        else if (nDPId_options.process_external_initial_direction != 0 && flow_basic.tcp_is_midstream_flow == 0)
        {
            if (is_ip_in_subnet(&flow_basic.src, netmask, subnet, flow_basic.l3_type) != 0)
            {
                if (add_new_flow(workflow, &flow_basic, FT_SKIPPED, hashed_index) == NULL)
                {
                    jsonize_packet_event(reader_thread,
                                         header,
                                         packet,
                                         type,
                                         ip_offset,
                                         (l4_ptr - packet),
                                         l4_len,
                                         NULL,
                                         PACKET_EVENT_PAYLOAD);
                    jsonize_basic_eventf(reader_thread,
                                         FLOW_MEMORY_ALLOCATION_FAILED,
                                         "%s%zu",
                                         "size",
                                         sizeof(struct nDPId_flow_skipped));
                }
                return;
            }
        }

        if (workflow->cur_active_flows == workflow->max_active_flows)
        {
            jsonize_packet_event(
                reader_thread, header, packet, type, ip_offset, (l4_ptr - packet), l4_len, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(reader_thread,
                                 MAX_FLOW_TO_TRACK,
                                 "%s%llu %s%llu %s%llu %s%llu",
                                 "current_active",
                                 workflow->max_active_flows,
                                 "current_idle",
                                 workflow->cur_idle_flows,
                                 "max_active",
                                 workflow->max_active_flows,
                                 "max_idle",
                                 workflow->max_idle_flows);
            return;
        }

        flow_to_process = (struct nDPId_flow_info *)add_new_flow(workflow, &flow_basic, FT_INFO, hashed_index);
        if (flow_to_process == NULL)
        {
            jsonize_packet_event(
                reader_thread, header, packet, type, ip_offset, (l4_ptr - packet), l4_len, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, FLOW_MEMORY_ALLOCATION_FAILED, "%s%zu", "size", sizeof(*flow_to_process));
            return;
        }

        workflow->cur_active_flows++;
        workflow->total_active_flows++;
        flow_to_process->flow_extended.flow_id = __sync_fetch_and_add(&global_flow_id, 1);

        if (alloc_detection_data(flow_to_process) != 0)
        {
            jsonize_packet_event(
                reader_thread, header, packet, type, ip_offset, (l4_ptr - packet), l4_len, NULL, PACKET_EVENT_PAYLOAD);
            jsonize_basic_eventf(
                reader_thread, FLOW_MEMORY_ALLOCATION_FAILED, "%s%zu", "size", sizeof(*flow_to_process));
            return;
        }

        ndpi_src = &flow_to_process->detection_data->src;
        ndpi_dst = &flow_to_process->detection_data->dst;

        is_new_flow = 1;
    }
    else
    {
        /* flow already exists in the tree */

        struct nDPId_flow_basic * const flow_basic_to_process = *(struct nDPId_flow_basic **)tree_result;
        /* Update last seen timestamp for timeout handling. */
        flow_basic_to_process->last_seen = workflow->last_time;
        /* TCP-FIN/TCP-RST: indicates that at least one side wants to end the connection. */
        if (flow_basic.tcp_fin_rst_seen != 0)
        {
            flow_basic_to_process->tcp_fin_rst_seen = 1;
        }

        switch (flow_basic_to_process->type)
        {
            case FT_UNKNOWN:
            case FT_SKIPPED:
                return;

            case FT_FINISHED:
            case FT_INFO:
                break;
        }
        flow_to_process = (struct nDPId_flow_info *)flow_basic_to_process;

#ifdef ENABLE_ZLIB
        if (nDPId_options.enable_zlib_compression != 0 && flow_to_process->detection_data_compressed_size > 0)
        {
            int ret = detection_data_inflate(flow_to_process);
            if (ret <= 0)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "zLib decompression failed for existing flow %llu with error code: %d",
                       flow_to_process->flow_extended.flow_id,
                       ret);
                return;
            }
        }
#endif

        if (flow_to_process->detection_data != NULL)
        {
            if (direction_changed != 0)
            {
                ndpi_src = &flow_to_process->detection_data->dst;
                ndpi_dst = &flow_to_process->detection_data->src;
            }
            else
            {
                ndpi_src = &flow_to_process->detection_data->src;
                ndpi_dst = &flow_to_process->detection_data->dst;
            }
        }
        else
        {
            ndpi_src = NULL;
            ndpi_dst = NULL;
        }
    }

    flow_to_process->flow_extended.packets_processed++;
    flow_to_process->flow_extended.total_l4_payload_len += l4_payload_len;
    workflow->packets_processed++;
    workflow->total_l4_data_len += l4_payload_len;

    if (flow_to_process->flow_extended.first_seen == 0)
    {
        flow_to_process->flow_extended.first_seen = flow_to_process->flow_extended.flow_basic.last_seen =
            flow_to_process->flow_extended.last_flow_update = workflow->last_time;
    }
    if (l4_payload_len > flow_to_process->flow_extended.max_l4_payload_len)
    {
        flow_to_process->flow_extended.max_l4_payload_len = l4_payload_len;
    }
    if (l4_payload_len < flow_to_process->flow_extended.min_l4_payload_len)
    {
        flow_to_process->flow_extended.min_l4_payload_len = l4_payload_len;
    }

    if (flow_to_process->flow_extended.flow_basic.type != FT_INFO)
    {
        /* Only FT_INFO goes through the whole detection process. */
        return;
    }

    if (is_new_flow != 0)
    {
        flow_to_process->flow_extended.max_l4_payload_len = l4_payload_len;
        flow_to_process->flow_extended.min_l4_payload_len = l4_payload_len;
        jsonize_flow_event(reader_thread, &flow_to_process->flow_extended, FLOW_EVENT_NEW);
    }

    jsonize_packet_event(reader_thread,
                         header,
                         packet,
                         type,
                         ip_offset,
                         (l4_ptr - packet),
                         l4_len,
                         &flow_to_process->flow_extended,
                         PACKET_EVENT_PAYLOAD_FLOW);

    if (flow_to_process->detection_data->flow.num_processed_pkts == nDPId_options.max_packets_per_flow_to_process - 1)
    {
        if (flow_to_process->detection_completed != 0)
        {
            reader_thread->workflow->total_flow_detection_updates++;
            jsonize_flow_detection_event(reader_thread, flow_to_process, FLOW_EVENT_DETECTION_UPDATE);
        }
        else
        {
            /* last chance to guess something, better then nothing */
            uint8_t protocol_was_guessed = 0;
            flow_to_process->detection_data->guessed_l7_protocol = ndpi_detection_giveup(
                workflow->ndpi_struct, &flow_to_process->detection_data->flow, 1, &protocol_was_guessed);
            if (protocol_was_guessed != 0)
            {
                workflow->total_guessed_flows++;
                jsonize_flow_detection_event(reader_thread, flow_to_process, FLOW_EVENT_GUESSED);
            }
            else
            {
                reader_thread->workflow->total_not_detected_flows++;
                jsonize_flow_detection_event(reader_thread, flow_to_process, FLOW_EVENT_NOT_DETECTED);
            }
        }
    }

    flow_to_process->detection_data->detected_l7_protocol =
        ndpi_detection_process_packet(workflow->ndpi_struct,
                                      &flow_to_process->detection_data->flow,
                                      ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6,
                                      ip_size,
                                      workflow->last_time,
                                      ndpi_src,
                                      ndpi_dst);

    if (ndpi_is_protocol_detected(workflow->ndpi_struct, flow_to_process->detection_data->detected_l7_protocol) != 0 &&
        flow_to_process->detection_completed == 0)
    {
        flow_to_process->detection_completed = 1;
        workflow->total_detected_flows++;
        jsonize_flow_detection_event(reader_thread, flow_to_process, FLOW_EVENT_DETECTED);
        flow_to_process->detection_data->last_ndpi_flow_struct_hash =
            calculate_ndpi_flow_struct_hash(&flow_to_process->detection_data->flow);
    }
    else if (flow_to_process->detection_completed == 1)
    {
        uint32_t hash = calculate_ndpi_flow_struct_hash(&flow_to_process->detection_data->flow);
        if (hash != flow_to_process->detection_data->last_ndpi_flow_struct_hash)
        {
            workflow->total_flow_detection_updates++;
            jsonize_flow_detection_event(reader_thread, flow_to_process, FLOW_EVENT_DETECTION_UPDATE);
            flow_to_process->detection_data->last_ndpi_flow_struct_hash = hash;
        }
    }

    if (flow_to_process->detection_data->flow.num_processed_pkts == nDPId_options.max_packets_per_flow_to_process)
    {
        free_detection_data(flow_to_process);
        flow_to_process->flow_extended.flow_basic.type = FT_FINISHED;
    }
#ifdef ENABLE_ZLIB
    else if (nDPId_options.enable_zlib_compression != 0)
    {
        check_for_compressable_flows(reader_thread);
    }
#endif
}

static void run_pcap_loop(struct nDPId_reader_thread * const reader_thread)
{
    if (reader_thread->workflow != NULL && reader_thread->workflow->pcap_handle != NULL)
    {
        if (reader_thread->workflow->is_pcap_file != 0)
        {
            switch (pcap_loop(reader_thread->workflow->pcap_handle, -1, &ndpi_process_packet, (uint8_t *)reader_thread))
            {
                case PCAP_ERROR:
                    syslog(LOG_DAEMON | LOG_ERR,
                           "Error while reading pcap file: '%s'",
                           pcap_geterr(reader_thread->workflow->pcap_handle));
                    __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
                    return;
                case PCAP_ERROR_BREAK:
                    __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
                    return;
                default:
                    return;
            }
        }
        else
        {
            int pcap_fd = pcap_get_selectable_fd(reader_thread->workflow->pcap_handle);
            if (pcap_fd < 0)
            {
                syslog(LOG_DAEMON | LOG_ERR, "%s", "Got an invalid PCAP fd");
                __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
                return;
            }

            int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
            if (epoll_fd < 0)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Got an invalid epoll fd: %s", strerror(errno));
                __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
                return;
            }

            struct epoll_event event = {};
            event.events = EPOLLIN;
            event.data.fd = pcap_fd;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pcap_fd, &event) != 0)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "Could not add pcap fd %d to epoll fd %d: %s",
                       epoll_fd,
                       pcap_fd,
                       strerror(errno));
                __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
                return;
            }

            struct epoll_event events[32];
            size_t const events_size = sizeof(events) / sizeof(events[0]);
            int const timeout_ms = 1000; /* TODO: Configurable? */
            int nready;
            while (nDPId_main_thread_shutdown == 0 && processing_threads_error_or_eof() == 0)
            {
                nready = epoll_wait(epoll_fd, events, events_size, timeout_ms);

                if (nready == 0)
                {
                    reader_thread->workflow->last_time += timeout_ms;

                    do_periodically_work(reader_thread);
                }

                for (int i = 0; i < nready; ++i)
                {
                    switch (pcap_dispatch(
                        reader_thread->workflow->pcap_handle, -1, ndpi_process_packet, (uint8_t *)reader_thread))
                    {
                        case PCAP_ERROR:
                            syslog(LOG_DAEMON | LOG_ERR,
                                   "Error while reading from pcap device: '%s'",
                                   pcap_geterr(reader_thread->workflow->pcap_handle));
                            __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
                            break;
                        case PCAP_ERROR_BREAK:
                            __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
                            return;
                        default:
                            break;
                    }
                }
            }
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
               "Thread %u: Could not connect to nDPIsrvd Collector at %s, will try again later. Error: %s",
               reader_thread->array_index,
               nDPId_options.json_sockpath,
               (errno != 0 ? strerror(errno) : "Internal Error."));
    }
    else
    {
        jsonize_daemon(reader_thread, DAEMON_EVENT_INIT);
    }

    run_pcap_loop(reader_thread);
    fcntl(reader_thread->json_sockfd, F_SETFL, fcntl(reader_thread->json_sockfd, F_GETFL, 0) & ~O_NONBLOCK);
    __sync_fetch_and_add(&reader_thread->workflow->error_or_eof, 1);
    return NULL;
}

static int processing_threads_error_or_eof(void)
{
    for (unsigned long long int i = 0; i < nDPId_options.reader_thread_count; ++i)
    {
        if (__sync_fetch_and_add(&reader_threads[i].workflow->error_or_eof, 0) == 0)
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

    if (daemonize_with_pidfile(nDPId_options.pidfile) != 0)
    {
        return 1;
    }
    closelog();
    openlog("nDPId", LOG_CONS | (nDPId_options.log_to_stderr != 0 ? LOG_PERROR : 0), LOG_DAEMON);

    errno = 0;
    if (change_user_group(nDPId_options.user, nDPId_options.group, nDPId_options.pidfile, NULL, NULL) != 0)
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

    for (unsigned long long int i = 0; i < nDPId_options.reader_thread_count; ++i)
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
    struct nDPId_flow_basic * const flow_basic = *(struct nDPId_flow_basic **)A;

    (void)depth;

    if (workflow == NULL || flow_basic == NULL)
    {
        return;
    }

    if (workflow->cur_idle_flows == nDPId_options.max_idle_flows_per_thread)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow_basic;
        switch (flow_basic->type)
        {
            case FT_UNKNOWN:
            case FT_SKIPPED:
                break;
            case FT_INFO:
            case FT_FINISHED:
                workflow->total_idle_flows++;
                break;
        }
    }
}

static void process_remaining_flows(void)
{
    for (unsigned long long int i = 0; i < nDPId_options.reader_thread_count; ++i)
    {
        if (fcntl(reader_threads[i].json_sockfd,
                  F_SETFL,
                  fcntl(reader_threads[i].json_sockfd, F_GETFL, 0) & ~O_NONBLOCK) == -1)
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "Could not set JSON fd %d to blocking mode for shutdown: %s",
                   reader_threads[i].json_sockfd,
                   strerror(errno));
        }

        for (size_t idle_scan_index = 0; idle_scan_index < reader_threads[i].workflow->max_active_flows;
             ++idle_scan_index)
        {
            ndpi_twalk(reader_threads[i].workflow->ndpi_flows_active[idle_scan_index],
                       ndpi_shutdown_walker,
                       reader_threads[i].workflow);
            process_idle_flow(&reader_threads[i], idle_scan_index);
        }

        jsonize_daemon(&reader_threads[i], DAEMON_EVENT_SHUTDOWN);
    }
}

static int stop_reader_threads(void)
{
    unsigned long long int total_packets_processed = 0;
    unsigned long long int total_l4_data_len = 0;
    unsigned long long int total_flows_skipped = 0;
    unsigned long long int total_flows_captured = 0;
    unsigned long long int total_flows_idle = 0;
    unsigned long long int total_not_detected = 0;
    unsigned long long int total_flows_guessed = 0;
    unsigned long long int total_flows_detected = 0;
    unsigned long long int total_flow_detection_updates = 0;
    unsigned long long int total_flow_updates = 0;

    for (unsigned long long int i = 0; i < nDPId_options.reader_thread_count; ++i)
    {
        break_pcap_loop(&reader_threads[i]);
    }

    printf("------------------------------------ Stopping reader threads\n");
    for (unsigned long long int i = 0; i < nDPId_options.reader_thread_count; ++i)
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
    process_remaining_flows();

    printf("------------------------------------ Results\n");
    for (unsigned long long int i = 0; i < nDPId_options.reader_thread_count; ++i)
    {
        if (reader_threads[i].workflow == NULL)
        {
            continue;
        }

        total_packets_processed += reader_threads[i].workflow->packets_processed;
        total_l4_data_len += reader_threads[i].workflow->total_l4_data_len;
        total_flows_skipped += reader_threads[i].workflow->total_skipped_flows;
        total_flows_captured += reader_threads[i].workflow->total_active_flows;
        total_flows_idle += reader_threads[i].workflow->total_idle_flows;
        total_not_detected += reader_threads[i].workflow->total_not_detected_flows;
        total_flows_guessed += reader_threads[i].workflow->total_guessed_flows;
        total_flows_detected += reader_threads[i].workflow->total_detected_flows;
        total_flow_detection_updates += reader_threads[i].workflow->total_flow_detection_updates;
        total_flow_updates += reader_threads[i].workflow->total_flow_updates;

        printf(
            "Stopping Thread %2d, processed %llu packets, %llu bytes\n"
            "\tskipped flows.....: %8llu, processed flows: %8llu, idle flows....: %8llu\n"
            "\tnot detected flows: %8llu, guessed flows..: %8llu, detected flows: %8llu\n"
            "\tdetection updates.: %8llu, updated flows..: %8llu\n",
            reader_threads[i].array_index,
            reader_threads[i].workflow->packets_processed,
            reader_threads[i].workflow->total_l4_data_len,
            reader_threads[i].workflow->total_skipped_flows,
            reader_threads[i].workflow->total_active_flows,
            reader_threads[i].workflow->total_idle_flows,
            reader_threads[i].workflow->total_not_detected_flows,
            reader_threads[i].workflow->total_guessed_flows,
            reader_threads[i].workflow->total_detected_flows,
            reader_threads[i].workflow->total_flow_detection_updates,
            reader_threads[i].workflow->total_flow_updates);
    }
    /* total packets captured: same value for all threads as packet2thread distribution happens later */
    printf("Total packets captured.......: %llu\n", reader_threads[0].workflow->packets_captured);
    printf("Total packets processed......: %llu\n", total_packets_processed);
    printf("Total layer4 data size.......: %llu\n", total_l4_data_len);
    printf("Total flows ignopred.........: %llu\n", total_flows_skipped);
    printf("Total flows processed........: %llu\n", total_flows_captured);
    printf("Total flows timed out........: %llu\n", total_flows_idle);
    printf("Total flows detected.........: %llu\n", total_flows_detected);
    printf("Total flows guessed..........: %llu\n", total_flows_guessed);
    printf("Total flows not detected.....: %llu\n", total_not_detected);
    printf("Total flow updates...........: %llu\n", total_flow_updates);
    printf("Total flow detections updates: %llu\n", total_flow_detection_updates);

    return 0;
}

static void free_reader_threads(void)
{
    for (unsigned long long int i = 0; i < nDPId_options.reader_thread_count; ++i)
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
    (void)signum;

    if (__sync_fetch_and_add(&nDPId_main_thread_shutdown, 0) == 0)
    {
        __sync_fetch_and_add(&nDPId_main_thread_shutdown, 1);
    }
}

static void print_subopt_usage(void)
{
    int index = MAX_FLOWS_PER_THREAD;
    char * const * token = &subopt_token[0];

    fprintf(stderr, "\tsubopts:\n");
    do
    {
        if (*token != NULL)
        {
            fprintf(stderr, "\t\t%s = ", *token);
            enum nDPId_subopts subopts = index++;
            switch (subopts)
            {
                case MAX_FLOWS_PER_THREAD:
                    fprintf(stderr, "%llu\n", nDPId_options.max_flows_per_thread);
                    break;
                case MAX_IDLE_FLOWS_PER_THREAD:
                    fprintf(stderr, "%llu\n", nDPId_options.max_idle_flows_per_thread);
                    break;
                case TICK_RESOLUTION:
                    fprintf(stderr, "%llu\n", nDPId_options.tick_resolution);
                    break;
                case MAX_READER_THREADS:
                    fprintf(stderr, "%llu\n", nDPId_options.reader_thread_count);
                    break;
#ifdef ENABLE_MEMORY_PROFILING
                case MEMORY_PROFILING_LOG_INTERVAL:
                    fprintf(stderr, "%llu\n", nDPId_options.memory_profiling_log_interval);
                    break;
#endif
#ifdef ENABLE_ZLIB
                case COMPRESSION_SCAN_INTERVAL:
                    fprintf(stderr, "%llu\n", nDPId_options.compression_scan_interval);
                    break;
                case COMPRESSION_FLOW_INACTIVITY:
                    fprintf(stderr, "%llu\n", nDPId_options.compression_flow_inactivity);
                    break;
#endif
                case FLOW_SCAN_INTVERAL:
                    fprintf(stderr, "%llu\n", nDPId_options.flow_scan_interval);
                    break;
                case GENERIC_MAX_IDLE_TIME:
                    fprintf(stderr, "%llu\n", nDPId_options.generic_max_idle_time);
                    break;
                case ICMP_MAX_IDLE_TIME:
                    fprintf(stderr, "%llu\n", nDPId_options.icmp_max_idle_time);
                    break;
                case UDP_MAX_IDLE_TIME:
                    fprintf(stderr, "%llu\n", nDPId_options.udp_max_idle_time);
                    break;
                case TCP_MAX_IDLE_TIME:
                    fprintf(stderr, "%llu\n", nDPId_options.tcp_max_idle_time);
                    break;
                case TCP_MAX_POST_END_FLOW_TIME:
                    fprintf(stderr, "%llu\n", nDPId_options.tcp_max_post_end_flow_time);
                    break;
                case MAX_PACKETS_PER_FLOW_TO_SEND:
                    fprintf(stderr, "%llu\n", nDPId_options.max_packets_per_flow_to_send);
                    break;
                case MAX_PACKETS_PER_FLOW_TO_PROCESS:
                    fprintf(stderr, "%llu\n", nDPId_options.max_packets_per_flow_to_process);
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

static int nDPId_parse_options(int argc, char ** argv)
{
    int opt;

    static char const usage[] =
        "Usage: %s "
        "[-i pcap-file/interface] [-I] [-E] [-B bpf-filter]\n"
        "\t  \t"
        "[-l] [-c path-to-unix-sock] "
        "[-d] [-p pidfile]\n"
        "\t  \t"
        "[-u user] [-g group] "
        "[-P path] [-C path] [-J path]\n"
        "\t  \t"
        "[-a instance-alias] [-o subopt=value]\n"
        "\t  \t"
        "[-v] [-h]\n\n"
        "\t-i\tInterface or file from where to read packets from.\n"
        "\t-I\tProcess only packets where the source address of the first packet\n"
        "\t  \tis part of the interface subnet. (Internal mode)\n"
        "\t-E\tProcess only packets where the source address of the first packet\n"
        "\t  \tis *NOT* part of the interface subnet. (External mode)\n"
        "\t-B\tSet an optional PCAP filter string. (BPF format)\n"
        "\t-l\tLog all messages to stderr as well. Logging via Syslog is always enabled.\n"
        "\t-c\tPath to the UNIX socket (nDPIsrvd Collector).\n"
        "\t-d\tForking into background after initialization.\n"
        "\t-p\tWrite the daemon PID to the given file path.\n"
        "\t-u\tChange UID to the numeric value of user.\n"
        "\t-g\tChange GID to the numeric value of group.\n"
        "\t-P\tLoad a nDPI custom protocols file.\n"
        "\t-C\tLoad a nDPI custom categories file.\n"
        "\t-J\tLoad a nDPI JA3 hash blacklist file.\n"
        "\t  \tSee: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv\n"
        "\t-S\tLoad a nDPI SSL SHA1 hash blacklist file.\n"
        "\t  \tSee: https://sslbl.abuse.ch/blacklist/sslblacklist.csv\n"
        "\t-a\tSet an alias name of this daemon instance which will\n"
        "\t  \tbe part of every JSON message.\n"
        "\t  \tThis value is required for correct flow handling of\n"
        "\t  \tmultiple instances and should be unique.\n"
        "\t  \tDefaults to your hostname.\n"
#ifdef ENABLE_ZLIB
        "\t-z\tEnable flow memory zLib compression.\n"
#endif
        "\t-o\t(Carefully) Tune some daemon options. See subopts below.\n"
        "\t-v\tversion\n"
        "\t-h\tthis\n\n";

    while ((opt = getopt(argc, argv, "hi:IEB:lc:dp:u:g:P:C:J:S:a:zo:vh")) != -1)
    {
        switch (opt)
        {
            case 'i':
                nDPId_options.pcap_file_or_interface = strdup(optarg);
                break;
            case 'I':
                nDPId_options.process_internal_initial_direction = 1;
                break;
            case 'E':
                nDPId_options.process_external_initial_direction = 1;
                break;
            case 'B':
                nDPId_options.bpf_str = strdup(optarg);
                break;
            case 'l':
                nDPId_options.log_to_stderr = 1;
                if (setvbuf(stderr, NULL, _IOLBF, 0) != 0)
                {
                    fprintf(stderr,
                            "%s: Could not set stderr line-buffered, "
                            "console syslog() messages may appear weird.\n",
                            argv[0]);
                }
                break;
            case 'c':
                strncpy(nDPId_options.json_sockpath, optarg, sizeof(nDPId_options.json_sockpath) - 1);
                nDPId_options.json_sockpath[sizeof(nDPId_options.json_sockpath) - 1] = '\0';
                break;
            case 'd':
                daemonize_enable();
                break;
            case 'p':
                strncpy(nDPId_options.pidfile, optarg, sizeof(nDPId_options.pidfile) - 1);
                nDPId_options.pidfile[sizeof(nDPId_options.pidfile) - 1] = '\0';
                break;
            case 'u':
                nDPId_options.user = strdup(optarg);
                break;
            case 'g':
                nDPId_options.group = strdup(optarg);
                break;
            case 'P':
                nDPId_options.custom_protocols_file = strdup(optarg);
                break;
            case 'C':
                nDPId_options.custom_categories_file = strdup(optarg);
                break;
            case 'J':
                nDPId_options.custom_ja3_file = strdup(optarg);
                break;
            case 'S':
                nDPId_options.custom_sha1_file = strdup(optarg);
                break;
            case 'a':
                nDPId_options.instance_alias = strdup(optarg);
                break;
            case 'z':
#ifdef ENABLE_ZLIB
                nDPId_options.enable_zlib_compression = 1;
                break;
#else
                fprintf(stderr, "nDPId was built w/o zLib compression\n");
                return 1;
#endif
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
                            nDPId_options.max_flows_per_thread = value_llu;
                            break;
                        case MAX_IDLE_FLOWS_PER_THREAD:
                            nDPId_options.max_idle_flows_per_thread = value_llu;
                            break;
                        case TICK_RESOLUTION:
                            nDPId_options.tick_resolution = value_llu;
                            break;
                        case MAX_READER_THREADS:
                            nDPId_options.reader_thread_count = value_llu;
                            break;
#ifdef ENABLE_MEMORY_PROFILING
                        case MEMORY_PROFILING_LOG_INTERVAL:
                            nDPId_options.memory_profiling_log_interval = value_llu;
                            break;
#endif
#ifdef ENABLE_ZLIB
                        case COMPRESSION_SCAN_INTERVAL:
                            nDPId_options.compression_scan_interval = value_llu;
                            break;
                        case COMPRESSION_FLOW_INACTIVITY:
                            nDPId_options.compression_flow_inactivity = value_llu;
                            break;
#endif
                        case FLOW_SCAN_INTVERAL:
                            nDPId_options.flow_scan_interval = value_llu;
                            break;
                        case GENERIC_MAX_IDLE_TIME:
                            nDPId_options.generic_max_idle_time = value_llu;
                            break;
                        case ICMP_MAX_IDLE_TIME:
                            nDPId_options.icmp_max_idle_time = value_llu;
                            break;
                        case UDP_MAX_IDLE_TIME:
                            nDPId_options.udp_max_idle_time = value_llu;
                            break;
                        case TCP_MAX_IDLE_TIME:
                            nDPId_options.tcp_max_idle_time = value_llu;
                            break;
                        case TCP_MAX_POST_END_FLOW_TIME:
                            nDPId_options.tcp_max_post_end_flow_time = value_llu;
                            break;
                        case MAX_PACKETS_PER_FLOW_TO_SEND:
                            nDPId_options.max_packets_per_flow_to_send = value_llu;
                            break;
                        case MAX_PACKETS_PER_FLOW_TO_PROCESS:
                            nDPId_options.max_packets_per_flow_to_process = value_llu;
                    }
                }
                break;
            }
            case 'v':
                fprintf(stderr, "%s", get_nDPId_version());
                return 1;
            case 'h':
            default:
                fprintf(stderr, "%s\n", get_nDPId_version());
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

#ifdef ENABLE_ZLIB
    if (nDPId_options.enable_zlib_compression != 0)
    {
        if (nDPId_options.compression_flow_inactivity < 10000 || nDPId_options.compression_scan_interval < 10000)
        {
            fprintf(stderr,
                    "%s: Setting compression-scan-interval / compression-flow-activity to values lower than 10000 is "
                    "not "
                    "recommended.\n"
                    "%s: Your CPU usage may increase heavily.\n",
                    arg0,
                    arg0);
        }
    }
#endif
    if (is_path_absolute("JSON socket", nDPId_options.json_sockpath) != 0)
    {
        retval = 1;
    }
    if (nDPId_options.instance_alias == NULL)
    {
        char hname[256];

        errno = 0;
        if (gethostname(hname, sizeof(hname)) != 0)
        {
            fprintf(stderr, "%s: Could not retrieve your hostname: %s\n", arg0, strerror(errno));
            retval = 1;
        }
        else
        {
            nDPId_options.instance_alias = strdup(hname);
            fprintf(stderr,
                    "%s: No instance alias given, using your hostname '%s'\n",
                    arg0,
                    nDPId_options.instance_alias);
            if (nDPId_options.instance_alias == NULL)
            {
                retval = 1;
            }
        }
    }
    if (nDPId_options.max_flows_per_thread < 128 || nDPId_options.max_flows_per_thread > nDPId_MAX_FLOWS_PER_THREAD)
    {
        fprintf(stderr,
                "%s: Value not in range: 128 < max-flows-per-thread[%llu] < %d\n",
                arg0,
                nDPId_options.max_flows_per_thread,
                nDPId_MAX_FLOWS_PER_THREAD);
        retval = 1;
    }
    if (nDPId_options.max_idle_flows_per_thread < 64 ||
        nDPId_options.max_idle_flows_per_thread > nDPId_MAX_IDLE_FLOWS_PER_THREAD)
    {
        fprintf(stderr,
                "%s: Value not in range: 64 < max-idle-flows-per-thread[%llu] < %d\n",
                arg0,
                nDPId_options.max_idle_flows_per_thread,
                nDPId_MAX_IDLE_FLOWS_PER_THREAD);
        retval = 1;
    }
    if (nDPId_options.tick_resolution < 1)
    {
        fprintf(stderr, "%s: Value not in range: tick-resolution[%llu] > 1\n", arg0, nDPId_options.tick_resolution);
        retval = 1;
    }
    if (nDPId_options.reader_thread_count < 1 || nDPId_options.reader_thread_count > nDPId_MAX_READER_THREADS)
    {
        fprintf(stderr,
                "%s: Value not in range: 1 < reader-thread-count[%llu] < %d\n",
                arg0,
                nDPId_options.reader_thread_count,
                nDPId_MAX_READER_THREADS);
        retval = 1;
    }
    if (nDPId_options.flow_scan_interval < 1000)
    {
        fprintf(stderr,
                "%s: Value not in range: idle-scan-interval[%llu] > 1000\n",
                arg0,
                nDPId_options.flow_scan_interval);
        retval = 1;
    }
    if (nDPId_options.flow_scan_interval >= nDPId_options.generic_max_idle_time)
    {
        fprintf(stderr,
                "%s: Value not in range: flow-scan-interval[%llu] < generic-max-idle-time[%llu]\n",
                arg0,
                nDPId_options.flow_scan_interval,
                nDPId_options.generic_max_idle_time);
        retval = 1;
    }
    if (nDPId_options.flow_scan_interval >= nDPId_options.icmp_max_idle_time)
    {
        fprintf(stderr,
                "%s: Value not in range: flow-scan-interval[%llu] < icmp-max-idle-time[%llu]\n",
                arg0,
                nDPId_options.flow_scan_interval,
                nDPId_options.icmp_max_idle_time);
        retval = 1;
    }
    if (nDPId_options.flow_scan_interval >= nDPId_options.tcp_max_idle_time)
    {
        fprintf(stderr,
                "%s: Value not in range: flow-scan-interval[%llu] < generic-max-idle-time[%llu]\n",
                arg0,
                nDPId_options.flow_scan_interval,
                nDPId_options.tcp_max_idle_time);
        retval = 1;
    }
    if (nDPId_options.flow_scan_interval >= nDPId_options.udp_max_idle_time)
    {
        fprintf(stderr,
                "%s: Value not in range:flow-scan-interval[%llu] < udp-max-idle-time[%llu]\n",
                arg0,
                nDPId_options.flow_scan_interval,
                nDPId_options.udp_max_idle_time);
        retval = 1;
    }
    if (nDPId_options.process_internal_initial_direction != 0 && nDPId_options.process_external_initial_direction != 0)
    {
        fprintf(stderr,
                "%s: Internal and External packet processing does not make sense as this is the default.\n",
                arg0);
        retval = 1;
    }
    if (nDPId_options.process_internal_initial_direction != 0 || nDPId_options.process_external_initial_direction != 0)
    {
        fprintf(stderr,
                "%s: Internal and External packet processing may lead to incorrect results for flows that were active "
                "before the daemon started.\n",
                arg0);
    }
    if (nDPId_options.max_packets_per_flow_to_process < 1 || nDPId_options.max_packets_per_flow_to_process > 65535)
    {
        fprintf(stderr,
                "%s: Value not in range: 1 =< max-packets-per-flow-to-process[%llu] =< 65535\n",
                arg0,
                nDPId_options.max_packets_per_flow_to_process);
        retval = 1;
    }
    if (nDPId_options.max_packets_per_flow_to_send > 30)
    {
        fprintf(stderr,
                "%s: Higher values of max-packets-per-flow-to-send may cause superfluous network usage.\n",
                arg0);
    }

    return retval;
}

#ifndef NO_MAIN
int main(int argc, char ** argv)
{
    if (argc == 0)
    {
        return 1;
    }

    if (nDPId_parse_options(argc, argv) != 0)
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
#ifdef ENABLE_MEMORY_PROFILING
    syslog(LOG_DAEMON, "size/flow: %zu bytes\n", sizeof(struct nDPId_flow_info) + sizeof(struct nDPId_detection_data));
#endif

    if (setup_reader_threads() != 0)
    {
        return 1;
    }

    if (start_reader_threads() != 0)
    {
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    while (nDPId_main_thread_shutdown == 0 && processing_threads_error_or_eof() == 0)
    {
        sleep(1);
    }

    if (stop_reader_threads() != 0)
    {
        return 1;
    }
    free_reader_threads();

    daemonize_shutdown(nDPId_options.pidfile);
    syslog(LOG_DAEMON | LOG_NOTICE, "Bye.");
    closelog();

    return 0;
}
#endif
