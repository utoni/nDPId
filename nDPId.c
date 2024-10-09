#if defined(__FreeBSD__) || defined(__APPLE__)
#include <sys/types.h>
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ndpi_api.h>
#include <ndpi_classify.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#include <stddef.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#if !defined(__FreeBSD__) && !defined(__APPLE__)
#include <sys/signalfd.h>
#endif
#include <sys/un.h>
#include <unistd.h>
#ifdef ENABLE_ZLIB
#include <zlib.h>
#endif

#include "config.h"
#include "nDPIsrvd.h"
#include "nio.h"
#ifdef ENABLE_PFRING
#include "npfring.h"
#endif
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

#ifndef DLT_DSA_TAG_DSA
#define DLT_DSA_TAG_DSA 284
#endif

#ifndef DLT_DSA_TAG_EDSA
#define DLT_DSA_TAG_EDSA 285
#endif

#define NDPI_VERSION_CHECK ((NDPI_MAJOR == 4 && NDPI_MINOR < 9) || NDPI_MAJOR < 4)

#if NDPI_VERSION_CHECK
#error "nDPI >= 4.9.0 required"
#endif

#if nDPId_MAX_READER_THREADS <= 0
#error "Invalid value for nDPId_MAX_READER_THREADS"
#endif

#if nDPId_FLOW_SCAN_INTERVAL > nDPId_GENERIC_IDLE_TIME || nDPId_FLOW_SCAN_INTERVAL > nDPId_ICMP_IDLE_TIME ||           \
    nDPId_FLOW_SCAN_INTERVAL > nDPId_TCP_IDLE_TIME || nDPId_FLOW_SCAN_INTERVAL > nDPId_UDP_IDLE_TIME
#error "Invalid value for nDPId_FLOW_SCAN_INTERVAL"
#endif

#if (nDPId_PACKETS_PLEN_MAX * 3) /* base64 encoded! */ > NETWORK_BUFFER_MAX_SIZE
#error "Invalid value for nDPId_PACKETS_PLEN_MAX"
#endif

#if defined(ENABLE_MEMORY_PROFILING) && !defined(ENABLE_MEMORY_STATUS)
#error "ENABLE_MEMORY_PROFILING requires ENABLE_MEMORY_STATUS to make it work!"
#endif

/* MIPS* does not support Compare and Swap. Use traditional locking as fallback. */
#if !defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4) || !defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)
#define MT_VALUE(name, type)                                                                                           \
    struct name                                                                                                        \
    {                                                                                                                  \
        volatile uint64_t var;                                                                                         \
        pthread_mutex_t var_mutex;                                                                                     \
    } name
#define MT_INIT(value)                                                                                                 \
    {                                                                                                                  \
        value, PTHREAD_MUTEX_INITIALIZER                                                                               \
    }
#define MT_INIT2(name, value)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        name.var = value;                                                                                              \
        pthread_mutex_init(&name.var_mutex, NULL);                                                                     \
    } while (0)

static inline uint64_t mt_pt_get_and_add(volatile uint64_t * value, uint64_t add, pthread_mutex_t * mutex)
{
    uint64_t result;
    pthread_mutex_lock(mutex);
    result = *value;
    *value += add;
    pthread_mutex_unlock(mutex);
    return result;
}

#define MT_GET_AND_ADD(name, value) mt_pt_get_and_add(&name.var, value, &name.var_mutex)

static inline uint64_t mt_pt_get_and_sub(volatile uint64_t * value, uint64_t sub, pthread_mutex_t * mutex)
{
    uint64_t result;
    pthread_mutex_lock(mutex);
    result = *value;
    *value -= sub;
    pthread_mutex_unlock(mutex);
    return result;
}
#define MT_GET_AND_SUB(name, value) mt_pt_get_and_sub(&name.var, value, &name.var_mutex)
#else
#define MT_VALUE(name, type) volatile type name
#define MT_INIT(value) value
#define MT_INIT2(name, value)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        name = value;                                                                                                  \
    } while (0)
#define MT_GET_AND_ADD(name, value) __sync_fetch_and_add(&name, value)
#define MT_GET_AND_SUB(name, value) __sync_fetch_and_sub(&name, value)
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

enum nDPId_flow_state
{
    FS_UNKNOWN = 0, // should never happen, bug otherwise
    FS_SKIPPED,     // flow should not be processed, see command line args -I and -E
    FS_FINISHED,    // detection done and detection data free'd
    FS_INFO,        // detection in progress, detection data allocated
    FS_COUNT
};

enum nDPId_flow_direction
{
    FD_SRC2DST = 0,
    FD_DST2SRC,
    FD_COUNT
};

struct nDPId_flow_analysis
{
    struct ndpi_analyze_struct iat;
    struct ndpi_analyze_struct pktlen;
    uint8_t * directions;
    struct ndpi_bin payload_len_bin[FD_COUNT];
    float * entropies;
};

/*
 * Minimal per-flow information required for flow mgmt and timeout handling.
 */
struct nDPId_flow_basic
{
    enum nDPId_flow_state state;
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
    uint64_t last_pkt_time[FD_COUNT];
};

/*
 * Information required for a full detection cycle.
 */
struct nDPId_flow_extended
{
    struct nDPId_flow_basic flow_basic; // Do not move this element!

    unsigned long long int flow_id;

    uint16_t min_l4_payload_len[FD_COUNT];
    uint16_t max_l4_payload_len[FD_COUNT];
    ;

    unsigned long long int packets_processed[FD_COUNT];
    uint64_t first_seen;
    uint64_t last_flow_update;

    struct nDPId_flow_analysis * flow_analysis;
    unsigned long long int total_l4_payload_len[FD_COUNT];
    struct ndpi_proto detected_l7_protocol;
};
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(offsetof(struct nDPId_flow_extended, flow_basic) == 0,
               "Offset of flow_basic is not zero any more. nDPId won't work anymore w/o changing it's core!");
#endif

/*
 * Skipped flows need at least some information.
 */
struct nDPId_flow_skipped
{
    struct nDPId_flow_basic flow_basic; // Do not move this element!
};
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(offsetof(struct nDPId_flow_skipped, flow_basic) == 0,
               "Offset of flow_basic is not zero any more. nDPId won't work anymore w/o changing it's core!");
#endif

/*
 * Structure which is important for the detection process.
 * The structure is also a compression target, if activated.
 */
struct nDPId_detection_data
{
    uint32_t last_ndpi_flow_struct_hash;
    struct ndpi_proto guessed_l7_protocol;
    struct ndpi_flow_struct flow;
};

struct nDPId_flow
{
    struct nDPId_flow_extended flow_extended; // Do not move this element!

    union
    {
        struct
        {
            uint8_t detection_completed : 1; // Flow was detected. Detection updates may still occur.
            uint8_t reserved_00 : 7;
            uint8_t reserved_01[1];
#ifdef ENABLE_ZLIB
            uint16_t detection_data_compressed_size;
#endif
            struct nDPId_detection_data * detection_data;
        } info;
        struct
        {
            ndpi_risk risk;
            ndpi_confidence_t confidence;
            char * hostname;
        } finished;
    };
};
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(offsetof(struct nDPId_flow, flow_extended) == 0,
               "Offset of flow_extended is not zero any more. nDPId won't work anymore w/o changing it's core!");
#endif

struct nDPId_workflow
{
#ifdef ENABLE_PFRING
    struct npfring npf;
#endif
    pcap_t * pcap_handle;

    MT_VALUE(error_or_eof, uint8_t);
    uint8_t is_pcap_file;

    uint16_t error_count;

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_skipped_flows;
    unsigned long long int total_l4_payload_len;

    unsigned long long int libnDPI_errors;

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
    uint64_t total_compressions;
    uint64_t total_compression_diff;
    uint64_t current_compression_diff;
#endif

    uint64_t last_scan_time;
    uint64_t last_status_time;
    uint64_t last_global_time;
    uint64_t last_thread_time;
    uint64_t last_error_time;

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
    pthread_t thread;
    int collector_sockfd;
    int collector_sock_last_errno;
    size_t array_index;
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
    FLOW_EVENT_END,     // TCP only: FIN/RST packet seen.
    FLOW_EVENT_IDLE,    // Flow timed out.
    FLOW_EVENT_UPDATE,  // Inform distributor applications about flows with a long lifetime.
    FLOW_EVENT_ANALYSE, // Print information regarding a flow analysis, see `struct nDPId_flow_analysis'.

    FLOW_EVENT_GUESSED,
    FLOW_EVENT_DETECTED,
    FLOW_EVENT_DETECTION_UPDATE, // Some information in `struct ndpi_flow_struct' changed.
    FLOW_EVENT_NOT_DETECTED,

    FLOW_EVENT_COUNT
};

enum error_event
{
    ERROR_EVENT_INVALID = 0,

    UNKNOWN_DATALINK_LAYER,
    UNKNOWN_L3_PROTOCOL,
    UNSUPPORTED_DATALINK_LAYER,
    PACKET_TOO_SHORT,
    PACKET_TYPE_UNKNOWN,
    PACKET_HEADER_INVALID,
    IP4_PACKET_TOO_SHORT,
    IP4_SIZE_SMALLER_THAN_HEADER,
    IP4_L4_PAYLOAD_DETECTION_FAILED,
    IP6_PACKET_TOO_SHORT, // 10
    IP6_SIZE_SMALLER_THAN_HEADER,
    IP6_L4_PAYLOAD_DETECTION_FAILED,
    TCP_PACKET_TOO_SHORT,
    UDP_PACKET_TOO_SHORT,
    CAPTURE_SIZE_SMALLER_THAN_PACKET_SIZE,
    MAX_FLOW_TO_TRACK,
    FLOW_MEMORY_ALLOCATION_FAILED,

    ERROR_EVENT_COUNT // 17
};

enum daemon_event
{
    DAEMON_EVENT_INVALID = 0,

    DAEMON_EVENT_INIT,
    DAEMON_EVENT_RECONNECT,
    DAEMON_EVENT_SHUTDOWN,
    DAEMON_EVENT_STATUS,

    DAEMON_EVENT_COUNT
};

static char const * const flow_state_name_table[FS_COUNT] = {
    [FS_UNKNOWN] = "unknown", [FS_SKIPPED] = "skipped", [FS_FINISHED] = "finished", [FS_INFO] = "info"};

static char const * const packet_event_name_table[PACKET_EVENT_COUNT] = {
    [PACKET_EVENT_INVALID] = "invalid", [PACKET_EVENT_PAYLOAD] = "packet", [PACKET_EVENT_PAYLOAD_FLOW] = "packet-flow"};

static char const * const flow_event_name_table[FLOW_EVENT_COUNT] = {[FLOW_EVENT_INVALID] = "invalid",
                                                                     [FLOW_EVENT_NEW] = "new",
                                                                     [FLOW_EVENT_END] = "end",
                                                                     [FLOW_EVENT_IDLE] = "idle",
                                                                     [FLOW_EVENT_UPDATE] = "update",
                                                                     [FLOW_EVENT_ANALYSE] = "analyse",
                                                                     [FLOW_EVENT_GUESSED] = "guessed",
                                                                     [FLOW_EVENT_DETECTED] = "detected",
                                                                     [FLOW_EVENT_DETECTION_UPDATE] = "detection-update",
                                                                     [FLOW_EVENT_NOT_DETECTED] = "not-detected"};
static char const * const error_event_name_table[ERROR_EVENT_COUNT] = {
    [ERROR_EVENT_INVALID] = "invalid",
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
    [DAEMON_EVENT_STATUS] = "status",
};

static struct nDPId_reader_thread reader_threads[nDPId_MAX_READER_THREADS] = {};
static MT_VALUE(nDPId_main_thread_shutdown, int) = MT_INIT(0);
static MT_VALUE(global_flow_id, uint64_t) = MT_INIT(1);

#ifdef ENABLE_MEMORY_STATUS
static MT_VALUE(ndpi_memory_alloc_count, uint64_t) = MT_INIT(0);
static MT_VALUE(ndpi_memory_alloc_bytes, uint64_t) = MT_INIT(0);
static MT_VALUE(ndpi_memory_free_count, uint64_t) = MT_INIT(0);
static MT_VALUE(ndpi_memory_free_bytes, uint64_t) = MT_INIT(0);
#ifdef ENABLE_ZLIB
static MT_VALUE(zlib_compressions, uint64_t) = MT_INIT(0);
static MT_VALUE(zlib_decompressions, uint64_t) = MT_INIT(0);
static MT_VALUE(zlib_compression_diff, uint64_t) = MT_INIT(0);
static MT_VALUE(zlib_compression_bytes, uint64_t) = MT_INIT(0);
#endif
#endif

static struct
{
    /* options which are resolved automatically */
    struct nDPIsrvd_address parsed_collector_address;
    union nDPId_ip pcap_dev_ip4, pcap_dev_ip6;
    union nDPId_ip pcap_dev_netmask4, pcap_dev_netmask6;
    union nDPId_ip pcap_dev_subnet4, pcap_dev_subnet6;
    /* opts */
    struct cmdarg config_file;
    struct cmdarg pcap_file_or_interface;
    struct cmdarg bpf_str;
    struct cmdarg pidfile;
    struct cmdarg user;
    struct cmdarg group;
    struct cmdarg custom_protocols_file;
    struct cmdarg custom_categories_file;
    struct cmdarg custom_ja3_file;
    struct cmdarg custom_sha1_file;
    struct cmdarg collector_address;
    struct cmdarg instance_alias;
    struct cmdarg process_internal_initial_direction;
    struct cmdarg process_external_initial_direction;
#ifdef ENABLE_ZLIB
    struct cmdarg enable_zlib_compression;
#endif
    struct cmdarg enable_data_analysis;
#ifdef ENABLE_EPOLL
    struct cmdarg use_poll;
#endif
#ifdef ENABLE_PFRING
    struct cmdarg use_pfring;
#endif
    /* subopts */
    struct cmdarg max_flows_per_thread;
    struct cmdarg max_idle_flows_per_thread;
    struct cmdarg reader_thread_count;
    struct cmdarg daemon_status_interval;
#ifdef ENABLE_MEMORY_PROFILING
    struct cmdarg memory_profiling_log_interval;
#endif
#ifdef ENABLE_ZLIB
    struct cmdarg compression_scan_interval;
    struct cmdarg compression_flow_inactivity;
#endif
    struct cmdarg flow_scan_interval;
    struct cmdarg generic_max_idle_time;
    struct cmdarg icmp_max_idle_time;
    struct cmdarg udp_max_idle_time;
    struct cmdarg tcp_max_idle_time;
    struct cmdarg tcp_max_post_end_flow_time;
    struct cmdarg max_packets_per_flow_to_send;
    struct cmdarg max_packets_per_flow_to_process;
    struct cmdarg max_packets_per_flow_to_analyse;
    struct cmdarg error_event_threshold_n;
    struct cmdarg error_event_threshold_time;
} nDPId_options = {.config_file = CMDARG_STR(NULL),
                   .pcap_file_or_interface = CMDARG_STR(NULL),
                   .bpf_str = CMDARG_STR(NULL),
                   .pidfile = CMDARG_STR(nDPId_PIDFILE),
                   .user = CMDARG_STR(DEFAULT_CHUSER),
                   .group = CMDARG_STR(NULL),
                   .custom_protocols_file = CMDARG_STR(NULL),
                   .custom_categories_file = CMDARG_STR(NULL),
                   .custom_ja3_file = CMDARG_STR(NULL),
                   .custom_sha1_file = CMDARG_STR(NULL),
                   .collector_address = CMDARG_STR(COLLECTOR_UNIX_SOCKET),
                   .instance_alias = CMDARG_STR(NULL),
                   .process_internal_initial_direction = CMDARG_BOOL(0),
                   .process_external_initial_direction = CMDARG_BOOL(0),
#ifdef ENABLE_ZLIB
                   .enable_zlib_compression = CMDARG_BOOL(0),
#endif
                   .enable_data_analysis = CMDARG_BOOL(0),
#ifdef ENABLE_EPOLL
                   .use_poll = CMDARG_BOOL(0),
#endif
#ifdef ENABLE_PFRING
                   .use_pfring = CMDARG_BOOL(0),
#endif
                   .max_flows_per_thread = CMDARG_ULL(nDPId_MAX_FLOWS_PER_THREAD / 2),
                   .max_idle_flows_per_thread = CMDARG_ULL(nDPId_MAX_IDLE_FLOWS_PER_THREAD / 2),
#ifdef CROSS_COMPILATION
                   /*
                    * We are assuming that in the cross compilation case
                    * our target system is an embedded one with not much memory available.
                    * To further reduce memory consumption caused by allocating nDPId / nDPI workflows per thread,
                    * we set the default reader thread count to two.
                    */
                   .reader_thread_count = CMDARG_ULL(2),
#else
                   .reader_thread_count = CMDARG_ULL(nDPId_MAX_READER_THREADS / 3),
#endif
                   .daemon_status_interval = CMDARG_ULL(nDPId_DAEMON_STATUS_INTERVAL),
#ifdef ENABLE_MEMORY_PROFILING
                   .memory_profiling_log_interval = CMDARG_ULL(nDPId_MEMORY_PROFILING_LOG_INTERVAL),
#endif
#ifdef ENABLE_ZLIB
                   .compression_scan_interval = CMDARG_ULL(nDPId_COMPRESSION_SCAN_INTERVAL),
                   .compression_flow_inactivity = CMDARG_ULL(nDPId_COMPRESSION_FLOW_INACTIVITY),
#endif
                   .flow_scan_interval = CMDARG_ULL(nDPId_FLOW_SCAN_INTERVAL),
                   .generic_max_idle_time = CMDARG_ULL(nDPId_GENERIC_IDLE_TIME),
                   .icmp_max_idle_time = CMDARG_ULL(nDPId_ICMP_IDLE_TIME),
                   .udp_max_idle_time = CMDARG_ULL(nDPId_UDP_IDLE_TIME),
                   .tcp_max_idle_time = CMDARG_ULL(nDPId_TCP_IDLE_TIME),
                   .tcp_max_post_end_flow_time = CMDARG_ULL(nDPId_TCP_POST_END_FLOW_TIME),
                   .max_packets_per_flow_to_send = CMDARG_ULL(nDPId_PACKETS_PER_FLOW_TO_SEND),
                   .max_packets_per_flow_to_process = CMDARG_ULL(nDPId_PACKETS_PER_FLOW_TO_PROCESS),
                   .max_packets_per_flow_to_analyse = CMDARG_ULL(nDPId_PACKETS_PER_FLOW_TO_ANALYZE),
                   .error_event_threshold_n = CMDARG_ULL(nDPId_ERROR_EVENT_THRESHOLD_N),
                   .error_event_threshold_time = CMDARG_ULL(nDPId_ERROR_EVENT_THRESHOLD_TIME)};
struct confopt general_config_map[] = {CONFOPT("netif", &nDPId_options.pcap_file_or_interface),
                                       CONFOPT("bpf", &nDPId_options.bpf_str),
                                       CONFOPT("pidfile", &nDPId_options.pidfile),
                                       CONFOPT("user", &nDPId_options.user),
                                       CONFOPT("group", &nDPId_options.group),
                                       CONFOPT("protocols", &nDPId_options.custom_protocols_file),
                                       CONFOPT("categories", &nDPId_options.custom_categories_file),
                                       CONFOPT("ja3", &nDPId_options.custom_ja3_file),
                                       CONFOPT("sha1", &nDPId_options.custom_sha1_file),
                                       CONFOPT("collector", &nDPId_options.collector_address),
                                       CONFOPT("alias", &nDPId_options.instance_alias),
                                       CONFOPT("internal", &nDPId_options.process_internal_initial_direction),
                                       CONFOPT("external", &nDPId_options.process_external_initial_direction),
#ifdef ENABLE_ZLIB
                                       CONFOPT("compression", &nDPId_options.enable_zlib_compression),
#endif
                                       CONFOPT("analysis", &nDPId_options.enable_data_analysis),
#ifdef ENABLE_EPOLL
                                       CONFOPT("poll", &nDPId_options.use_poll),
#endif
#ifdef ENABLE_PFRING
                                       CONFOPT("pfring", &nDPId_options_use_pfring)
#endif
};
struct confopt tuning_config_map[] = {
    CONFOPT("max-flows-per-thread", &nDPId_options.max_flows_per_thread),
    CONFOPT("max-idle-flows-per-thread", &nDPId_options.max_idle_flows_per_thread),
    CONFOPT("max-reader-threads", &nDPId_options.reader_thread_count),
    CONFOPT("daemon-status-interval", &nDPId_options.daemon_status_interval),
#ifdef ENABLE_MEMORY_PROFILING
    CONFOPT("memory-profiling-log-interval", &nDPId_options.memory_profiling_log_interval),
#endif
#ifdef ENABLE_ZLIB
    CONFOPT("compression-scan-interval", &nDPId_options.compression_scan_interval),
    CONFOPT("compression-flow-inactivity", &nDPId_options.compression_flow_inactivity),
#endif
    CONFOPT("flow-scan-interval", &nDPId_options.flow_scan_interval),
    CONFOPT("generic-max-idle-time", &nDPId_options.generic_max_idle_time),
    CONFOPT("icmp-max-idle-time", &nDPId_options.icmp_max_idle_time),
    CONFOPT("udp-max-idle-time", &nDPId_options.udp_max_idle_time),
    CONFOPT("tcp-max-idle-time", &nDPId_options.tcp_max_idle_time),
    CONFOPT("tcp-max-post-end-flow-time", &nDPId_options.tcp_max_post_end_flow_time),
    CONFOPT("max-packets-per-flow-to-send", &nDPId_options.max_packets_per_flow_to_send),
    CONFOPT("max-packets-per-flow-to-process", &nDPId_options.max_packets_per_flow_to_process),
    CONFOPT("max-packets-per-flow-to-analyse", &nDPId_options.max_packets_per_flow_to_analyse),
    CONFOPT("error-event-threshold-n", &nDPId_options.error_event_threshold_n),
    CONFOPT("error-event-threshold-time", &nDPId_options.error_event_threshold_time),
};

static void sighandler(int signum);
static WARN_UNUSED int processing_threads_error_or_eof(void);
static void free_workflow(struct nDPId_workflow ** const workflow);
static void serialize_and_send(struct nDPId_reader_thread * const reader_thread);
static void jsonize_flow_event(struct nDPId_reader_thread * const reader_thread,
                               struct nDPId_flow_extended * const flow_ext,
                               enum flow_event event);
static void jsonize_flow_detection_event(struct nDPId_reader_thread * const reader_thread,
                                         struct nDPId_flow * const flow,
                                         enum flow_event event);

static int set_collector_nonblock(struct nDPId_reader_thread * const reader_thread)
{
    int current_flags;

    while ((current_flags = fcntl(reader_thread->collector_sockfd, F_GETFL, 0)) == -1 && errno == EINTR) {}
    if (current_flags == -1) {}

    while ((current_flags = fcntl(reader_thread->collector_sockfd, F_SETFL, current_flags | O_NONBLOCK)) == -1 &&
           errno == EINTR)
    {
        // Retry if interrupted by a signal.
    }
    if (current_flags == -1)
    {
        reader_thread->collector_sock_last_errno = errno;
        logger(1,
               "[%8llu] Could not set collector fd %d to non-blocking mode: %s",
               reader_thread->workflow->packets_processed,
               reader_thread->collector_sockfd,
               strerror(errno));
        return 1;
    }

    return 0;
}

static int set_collector_block(struct nDPId_reader_thread * const reader_thread)
{
    int current_flags = fcntl(reader_thread->collector_sockfd, F_GETFL, 0);

    if (current_flags == -1 || fcntl(reader_thread->collector_sockfd, F_SETFL, current_flags & ~O_NONBLOCK) == -1)
    {
        reader_thread->collector_sock_last_errno = errno;
        logger(1,
               "[%8llu] Could not set collector fd %d to blocking mode: %s",
               reader_thread->workflow->packets_processed,
               reader_thread->collector_sockfd,
               strerror(errno));
        return 1;
    }

    return 0;
}

u_int8_t plen2slot(u_int16_t plen)
{
    if (plen > nDPId_ANALYZE_PLEN_MAX)
    {
        return nDPId_ANALYZE_PLEN_NUM_BINS - 1;
    }
    else
    {
        return plen / nDPId_ANALYZE_PLEN_BIN_LEN;
    }
}

static uint64_t get_last_pkt_time(struct nDPId_flow_basic const * const flow_basic)
{
    return ndpi_max(flow_basic->last_pkt_time[FD_SRC2DST], flow_basic->last_pkt_time[FD_DST2SRC]);
}

static uint64_t timer_sub(uint64_t a, uint64_t b)
{
    if (b > a)
    {
        return 0;
    }

    return a - b;
}

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

    err = deflateInit2(&strm, Z_BEST_COMPRESSION, Z_BINARY, 15, 9, Z_HUFFMAN_ONLY);
    if (err != Z_OK)
    {
        err = deflateInit(&strm, Z_BEST_COMPRESSION);
    }
    if (err == Z_OK)
    {
        err = deflate(&strm, Z_FINISH);
        if (err == Z_STREAM_END)
        {
            ret = strm.total_out;
#ifdef ENABLE_MEMORY_STATUS
            MT_GET_AND_ADD(zlib_compressions, 1);
            MT_GET_AND_ADD(zlib_compression_diff, srcLen - ret);
            MT_GET_AND_ADD(zlib_compression_bytes, ret);
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
#ifdef ENABLE_MEMORY_STATUS
            MT_GET_AND_ADD(zlib_decompressions, 1);
            MT_GET_AND_SUB(zlib_compression_diff, ret - srcLen);
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

static int detection_data_deflate(struct nDPId_flow * const flow)
{
    uint8_t tmpOut[sizeof(*flow->info.detection_data)];
    int ret;

    if (flow->info.detection_data_compressed_size > 0)
    {
        return -7;
    }

    ret = zlib_deflate(flow->info.detection_data, sizeof(*flow->info.detection_data), tmpOut, sizeof(tmpOut));
    if (ret <= 0)
    {
        return ret;
    }

    struct nDPId_detection_data * const new_det_data = ndpi_malloc(ret);
    if (new_det_data == NULL)
    {
        return -8;
    }
    ndpi_free(flow->info.detection_data);
    flow->info.detection_data = new_det_data;

    memcpy(flow->info.detection_data, tmpOut, ret);
    flow->info.detection_data_compressed_size = ret;

    return ret;
}

static int detection_data_inflate(struct nDPId_flow * const flow)
{
    uint8_t tmpOut[sizeof(*flow->info.detection_data)];
    int ret;

    if (flow->info.detection_data_compressed_size == 0)
    {
        return -7;
    }

    ret = zlib_inflate(flow->info.detection_data, flow->info.detection_data_compressed_size, tmpOut, sizeof(tmpOut));
    if (ret <= 0)
    {
        return ret;
    }

    struct nDPId_detection_data * const new_det_data = ndpi_malloc(ret);
    if (new_det_data == NULL)
    {
        return -8;
    }
    ndpi_free(flow->info.detection_data);
    flow->info.detection_data = new_det_data;

    memcpy(flow->info.detection_data, tmpOut, ret);
    flow->info.detection_data_compressed_size = 0;

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
        switch (flow_basic->state)
        {
            case FS_UNKNOWN:
            case FS_COUNT:

            case FS_SKIPPED:
            case FS_FINISHED:
                break;

            case FS_INFO:
            {
                if (get_last_pkt_time(flow_basic) + GET_CMDARG_ULL(nDPId_options.compression_flow_inactivity) <
                    workflow->last_thread_time)
                {
                    struct nDPId_flow * const flow = (struct nDPId_flow *)flow_basic;

                    if (flow->info.detection_data_compressed_size > 0)
                    {
                        break;
                    }

                    int ret = detection_data_deflate(flow);

                    if (ret <= 0)
                    {
                        logger(1,
                               "zLib compression failed for flow %llu with error code: %d",
                               flow->flow_extended.flow_id,
                               ret);
                    }
                    else
                    {
                        workflow->total_compressions++;
                        workflow->total_compression_diff += ret;
                        workflow->current_compression_diff += ret;
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

    if (workflow->last_compression_scan_time + GET_CMDARG_ULL(nDPId_options.compression_scan_interval) <
        workflow->last_thread_time)
    {
        for (size_t comp_scan_index = 0; comp_scan_index < workflow->max_active_flows; ++comp_scan_index)
        {
            ndpi_twalk(workflow->ndpi_flows_active[comp_scan_index], ndpi_comp_scan_walker, workflow);
        }

        workflow->last_compression_scan_time = workflow->last_thread_time;
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
#if defined(__FreeBSD__) || defined(__APPLE__)
            dest->v6.ip_u32[0] = saddr->sin6_addr.__u6_addr.__u6_addr32[0];
            dest->v6.ip_u32[1] = saddr->sin6_addr.__u6_addr.__u6_addr32[1];
            dest->v6.ip_u32[2] = saddr->sin6_addr.__u6_addr.__u6_addr32[2];
            dest->v6.ip_u32[3] = saddr->sin6_addr.__u6_addr.__u6_addr32[3];
#else
            dest->v6.ip_u32[0] = saddr->sin6_addr.s6_addr32[0];
            dest->v6.ip_u32[1] = saddr->sin6_addr.s6_addr32[1];
            dest->v6.ip_u32[2] = saddr->sin6_addr.s6_addr32[2];
            dest->v6.ip_u32[3] = saddr->sin6_addr.s6_addr32[3];
#endif
            break;
        default:
            return;
    }
}

static void get_ip6_address_and_netmask(struct ifaddrs const * const ifaddr)
{
    get_ip6_from_sockaddr((struct sockaddr_in6 *)ifaddr->ifa_netmask, &nDPId_options.pcap_dev_netmask6);
    get_ip6_from_sockaddr((struct sockaddr_in6 *)ifaddr->ifa_addr, &nDPId_options.pcap_dev_ip6);
    ip_netmask_to_subnet(&nDPId_options.pcap_dev_ip6,
                         &nDPId_options.pcap_dev_netmask6,
                         &nDPId_options.pcap_dev_subnet6,
                         L3_IP6);
    {
        char addr[INET6_ADDRSTRLEN];
        char netm[INET6_ADDRSTRLEN];
        char subn[INET6_ADDRSTRLEN];
        void * saddr = &nDPId_options.pcap_dev_ip6.v6.ip;
        void * snetm = &nDPId_options.pcap_dev_netmask6.v6.ip;
        void * ssubn = &nDPId_options.pcap_dev_subnet6.v6.ip;
        logger(0,
               "%s IPv6 address netmask subnet: %s %s %s",
               GET_CMDARG_STR(nDPId_options.pcap_file_or_interface),
               inet_ntop(AF_INET6, saddr, addr, sizeof(addr)),
               inet_ntop(AF_INET6, snetm, netm, sizeof(netm)),
               inet_ntop(AF_INET6, ssubn, subn, sizeof(subn)));
    }
}

static void get_ip4_address_and_netmask(struct ifaddrs const * const ifaddr)
{
    get_ip4_from_sockaddr((struct sockaddr_in *)ifaddr->ifa_netmask, &nDPId_options.pcap_dev_netmask4);
    get_ip4_from_sockaddr((struct sockaddr_in *)ifaddr->ifa_addr, &nDPId_options.pcap_dev_ip4);
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
        logger(0,
               "%s IPv4 address netmask subnet: %s %s %s",
               GET_CMDARG_STR(nDPId_options.pcap_file_or_interface),
               inet_ntop(AF_INET, saddr, addr, sizeof(addr)),
               inet_ntop(AF_INET, snetm, netm, sizeof(netm)),
               inet_ntop(AF_INET, ssubn, subn, sizeof(subn)));
    }
}

static int get_ip_netmask_from_pcap_dev(char const * const pcap_dev)
{
    int retval = 0, found_dev = 0;
    int ip4_interface_avail = 0;
    int ip6_interface_avail = 0;
    struct ifaddrs * ifaddrs = NULL;
    struct ifaddrs * ifa;

    if (getifaddrs(&ifaddrs) != 0 || ifaddrs == NULL)
    {
        int saved_errno = errno;
        logger_early(1, "Interface retrieval failed with: %s", strerror(saved_errno));
        errno = saved_errno;
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
                    get_ip4_address_and_netmask(ifa);
                    ip4_interface_avail = 1;
                    break;
                case AF_INET6:
                    get_ip6_address_and_netmask(ifa);
                    ip6_interface_avail = 1;
                    break;
                default:
                    break;
            }
        }
    }

    if (retval == 0 && found_dev != 0 &&
        (GET_CMDARG_BOOLEAN(nDPId_options.process_internal_initial_direction) != 0 ||
         GET_CMDARG_BOOLEAN(nDPId_options.process_external_initial_direction) != 0) &&
        ip4_interface_avail == 0 && ip6_interface_avail == 0)
    {
        logger_early(1, "Interface %s does not have any IPv4 / IPv6 address set, -I / -E won't work.", pcap_dev);
        retval = 1;
    }

    freeifaddrs(ifaddrs);
    return retval;
}

#ifdef ENABLE_MEMORY_STATUS
static void * ndpi_malloc_wrapper(size_t const size)
{
    void * p = malloc(sizeof(uint64_t) + size);

    if (p == NULL)
    {
        return NULL;
    }
    *(uint64_t *)p = size;

    MT_GET_AND_ADD(ndpi_memory_alloc_count, 1);
    MT_GET_AND_ADD(ndpi_memory_alloc_bytes, size);

    return (uint8_t *)p + sizeof(uint64_t);
}

static void ndpi_free_wrapper(void * const freeable)
{
    void * p = (uint8_t *)freeable - sizeof(uint64_t);

    MT_GET_AND_ADD(ndpi_memory_free_count, 1);
    MT_GET_AND_ADD(ndpi_memory_free_bytes, *(uint64_t *)p);

    free(p);
}
#endif

#ifdef ENABLE_MEMORY_PROFILING
static void log_memory_usage(struct nDPId_reader_thread const * const reader_thread)
{
    if (reader_thread->array_index == 0)
    {
        uint64_t alloc_count = MT_GET_AND_ADD(ndpi_memory_alloc_count, 0);
        uint64_t free_count = MT_GET_AND_ADD(ndpi_memory_free_count, 0);
        uint64_t alloc_bytes = MT_GET_AND_ADD(ndpi_memory_alloc_bytes, 0);
        uint64_t free_bytes = MT_GET_AND_ADD(ndpi_memory_free_bytes, 0);

        logger(0,
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
        uint64_t zlib_compression_count = MT_GET_AND_ADD(zlib_compressions, 0);
        uint64_t zlib_decompression_count = MT_GET_AND_ADD(zlib_decompressions, 0);
        uint64_t zlib_bytes_diff = MT_GET_AND_ADD(zlib_compression_diff, 0);
        uint64_t zlib_bytes_total = MT_GET_AND_ADD(zlib_compression_bytes, 0);

        logger(0,
               "MemoryProfiler (zLib): %llu compressions, %llu decompressions, %llu compressed blocks in use, %llu "
               "bytes diff, %llu bytes total compressed",
               (long long unsigned int)zlib_compression_count,
               (long long unsigned int)zlib_decompression_count,
               (long long unsigned int)zlib_compression_count - (long long unsigned int)zlib_decompression_count,
               (long long unsigned int)zlib_bytes_diff,
               (long long unsigned int)zlib_bytes_total);
#endif
    }
}
#endif

static void ndpi_debug_printf(unsigned int proto,
                              struct ndpi_detection_module_struct * ndpi_struct,
                              ndpi_log_level_t log_level,
                              const char * file_name,
                              const char * func_name,
                              unsigned int line_number,
                              const char * format,
                              ...)
{
    va_list vl;
    int written, is_log_err = 0;
    char buf[128];
    struct nDPId_workflow * const workflow = (struct nDPId_workflow *)ndpi_get_user_data(ndpi_struct);

    va_start(vl, format);
    if ((written = vsnprintf(buf, nDPIsrvd_ARRAY_LENGTH(buf), format, vl)) >= (int)nDPIsrvd_ARRAY_LENGTH(buf))
    {
        logger(1,
               "[libnDPI] Logging failure due to buffer size; current: %zu, required: %d",
               nDPIsrvd_ARRAY_LENGTH(buf),
               written);
    }
    va_end(vl);

    switch (log_level)
    {
        case NDPI_LOG_ERROR:
            workflow->libnDPI_errors++;
            is_log_err = 1;
            break;
        case NDPI_LOG_TRACE:
            is_log_err = 1;
            break;
        case NDPI_LOG_DEBUG:
        case NDPI_LOG_DEBUG_EXTRA:
            is_log_err = 0;
            break;
    }

    logger(is_log_err,
           "[libnDPI@%s.%s.%u] protocol %u.%s: %s",
           file_name,
           func_name,
           line_number,
           proto,
           ndpi_get_proto_name(ndpi_struct, proto),
           buf);
}

static char const * cfg_err2str(ndpi_cfg_error err)
{
    switch (err)
    {
        case NDPI_CFG_INVALID_CONTEXT:
            return "Invalid context";
        case NDPI_CFG_NOT_FOUND:
            return "Not found";
        case NDPI_CFG_INVALID_PARAM:
            return "Invalid parameter";
        case NDPI_CFG_CONTEXT_ALREADY_INITIALIZED:
            return "Context already initialized";
        case NDPI_CFG_CALLBACK_ERROR:
            return "Callback error";
        case NDPI_CFG_OK:
            return "Success";
    }

    return "Unknown error";
}

static int cfg_set_u64(struct nDPId_workflow * const workflow,
                       char const * const proto,
                       char const * const param,
                       uint64_t const value)
{
    ndpi_cfg_error cfg_err;

    cfg_err = ndpi_set_config_u64(workflow->ndpi_struct, proto, param, value);
    if (cfg_err != NDPI_CFG_OK)
    {
        logger_early(1, "Could not set nDPI configuration (numeric value): %s", cfg_err2str(cfg_err));
        return 1;
    }

    return 0;
}

static int cfg_set(struct nDPId_workflow * const workflow, const char * proto, const char * param, const char * value)
{
    ndpi_cfg_error cfg_err;

    cfg_err = ndpi_set_config(workflow->ndpi_struct, proto, param, value);
    if (cfg_err != NDPI_CFG_OK)
    {
        if (proto != NULL)
        {
            logger_early(1,
                         "Could not set nDPI configuration for protocol `%s' with key `%s' and value `%s': %s",
                         proto,
                         param,
                         value,
                         cfg_err2str(cfg_err));
        }
        else
        {
            logger_early(1,
                         "Could not set nDPI configuration for key `%s' with value `%s': %s",
                         param,
                         value,
                         cfg_err2str(cfg_err));
        }
        return 1;
    }

    return 0;
}

static int libnDPI_parsed_config_line(
    int lineno, char const * const section, char const * const name, char const * const value, void * const user_data)
{
    struct nDPId_workflow * const workflow = (struct nDPId_workflow *)user_data;

    if ((strnlen(section, INI_MAX_SECTION) == nDPIsrvd_STRLEN_SZ("general") &&
         strncmp(section, "general", INI_MAX_SECTION) == 0) ||
        (strnlen(section, INI_MAX_SECTION) == nDPIsrvd_STRLEN_SZ("tuning") &&
         strncmp(section, "tuning", INI_MAX_SECTION) == 0))
    {
        // Nothing to do here right now (already initialized)
        return 1;
    }
    else if (strnlen(section, INI_MAX_SECTION) == nDPIsrvd_STRLEN_SZ("ndpi") &&
             strncmp(section, "ndpi", INI_MAX_SECTION) == 0)
    {
        return (cfg_set(workflow, NULL, name, value) == 0);
    }
    else if (strnlen(section, INI_MAX_SECTION) == nDPIsrvd_STRLEN_SZ("protos") &&
             strncmp(section, "protos", INI_MAX_SECTION) == 0)
    {
        char const * const first_sep = strchr(name, '.');
        char proto[INI_MAX_NAME];

        if (first_sep == NULL)
        {
            logger_early(1,
                         "Missing first `.' for section `protos' at line %d with key `%s' and value `%s'",
                         lineno,
                         name,
                         value);
            return 0;
        }
        int s_ret = snprintf(proto, sizeof(proto), "%.*s", (int)(first_sep - name), name);
        if (s_ret < 0)
        {
            logger_early(1,
                         "Could not format protocol at line %d with key `%s' and value `%s': snprintf returnded %d, "
                         "buffer size %zu",
                         lineno,
                         name,
                         value,
                         s_ret,
                         sizeof(proto));
            return 0;
        }

        return (cfg_set(workflow, proto, first_sep + 1, value) == 0);
    }
    else
    {
        logger_early(
            1, "Invalid config section `%s' at line %d with key `%s' and value `%s'", section, lineno, name, value);
    }

    return 1;
}

static struct nDPId_workflow * init_workflow(char const * const file_or_device)
{
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    struct nDPId_workflow * workflow;

#ifdef ENABLE_MEMORY_STATUS
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

    MT_INIT2(workflow->error_or_eof, 0);

#ifdef ENABLE_PFRING
    if (GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0)
    {
        errno = 0;

        if (npfring_init(file_or_device, PFRING_BUFFER_SIZE, &workflow->npf) != 0)
        {
            logger_early(1, "PF_RING open device %s failed: %s", file_or_device, strerror(errno));
            free_workflow(&workflow);
            return NULL;
        }

        if (IS_CMDARG_SET(nDPId_options.bpf_str) != 0)
        {
            if (npfring_set_bpf(&workflow->npf, GET_CMDARG_STR(nDPId_options.bpf_str)) != 0)
            {
                logger_early(1, "%s", "PF_RING set bpf filter failed");
                free_workflow(&workflow);
                return NULL;
            }
        }
    }
    else
#endif
    {
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
            logger_early(1,
                         (workflow->is_pcap_file == 0 ? "pcap_open_live: %.*s"
                                                      : "pcap_open_offline_with_tstamp_precision: %.*s"),
                         (int)PCAP_ERRBUF_SIZE,
                         pcap_error_buffer);
            free_workflow(&workflow);
            return NULL;
        }

        if (workflow->is_pcap_file == 0 && pcap_setnonblock(workflow->pcap_handle, 1, pcap_error_buffer) == PCAP_ERROR)
        {
            logger_early(1, "pcap_setnonblock: %.*s", (int)PCAP_ERRBUF_SIZE, pcap_error_buffer);
            free_workflow(&workflow);
            return NULL;
        }

        if (IS_CMDARG_SET(nDPId_options.bpf_str) != 0)
        {
            struct bpf_program fp;
            if (pcap_compile(
                    workflow->pcap_handle, &fp, GET_CMDARG_STR(nDPId_options.bpf_str), 1, PCAP_NETMASK_UNKNOWN) != 0)
            {
                logger_early(1, "pcap_compile: %s", pcap_geterr(workflow->pcap_handle));
                free_workflow(&workflow);
                return NULL;
            }
            if (pcap_setfilter(workflow->pcap_handle, &fp) != 0)
            {
                logger_early(1, "pcap_setfilter: %s", pcap_geterr(workflow->pcap_handle));
                free_workflow(&workflow);
                pcap_freecode(&fp);
                return NULL;
            }
            pcap_freecode(&fp);
        }
    }

#ifdef ENABLE_PFRING
    if (GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0)
    {
        if (npfring_enable(&workflow->npf) != 0)
        {
            logger_early(1, "%s", "Could not enable PF_RING");
            free_workflow(&workflow);
            return NULL;
        }
    }
#endif

    workflow->ndpi_struct = ndpi_init_detection_module(NULL);
    if (workflow->ndpi_struct == NULL)
    {
        logger_early(1, "%s", "BUG: Could not init ndpi detection module");
        free_workflow(&workflow);
        return NULL;
    }

    ndpi_set_user_data(workflow->ndpi_struct, workflow);
    set_ndpi_debug_function(workflow->ndpi_struct, ndpi_debug_printf);

    {
        int ret;

        if (IS_CMDARG_SET(nDPId_options.config_file) != 0 &&
            (ret =
                 parse_config_file(GET_CMDARG_STR(nDPId_options.config_file), libnDPI_parsed_config_line, workflow)) !=
                0)
        {
            if (ret > 0)
            {
                logger_early(1, "Config file `%s' is malformed", GET_CMDARG_STR(nDPId_options.config_file));
            }
            else if (ret == -ENOENT)
            {
                logger_early(1, "Path `%s' is not a regular file", GET_CMDARG_STR(nDPId_options.config_file));
            }
            else
            {
                logger_early(1,
                             "Could not open file `%s' for reading: %s",
                             GET_CMDARG_STR(nDPId_options.config_file),
                             strerror(errno));
            }
            free_workflow(&workflow);
            return NULL;
        }
    }

    cfg_set_u64(workflow, NULL, "log.level", 3);
    cfg_set_u64(workflow,
                NULL,
                "packets_limit_per_flow",
                GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_process));
    cfg_set_u64(workflow, "tls", "application_blocks_tracking", 1);
    cfg_set_u64(workflow, "tls", "certificate_expiration_threshold", 5);

    workflow->total_skipped_flows = 0;
    workflow->total_active_flows = 0;
    workflow->max_active_flows = GET_CMDARG_ULL(nDPId_options.max_flows_per_thread);
    workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
    if (workflow->ndpi_flows_active == NULL)
    {
        logger_early(1,
                     "Could not allocate %llu bytes for (active) flow tracking",
                     workflow->max_active_flows * sizeof(void *));
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_idle_flows = 0;
    workflow->max_idle_flows = GET_CMDARG_ULL(nDPId_options.max_idle_flows_per_thread);
    workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
    if (workflow->ndpi_flows_idle == NULL)
    {
        logger_early(1,
                     "Could not allocate %llu bytes for (idle) flow tracking",
                     workflow->max_idle_flows * sizeof(void *));
        free_workflow(&workflow);
        return NULL;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
    if (IS_CMDARG_SET(nDPId_options.custom_protocols_file) != 0)
    {
        ndpi_load_protocols_file(workflow->ndpi_struct, GET_CMDARG_STR(nDPId_options.custom_protocols_file));
    }
    if (IS_CMDARG_SET(nDPId_options.custom_categories_file) != 0)
    {
        ndpi_load_categories_file(workflow->ndpi_struct, GET_CMDARG_STR(nDPId_options.custom_categories_file), NULL);
    }
    if (IS_CMDARG_SET(nDPId_options.custom_ja3_file) != 0)
    {
        ndpi_load_malicious_ja3_file(workflow->ndpi_struct, GET_CMDARG_STR(nDPId_options.custom_ja3_file));
    }
    if (IS_CMDARG_SET(nDPId_options.custom_sha1_file) != 0)
    {
        ndpi_load_malicious_sha1_file(workflow->ndpi_struct, GET_CMDARG_STR(nDPId_options.custom_sha1_file));
    }
    ndpi_finalize_initialization(workflow->ndpi_struct);

    if (ndpi_init_serializer_ll(&workflow->ndpi_serializer, ndpi_serialization_format_json, NETWORK_BUFFER_MAX_SIZE) !=
        0)
    {
        logger_early(1, "BUG: Could not init JSON serializer with buffer size: %u bytes", NETWORK_BUFFER_MAX_SIZE);
        free_workflow(&workflow);
        return NULL;
    }

    return workflow;
}

static void free_analysis_data(struct nDPId_flow_extended * const flow_ext)
{
    if (GET_CMDARG_BOOLEAN(nDPId_options.enable_data_analysis) != 0 && flow_ext->flow_analysis != NULL)
    {
        ndpi_free_data_analysis(&flow_ext->flow_analysis->iat, 0);
        ndpi_free_data_analysis(&flow_ext->flow_analysis->pktlen, 0);
        ndpi_free(flow_ext->flow_analysis->directions);
        ndpi_free_bin(&flow_ext->flow_analysis->payload_len_bin[FD_SRC2DST]);
        ndpi_free_bin(&flow_ext->flow_analysis->payload_len_bin[FD_DST2SRC]);
        ndpi_free(flow_ext->flow_analysis->entropies);
        ndpi_free(flow_ext->flow_analysis);
        flow_ext->flow_analysis = NULL;
    }
}

static void free_detection_data(struct nDPId_flow * const flow)
{
    if (flow->info.detection_data != NULL)
    {
        ndpi_free_flow_data(&flow->info.detection_data->flow);
        ndpi_free(flow->info.detection_data);
        flow->info.detection_data = NULL;
    }
}

static int alloc_detection_data(struct nDPId_flow * const flow)
{
    flow->info.detection_data = (struct nDPId_detection_data *)ndpi_flow_malloc(sizeof(*flow->info.detection_data));

    if (flow->info.detection_data == NULL)
    {
        goto error;
    }

    memset(flow->info.detection_data, 0, sizeof(*flow->info.detection_data));

    if (GET_CMDARG_BOOLEAN(nDPId_options.enable_data_analysis) != 0)
    {
        flow->flow_extended.flow_analysis =
            (struct nDPId_flow_analysis *)ndpi_malloc(sizeof(*flow->flow_extended.flow_analysis));
        if (flow->flow_extended.flow_analysis == NULL)
        {
            goto error;
        }

        ndpi_init_data_analysis(&flow->flow_extended.flow_analysis->iat,
                                GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse) -
                                    1 /* first packet IAT is always 0 */);
        ndpi_init_data_analysis(&flow->flow_extended.flow_analysis->pktlen,
                                GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse));
        flow->flow_extended.flow_analysis->directions =
            (uint8_t *)ndpi_malloc(sizeof(*flow->flow_extended.flow_analysis->directions) *
                                   GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse));
        flow->flow_extended.flow_analysis->entropies =
            (float *)ndpi_malloc(sizeof(*flow->flow_extended.flow_analysis->entropies) *
                                 GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse));

        if (ndpi_init_bin(&flow->flow_extended.flow_analysis->payload_len_bin[FD_SRC2DST],
                          ndpi_bin_family8,
                          nDPId_ANALYZE_PLEN_NUM_BINS) != 0 ||
            ndpi_init_bin(&flow->flow_extended.flow_analysis->payload_len_bin[FD_DST2SRC],
                          ndpi_bin_family8,
                          nDPId_ANALYZE_PLEN_NUM_BINS) != 0 ||
            flow->flow_extended.flow_analysis->iat.values == NULL ||
            flow->flow_extended.flow_analysis->pktlen.values == NULL ||
            flow->flow_extended.flow_analysis->directions == NULL ||
            flow->flow_extended.flow_analysis->entropies == NULL)
        {
            goto error;
        }
    }

    return 0;
error:
    free_detection_data(flow);
    flow->info.detection_completed = 1;
    return 1;
}

static void ndpi_flow_info_free(void * const node)
{
    struct nDPId_flow_basic * const flow_basic = (struct nDPId_flow_basic *)node;

    switch (flow_basic->state)
    {
        case FS_UNKNOWN:
        case FS_COUNT:

        case FS_SKIPPED:
            break;

        case FS_FINISHED:
        {
            struct nDPId_flow * const flow = (struct nDPId_flow *)flow_basic;
            free(flow->finished.hostname);
            free_analysis_data(&flow->flow_extended);
            break;
        }

        case FS_INFO:
        {
            struct nDPId_flow * const flow = (struct nDPId_flow *)flow_basic;
            free_analysis_data(&flow->flow_extended);
            free_detection_data(flow);
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

#ifdef ENABLE_PFRING
    if (GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0)
    {
        npfring_close(&w->npf);
    }
#endif

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
        if (w->ndpi_flows_active != NULL)
        {
            ndpi_tdestroy(w->ndpi_flows_active[i], ndpi_flow_info_free);
        }
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

    if (GET_CMDARG_ULL(nDPId_options.reader_thread_count) > nDPId_MAX_READER_THREADS)
    {
        return 1;
    }

    if (IS_CMDARG_SET(nDPId_options.pcap_file_or_interface) == 0)
    {
        char * const pcapdev = get_default_pcapdev(pcap_error_buffer);
        set_cmdarg_string(&nDPId_options.pcap_file_or_interface, pcapdev);
        free(pcapdev);
        if (IS_CMDARG_SET(nDPId_options.pcap_file_or_interface) == 0)
        {
            logger_early(1, "pcap_lookupdev: %.*s", (int)PCAP_ERRBUF_SIZE, pcap_error_buffer);
            return 1;
        }
        logger_early(0,
                     "Capturing packets from default device: %s",
                     GET_CMDARG_STR(nDPId_options.pcap_file_or_interface));
    }

    errno = 0;
    if (access(GET_CMDARG_STR(nDPId_options.pcap_file_or_interface), R_OK) != 0 && errno == ENOENT)
    {
        errno = 0;
        if (get_ip_netmask_from_pcap_dev(GET_CMDARG_STR(nDPId_options.pcap_file_or_interface)) != 0)
        {
            if (errno != 0)
            {
                logger_early(1,
                             "Could not get netmask for pcap device %s: %s",
                             GET_CMDARG_STR(nDPId_options.pcap_file_or_interface),
                             strerror(errno));
            }
            else
            {
                logger_early(1,
                             "Unexpected error while retrieving netmask for pcap device %s",
                             GET_CMDARG_STR(nDPId_options.pcap_file_or_interface));
            }
            return 1;
        }
    }

    for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.reader_thread_count); ++i)
    {
        reader_threads[i].workflow = init_workflow(GET_CMDARG_STR(nDPId_options.pcap_file_or_interface));
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
            return GET_CMDARG_ULL(nDPId_options.icmp_max_idle_time);
        case IPPROTO_TCP:
            return GET_CMDARG_ULL(nDPId_options.tcp_max_idle_time);
        case IPPROTO_UDP:
            return GET_CMDARG_ULL(nDPId_options.udp_max_idle_time);
        default:
            return GET_CMDARG_ULL(nDPId_options.generic_max_idle_time);
    }
}

static uint64_t get_l4_protocol_idle_time_external(uint8_t l4_protocol)
{
    uint64_t idle_time = get_l4_protocol_idle_time(l4_protocol);

    idle_time += GET_CMDARG_ULL(nDPId_options.flow_scan_interval) * 2;
    if (l4_protocol == IPPROTO_TCP)
    {
        idle_time += GET_CMDARG_ULL(nDPId_options.tcp_max_post_end_flow_time);
    }

    return idle_time;
}

static int is_l4_protocol_timed_out(struct nDPId_workflow const * const workflow,
                                    struct nDPId_flow_basic const * const flow_basic)
{
    uint64_t itime = get_l4_protocol_idle_time(flow_basic->l4_protocol);

    return flow_basic->tcp_fin_rst_seen == 1 || get_last_pkt_time(flow_basic) + itime <= workflow->last_thread_time;
}

static int is_tcp_post_end(struct nDPId_workflow const * const workflow,
                           struct nDPId_flow_basic const * const flow_basic)
{
    return flow_basic->l4_protocol != IPPROTO_TCP || flow_basic->tcp_fin_rst_seen == 0 ||
           (flow_basic->tcp_fin_rst_seen == 1 &&
            get_last_pkt_time(flow_basic) + GET_CMDARG_ULL(nDPId_options.tcp_max_post_end_flow_time) <=
                workflow->last_thread_time);
}

static int is_flow_update_required(struct nDPId_workflow const * const workflow,
                                   struct nDPId_flow_extended const * const flow_ext)
{
    uint64_t itime = get_l4_protocol_idle_time(flow_ext->flow_basic.l4_protocol);

    if (flow_ext->flow_basic.l4_protocol != IPPROTO_TCP)
    {
        return flow_ext->last_flow_update + itime / 4 <= workflow->last_thread_time;
    }
    return flow_ext->last_flow_update + itime <= workflow->last_thread_time;
}

static int is_error_event_threshold(struct nDPId_workflow * const workflow)
{
    if (workflow->last_global_time - workflow->last_error_time >
        GET_CMDARG_ULL(nDPId_options.error_event_threshold_time))
    {
        workflow->error_count = 0;
    }

    workflow->last_error_time = workflow->last_global_time;
    if (workflow->error_count >= GET_CMDARG_ULL(nDPId_options.error_event_threshold_n))
    {
        return 1;
    }

    workflow->error_count++;
    return 0;
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

    if (workflow->cur_idle_flows == GET_CMDARG_ULL(nDPId_options.max_idle_flows_per_thread))
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        if (is_l4_protocol_timed_out(workflow, flow_basic) != 0)
        {
            if (is_tcp_post_end(workflow, flow_basic) != 0)
            {
                workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow_basic;
                switch (flow_basic->state)
                {
                    case FS_UNKNOWN:
                    case FS_COUNT:

                    case FS_SKIPPED:
                        break;

                    case FS_FINISHED:
                    case FS_INFO:
                        workflow->total_idle_flows++;
                        break;
                }
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

        switch (flow_basic->state)
        {
            case FS_UNKNOWN:
            case FS_COUNT:

            case FS_SKIPPED:
                break;

            case FS_FINISHED:
            {
                struct nDPId_flow * const flow = (struct nDPId_flow *)flow_basic;

                if (flow->flow_extended.flow_basic.tcp_fin_rst_seen != 0)
                {
                    jsonize_flow_event(reader_thread, &flow->flow_extended, FLOW_EVENT_END);
                }
                else
                {
                    jsonize_flow_event(reader_thread, &flow->flow_extended, FLOW_EVENT_IDLE);
                }
                break;
            }

            case FS_INFO:
            {
                struct nDPId_flow * const flow = (struct nDPId_flow *)flow_basic;

#ifdef ENABLE_ZLIB
                if (GET_CMDARG_BOOLEAN(nDPId_options.enable_zlib_compression) != 0 &&
                    flow->info.detection_data_compressed_size > 0)
                {
                    workflow->current_compression_diff -= flow->info.detection_data_compressed_size;
                    int ret = detection_data_inflate(flow);
                    if (ret <= 0)
                    {
                        workflow->current_compression_diff += flow->info.detection_data_compressed_size;
                        logger(1, "zLib decompression failed with error code: %d", ret);
                        return;
                    }
                }
#endif

                if (flow->info.detection_completed == 0)
                {
                    uint8_t protocol_was_guessed = 0;

                    if (ndpi_is_protocol_detected(flow->info.detection_data->guessed_l7_protocol) == 0)
                    {
                        flow->info.detection_data->guessed_l7_protocol =
                            ndpi_detection_giveup(workflow->ndpi_struct,
                                                  &flow->info.detection_data->flow,
                                                  &protocol_was_guessed);
                    }
                    else
                    {
                        protocol_was_guessed = 1;
                    }

                    if (protocol_was_guessed != 0)
                    {
                        workflow->total_guessed_flows++;
                        jsonize_flow_detection_event(reader_thread, flow, FLOW_EVENT_GUESSED);
                    }
                    else
                    {
                        workflow->total_not_detected_flows++;
                        jsonize_flow_detection_event(reader_thread, flow, FLOW_EVENT_NOT_DETECTED);
                    }
                }
                if (flow->flow_extended.flow_basic.tcp_fin_rst_seen != 0)
                {
                    jsonize_flow_event(reader_thread, &flow->flow_extended, FLOW_EVENT_END);
                }
                else
                {
                    jsonize_flow_event(reader_thread, &flow->flow_extended, FLOW_EVENT_IDLE);
                }
                break;
            }
        }

        ndpi_tdelete(flow_basic, &workflow->ndpi_flows_active[idle_scan_index], ndpi_workflow_node_cmp);
        ndpi_flow_info_free(flow_basic);
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
        switch (flow_basic->state)
        {
            case FS_UNKNOWN:
            case FS_COUNT:

            case FS_SKIPPED:
                break;

            case FS_FINISHED:
            case FS_INFO:
            {
                struct nDPId_flow_extended * const flow_ext = (struct nDPId_flow_extended *)flow_basic;

                if (is_flow_update_required(workflow, flow_ext) != 0)
                {
                    workflow->total_flow_updates++;
                    jsonize_flow_event(reader_thread, flow_ext, FLOW_EVENT_UPDATE);
                    flow_ext->last_flow_update = workflow->last_thread_time;
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
                logger(1, "Could not convert IPv4 source ip to string: %s", strerror(errno));
            }
            if (inet_ntop(AF_INET, &flow_basic->dst.v4.ip, dst_name, sizeof(dst_name)) == NULL)
            {
                logger(1, "Could not convert IPv4 destination ip to string: %s", strerror(errno));
            }
            break;
        case L3_IP6:
            ndpi_serialize_string_string(serializer, "l3_proto", "ip6");
            if (inet_ntop(AF_INET6, &flow_basic->src.v6.ip[0], src_name, sizeof(src_name)) == NULL)
            {
                logger(1, "Could not convert IPv6 source ip to string: %s", strerror(errno));
            }
            if (inet_ntop(AF_INET6, &flow_basic->dst.v6.ip[0], dst_name, sizeof(dst_name)) == NULL)
            {
                logger(1, "Could not convert IPv6 destination ip to string: %s", strerror(errno));
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

static void jsonize_basic(struct nDPId_reader_thread * const reader_thread, int serialize_thread_id)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    if (serialize_thread_id != 0)
    {
        ndpi_serialize_string_int32(&workflow->ndpi_serializer, "thread_id", reader_thread->array_index);
    }
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "packet_id", workflow->packets_captured);
    ndpi_serialize_string_string(&workflow->ndpi_serializer,
                                 "source",
                                 GET_CMDARG_STR(nDPId_options.pcap_file_or_interface));
    ndpi_serialize_string_string(&workflow->ndpi_serializer, "alias", GET_CMDARG_STR(nDPId_options.instance_alias));
}

static void jsonize_daemon(struct nDPId_reader_thread * const reader_thread, enum daemon_event event)
{
    char const ev[] = "daemon_event_name";
    struct nDPId_workflow * const workflow = reader_thread->workflow;

    if (event == DAEMON_EVENT_RECONNECT)
    {
        ndpi_reset_serializer(&reader_thread->workflow->ndpi_serializer);
    }

    ndpi_serialize_string_int32(&workflow->ndpi_serializer, "daemon_event_id", event);
    if (event > DAEMON_EVENT_INVALID && event < DAEMON_EVENT_COUNT)
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, daemon_event_name_table[event]);
    }
    else
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, daemon_event_name_table[DAEMON_EVENT_INVALID]);
    }

    jsonize_basic(reader_thread, 1);
#ifndef PKG_VERSION
    ndpi_serialize_string_string(&workflow->ndpi_serializer, "version", "unknown");
#else
    ndpi_serialize_string_string(&workflow->ndpi_serializer, "version", PKG_VERSION);
#endif
    ndpi_serialize_string_string(&workflow->ndpi_serializer, "ndpi_version", ndpi_revision());

    switch (event)
    {
        case DAEMON_EVENT_INVALID:
        case DAEMON_EVENT_COUNT:
            break;

        case DAEMON_EVENT_INIT:
        case DAEMON_EVENT_RECONNECT:
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "max-flows-per-thread",
                                         GET_CMDARG_ULL(nDPId_options.max_flows_per_thread));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "max-idle-flows-per-thread",
                                         GET_CMDARG_ULL(nDPId_options.max_idle_flows_per_thread));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "reader-thread-count",
                                         GET_CMDARG_ULL(nDPId_options.reader_thread_count));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "flow-scan-interval",
                                         GET_CMDARG_ULL(nDPId_options.flow_scan_interval));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "generic-max-idle-time",
                                         GET_CMDARG_ULL(nDPId_options.generic_max_idle_time));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "icmp-max-idle-time",
                                         GET_CMDARG_ULL(nDPId_options.icmp_max_idle_time));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "udp-max-idle-time",
                                         GET_CMDARG_ULL(nDPId_options.udp_max_idle_time));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "tcp-max-idle-time",
                                         GET_CMDARG_ULL(nDPId_options.tcp_max_idle_time) +
                                             GET_CMDARG_ULL(nDPId_options.tcp_max_post_end_flow_time));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "max-packets-per-flow-to-send",
                                         GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_send));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "max-packets-per-flow-to-process",
                                         GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_process));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "max-packets-per-flow-to-analyse",
                                         GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse));
            break;

        case DAEMON_EVENT_STATUS:
        case DAEMON_EVENT_SHUTDOWN:
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "packets-captured", workflow->packets_captured);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "packets-processed", workflow->packets_processed);
#ifdef ENABLE_PFRING
            {
                int rc;
                struct npfring_stats stats = {};

                if (GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0)
                {
                    if ((rc = npfring_stats(&workflow->npf, &stats)) != 0)
                    {
                        logger(1, "[%8llu] PF_RING stats returned: %d", reader_thread->workflow->packets_processed, rc);
                    }
                    ndpi_serialize_string_boolean(&workflow->ndpi_serializer, "pfring_active", 0);
                    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pfring_recv", 0);
                    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pfring_drop", 0);
                    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pfring_shunt", 0);
                }
                else
                {
                    ndpi_serialize_string_boolean(&workflow->ndpi_serializer,
                                                  "pfring_active",
                                                  GET_CMDARG_BOOLEAN(nDPId_options.use_pfring));
                    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pfring_recv", stats.recv);
                    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pfring_drop", stats.drop);
                    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pfring_shunt", stats.shunt);
                }
            }
#else
            ndpi_serialize_string_boolean(&workflow->ndpi_serializer, "pfring_active", 0);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pfring_recv", 0);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pfring_drop", 0);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "pfring_shunt", 0);
#endif
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-skipped-flows",
                                         workflow->total_skipped_flows);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-l4-payload-len",
                                         workflow->total_l4_payload_len);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-not-detected-flows",
                                         workflow->total_not_detected_flows);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-guessed-flows",
                                         workflow->total_guessed_flows);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-detected-flows",
                                         workflow->total_detected_flows);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-detection-updates",
                                         workflow->total_flow_detection_updates);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "total-updates", workflow->total_flow_updates);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "current-active-flows",
                                         workflow->cur_active_flows);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-active-flows",
                                         workflow->total_active_flows);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "total-idle-flows", workflow->total_idle_flows);
#if defined(ENABLE_ZLIB) && !defined(NO_MAIN)
            /* Compression diff's may very from run to run. Due to this, `nDPId-test' would be inconsistent. */
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-compressions",
                                         workflow->total_compressions);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-compression-diff",
                                         workflow->total_compression_diff);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "current-compression-diff",
                                         workflow->current_compression_diff);
#else
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "total-compressions", 0);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "total-compression-diff", 0);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "current-compression-diff", 0);
#endif
#if defined(ENABLE_MEMORY_STATUS) && !defined(NO_MAIN)
            /*
             * Global memory stats may very from run to run.
             * Due to this, `nDPId-test' results would be inconsistent and is disabled if NO_MAIN defined.
             */
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "global-alloc-count",
                                         MT_GET_AND_ADD(ndpi_memory_alloc_count, 0));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "global-free-count",
                                         MT_GET_AND_ADD(ndpi_memory_free_count, 0));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "global-alloc-bytes",
                                         MT_GET_AND_ADD(ndpi_memory_alloc_bytes, 0));
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "global-free-bytes",
                                         MT_GET_AND_ADD(ndpi_memory_free_bytes, 0));
#else
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "global-alloc-count", 0);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "global-free-count", 0);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "global-alloc-bytes", 0);
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "global-free-bytes", 0);
#endif
            ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                         "total-events-serialized",
                                         workflow->total_events_serialized +
                                             1 /* DAEMON_EVENT_SHUTDOWN is an event as well */);
            break;
    }
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "global_ts_usec", workflow->last_global_time);
    serialize_and_send(reader_thread);
}

static void jsonize_flow(struct nDPId_workflow * const workflow, struct nDPId_flow_extended const * const flow_ext)
{
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_id", flow_ext->flow_id);
    ndpi_serialize_string_string(&workflow->ndpi_serializer,
                                 "flow_state",
                                 flow_state_name_table[flow_ext->flow_basic.state]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_src_packets_processed",
                                 flow_ext->packets_processed[FD_SRC2DST]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_dst_packets_processed",
                                 flow_ext->packets_processed[FD_DST2SRC]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_first_seen", flow_ext->first_seen);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_src_last_pkt_time",
                                 flow_ext->flow_basic.last_pkt_time[FD_SRC2DST]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_dst_last_pkt_time",
                                 flow_ext->flow_basic.last_pkt_time[FD_DST2SRC]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_idle_time",
                                 get_l4_protocol_idle_time_external(flow_ext->flow_basic.l4_protocol));
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_src_min_l4_payload_len",
                                 flow_ext->min_l4_payload_len[FD_SRC2DST]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_dst_min_l4_payload_len",
                                 flow_ext->min_l4_payload_len[FD_DST2SRC]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_src_max_l4_payload_len",
                                 flow_ext->max_l4_payload_len[FD_SRC2DST]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_dst_max_l4_payload_len",
                                 flow_ext->max_l4_payload_len[FD_DST2SRC]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_src_tot_l4_payload_len",
                                 flow_ext->total_l4_payload_len[FD_SRC2DST]);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                 "flow_dst_tot_l4_payload_len",
                                 flow_ext->total_l4_payload_len[FD_DST2SRC]);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "midstream", flow_ext->flow_basic.tcp_is_midstream_flow);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "thread_ts_usec", workflow->last_thread_time);
}

static int connect_to_collector(struct nDPId_reader_thread * const reader_thread)
{
    if (reader_thread->collector_sockfd >= 0)
    {
        close(reader_thread->collector_sockfd);
    }

    int sock_type = (nDPId_options.parsed_collector_address.raw.sa_family == AF_UNIX ? SOCK_STREAM : SOCK_DGRAM);
    reader_thread->collector_sockfd = socket(nDPId_options.parsed_collector_address.raw.sa_family, sock_type, 0);
    if (reader_thread->collector_sockfd < 0 || set_fd_cloexec(reader_thread->collector_sockfd) < 0)
    {
        reader_thread->collector_sock_last_errno = errno;
        return 1;
    }

    int opt = NETWORK_BUFFER_MAX_SIZE;
    if (setsockopt(reader_thread->collector_sockfd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0)
    {
        return 1;
    }

    if (set_collector_nonblock(reader_thread) != 0)
    {
        return 1;
    }

    if (connect(reader_thread->collector_sockfd,
                &nDPId_options.parsed_collector_address.raw,
                nDPId_options.parsed_collector_address.size) < 0)
    {
        reader_thread->collector_sock_last_errno = errno;
        return 1;
    }

    if (shutdown(reader_thread->collector_sockfd, SHUT_RD) != 0)
    {
        reader_thread->collector_sock_last_errno = errno;
        return 1;
    }

    reader_thread->collector_sock_last_errno = 0;

    return 0;
}

static void send_to_collector(struct nDPId_reader_thread * const reader_thread,
                              char const * const json_msg,
                              size_t json_msg_len)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    int saved_errno;
    int s_ret;
    char newline_json_msg[NETWORK_BUFFER_MAX_SIZE];

    s_ret = snprintf(newline_json_msg,
                     sizeof(newline_json_msg),
                     "%0" NETWORK_BUFFER_LENGTH_DIGITS_STR "zu%.*s\n",
                     json_msg_len + 1,
                     (int)json_msg_len,
                     json_msg);

    if (s_ret < 0 || s_ret >= (int)sizeof(newline_json_msg))
    {
        logger(1,
               "[%8llu, %zu] JSON buffer prepare failed: snprintf returned %d, buffer size %zu",
               workflow->packets_captured,
               reader_thread->array_index,
               s_ret,
               sizeof(newline_json_msg));
        if (s_ret >= (int)sizeof(newline_json_msg))
        {
            logger(1,
                   "[%8llu, %zu] JSON message: %.*s...",
                   workflow->packets_captured,
                   reader_thread->array_index,
                   ndpi_min(512, NETWORK_BUFFER_MAX_SIZE),
                   newline_json_msg);
        }
        return;
    }

    if (reader_thread->collector_sock_last_errno != 0)
    {
        saved_errno = reader_thread->collector_sock_last_errno;

        if (connect_to_collector(reader_thread) == 0)
        {
            if (nDPId_options.parsed_collector_address.raw.sa_family == AF_UNIX)
            {
                logger(1,
                       "[%8llu, %zu] Reconnected to nDPIsrvd Collector at %s",
                       workflow->packets_captured,
                       reader_thread->array_index,
                       GET_CMDARG_STR(nDPId_options.collector_address));
                jsonize_daemon(reader_thread, DAEMON_EVENT_RECONNECT);
            }
        }
        else
        {
            if (saved_errno != reader_thread->collector_sock_last_errno)
            {
                logger(1,
                       "[%8llu, %zu] Could not connect to nDPIsrvd Collector at %s, will try again later. Error: %s",
                       workflow->packets_captured,
                       reader_thread->array_index,
                       GET_CMDARG_STR(nDPId_options.collector_address),
                       (reader_thread->collector_sock_last_errno != 0
                            ? strerror(reader_thread->collector_sock_last_errno)
                            : "Internal Error."));
            }
            return;
        }
    }

    errno = 0;
    ssize_t written;
    if (reader_thread->collector_sock_last_errno == 0 &&
        (written = write(reader_thread->collector_sockfd, newline_json_msg, s_ret)) != s_ret)
    {
        saved_errno = errno;
        if (saved_errno == EPIPE || written == 0)
        {
            logger(1,
                   "[%8llu, %zu] Lost connection to nDPIsrvd Collector",
                   workflow->packets_captured,
                   reader_thread->array_index);
        }
        if (saved_errno != EAGAIN)
        {
            if (saved_errno == ECONNREFUSED)
            {
                logger(1,
                       "[%8llu, %zu] %s to %s refused by endpoint",
                       workflow->packets_captured,
                       reader_thread->array_index,
                       (nDPId_options.parsed_collector_address.raw.sa_family == AF_UNIX ? "Connection" : "Datagram"),
                       GET_CMDARG_STR(nDPId_options.collector_address));
            }
            reader_thread->collector_sock_last_errno = saved_errno;
        }
        else if (nDPId_options.parsed_collector_address.raw.sa_family == AF_UNIX)
        {
            size_t pos = (written < 0 ? 0 : written);
            set_collector_block(reader_thread);
            while ((size_t)(written = write(reader_thread->collector_sockfd, newline_json_msg + pos, s_ret - pos)) !=
                   s_ret - pos)
            {
                saved_errno = errno;
                if (saved_errno == EPIPE || written == 0)
                {
                    logger(1,
                           "[%8llu, %zu] Lost connection to nDPIsrvd Collector",
                           workflow->packets_captured,
                           reader_thread->array_index);
                    reader_thread->collector_sock_last_errno = saved_errno;
                    break;
                }
                else if (written < 0)
                {
                    logger(1,
                           "[%8llu, %zu] Send data (blocking I/O) to nDPIsrvd Collector at %s failed: %s",
                           workflow->packets_captured,
                           reader_thread->array_index,
                           GET_CMDARG_STR(nDPId_options.collector_address),
                           strerror(saved_errno));
                    reader_thread->collector_sock_last_errno = saved_errno;
                    break;
                }
                else
                {
                    pos += written;
                }
            }
            set_collector_nonblock(reader_thread);
        }
    }
}

static void serialize_and_send(struct nDPId_reader_thread * const reader_thread)
{
    char * json_msg;
    uint32_t json_msg_len;

    json_msg = ndpi_serializer_get_buffer(&reader_thread->workflow->ndpi_serializer, &json_msg_len);
    if (json_msg == NULL || json_msg_len == 0)
    {
        logger(1,
               "[%8llu, %zu] jsonize failed, buffer length: %u",
               reader_thread->workflow->packets_captured,
               reader_thread->array_index,
               json_msg_len);
    }
    else
    {
        reader_thread->workflow->total_events_serialized++;
        send_to_collector(reader_thread, json_msg, json_msg_len);
    }
    ndpi_reset_serializer(&reader_thread->workflow->ndpi_serializer);
}

/* Slightly modified code from: https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64 */
static int base64_encode(uint8_t const * const data_buf,
                         size_t dataLength,
                         char * const result,
                         size_t * const resultSize)
{
    static const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
            n += ((uint32_t)data[x + 1]) << 8; // parenthesis needed, compiler depending on flags can do the shifting
                                               // before conversion to uint32_t, resulting to 0

        if ((x + 2) < dataLength)
            n += data[x + 2];

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
            return 1; /* indicate failure: buffer too small */
        result[resultIndex++] = base64chars[n0];
        if (resultIndex >= *resultSize)
            return 1; /* indicate failure: buffer too small */
        result[resultIndex++] = base64chars[n1];

        /*
         * if we have only two bytes available, then their encoding is
         * spread out over three chars
         */
        if ((x + 1) < dataLength)
        {
            if (resultIndex >= *resultSize)
                return 1; /* indicate failure: buffer too small */
            result[resultIndex++] = base64chars[n2];
        }

        /*
         * if we have all three bytes available, then their encoding is spread
         * out over four characters
         */
        if ((x + 2) < dataLength)
        {
            if (resultIndex >= *resultSize)
                return 1; /* indicate failure: buffer too small */
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
                return 1; /* indicate failure: buffer too small */
            result[resultIndex++] = '=';
        }
    }
    if (resultIndex >= *resultSize)
        return 1; /* indicate failure: buffer too small */
    result[resultIndex] = 0;
    *resultSize = resultIndex;
    return 0; /* indicate success */
}

static void jsonize_data_analysis(struct nDPId_reader_thread * const reader_thread,
                                  struct nDPId_flow_extended const * const flow_ext)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    struct nDPId_flow_analysis * const analysis = (struct nDPId_flow_analysis *)flow_ext->flow_analysis;

    if (GET_CMDARG_BOOLEAN(nDPId_options.enable_data_analysis) != 0 && flow_ext->flow_analysis != NULL)
    {
        ndpi_serialize_start_of_block(&workflow->ndpi_serializer, "data_analysis");
        ndpi_serialize_start_of_block(&workflow->ndpi_serializer, "iat");

        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "min", ndpi_data_min(&analysis->iat));
        ndpi_serialize_string_float(&workflow->ndpi_serializer, "avg", ndpi_data_average(&analysis->iat), "%.1f");
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "max", ndpi_data_max(&analysis->iat));
        ndpi_serialize_string_float(&workflow->ndpi_serializer, "stddev", ndpi_data_stddev(&analysis->iat), "%.1f");
        ndpi_serialize_string_float(&workflow->ndpi_serializer, "var", ndpi_data_variance(&analysis->iat), "%.1f");
        ndpi_serialize_string_float(&workflow->ndpi_serializer, "ent", ndpi_data_entropy(&analysis->iat), "%.1f");

        ndpi_serialize_start_of_list(&workflow->ndpi_serializer, "data");
        for (uint16_t i = 0; i < analysis->iat.num_values_array_len; ++i)
        {
            ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "", analysis->iat.values[i]);
        }
        ndpi_serialize_end_of_list(&workflow->ndpi_serializer);
        ndpi_serialize_end_of_block(&workflow->ndpi_serializer);

        ndpi_serialize_start_of_block(&workflow->ndpi_serializer, "pktlen");
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "min", ndpi_data_min(&analysis->pktlen));
        ndpi_serialize_string_float(&workflow->ndpi_serializer, "avg", ndpi_data_average(&analysis->pktlen), "%.1f");
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "max", ndpi_data_max(&analysis->pktlen));
        ndpi_serialize_string_float(&workflow->ndpi_serializer, "stddev", ndpi_data_stddev(&analysis->pktlen), "%.1f");
        ndpi_serialize_string_float(&workflow->ndpi_serializer, "var", ndpi_data_variance(&analysis->pktlen), "%.1f");
        ndpi_serialize_string_float(&workflow->ndpi_serializer, "ent", ndpi_data_entropy(&analysis->pktlen), "%.1f");

        ndpi_serialize_start_of_list(&workflow->ndpi_serializer, "data");
        for (uint16_t i = 0; i < ndpi_min(analysis->pktlen.num_data_entries, analysis->pktlen.num_values_array_len);
             ++i)
        {
            ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "", analysis->pktlen.values[i]);
        }
        ndpi_serialize_end_of_list(&workflow->ndpi_serializer);
        ndpi_serialize_end_of_block(&workflow->ndpi_serializer);

        ndpi_serialize_start_of_block(&workflow->ndpi_serializer, "bins");
        ndpi_serialize_start_of_list(&workflow->ndpi_serializer, "c_to_s");
        for (uint16_t i = 0; i < analysis->payload_len_bin[FD_SRC2DST].num_bins; ++i)
        {
            ndpi_serialize_string_uint32(&workflow->ndpi_serializer,
                                         "",
                                         analysis->payload_len_bin[FD_SRC2DST].u.bins8[i]);
        }
        ndpi_serialize_end_of_list(&workflow->ndpi_serializer);
        ndpi_serialize_start_of_list(&workflow->ndpi_serializer, "s_to_c");
        for (uint16_t i = 0; i < analysis->payload_len_bin[FD_DST2SRC].num_bins; ++i)
        {
            ndpi_serialize_string_uint32(&workflow->ndpi_serializer,
                                         "",
                                         analysis->payload_len_bin[FD_DST2SRC].u.bins8[i]);
        }
        ndpi_serialize_end_of_list(&workflow->ndpi_serializer);
        ndpi_serialize_end_of_block(&workflow->ndpi_serializer);

        ndpi_serialize_start_of_list(&workflow->ndpi_serializer, "directions");
        for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse); ++i)
        {
            ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "", analysis->directions[i]);
        }
        ndpi_serialize_end_of_list(&workflow->ndpi_serializer);

        ndpi_serialize_start_of_list(&workflow->ndpi_serializer, "entropies");
        for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse); ++i)
        {
            ndpi_serialize_string_float(&workflow->ndpi_serializer, "", analysis->entropies[i], "%.9f");
        }
        ndpi_serialize_end_of_list(&workflow->ndpi_serializer);

        ndpi_serialize_end_of_block(&workflow->ndpi_serializer);
    }
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
            logger(1,
                   "[%8llu, %zu] BUG: got a PACKET_EVENT_PAYLOAD_FLOW with a flow pointer equals NULL",
                   reader_thread->workflow->packets_captured,
                   reader_thread->array_index);
            return;
        }
        if (flow_ext->packets_processed[FD_SRC2DST] + flow_ext->packets_processed[FD_DST2SRC] >
            GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_send))
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

    jsonize_basic(reader_thread, (event == PACKET_EVENT_PAYLOAD_FLOW ? 1 : 0));

    if (event == PACKET_EVENT_PAYLOAD_FLOW)
    {
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "flow_id", flow_ext->flow_id);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "flow_packet_id",
                                     flow_ext->packets_processed[FD_SRC2DST] + flow_ext->packets_processed[FD_DST2SRC]);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "flow_src_last_pkt_time",
                                     flow_ext->flow_basic.last_pkt_time[FD_SRC2DST]);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "flow_dst_last_pkt_time",
                                     flow_ext->flow_basic.last_pkt_time[FD_DST2SRC]);
        ndpi_serialize_string_uint64(&workflow->ndpi_serializer,
                                     "flow_idle_time",
                                     get_l4_protocol_idle_time_external(flow_ext->flow_basic.l4_protocol));
    }

#ifdef ENABLE_PFRING
    if (GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0)
    {
        ndpi_serialize_string_int32(&workflow->ndpi_serializer,
                                    "pkt_datalink",
                                    npfring_datalink(&reader_thread->workflow->npf));
    }
    else
#endif
    {
        ndpi_serialize_string_int32(&workflow->ndpi_serializer,
                                    "pkt_datalink",
                                    pcap_datalink(reader_thread->workflow->pcap_handle));
    }
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_caplen", header->caplen);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_type", pkt_type);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_l3_offset", pkt_l3_offset);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_l4_offset", pkt_l4_offset);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_len", header->len);
    ndpi_serialize_string_uint32(&workflow->ndpi_serializer, "pkt_l4_len", pkt_l4_len);
    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "thread_ts_usec", workflow->last_thread_time);

    char base64_data[nDPId_PACKETS_PLEN_MAX * 4];
    size_t base64_data_len = sizeof(base64_data);
    if (base64_encode(packet,
                      (header->caplen > nDPId_PACKETS_PLEN_MAX ? nDPId_PACKETS_PLEN_MAX : header->caplen),
                      base64_data,
                      &base64_data_len) != 0)
    {
        logger(1,
               "[%8llu, %zu] Base64 encoding failed.",
               reader_thread->workflow->packets_captured,
               reader_thread->array_index);
    }
    else if (base64_data_len > 0 &&
             ndpi_serialize_string_binary(&workflow->ndpi_serializer, "pkt", base64_data, (uint16_t)base64_data_len) !=
                 0)
    {
        logger(1,
               "[%8llu, %zu] JSON serializing base64 packet buffer failed",
               reader_thread->workflow->packets_captured,
               reader_thread->array_index);
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
    jsonize_basic(reader_thread, 1);
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
        case FLOW_EVENT_ANALYSE:
#ifdef ENABLE_PFRING
            if (GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0)
            {
                ndpi_serialize_string_int32(&workflow->ndpi_serializer,
                                            "flow_datalink",
                                            npfring_datalink(&reader_thread->workflow->npf));
            }
            else
#endif
            {
                ndpi_serialize_string_int32(&workflow->ndpi_serializer,
                                            "flow_datalink",
                                            pcap_datalink(reader_thread->workflow->pcap_handle));
            }
            ndpi_serialize_string_uint32(&workflow->ndpi_serializer,
                                         "flow_max_packets",
                                         GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_send));

            if (event == FLOW_EVENT_ANALYSE)
            {
                jsonize_data_analysis(reader_thread, flow_ext);
            }
            if (flow_ext->flow_basic.state == FS_FINISHED)
            {
                struct nDPId_flow const * const flow = (struct nDPId_flow *)flow_ext;

                ndpi_serialize_start_of_block(&workflow->ndpi_serializer, "ndpi");
                ndpi_serialize_proto(workflow->ndpi_struct,
                                     &workflow->ndpi_serializer,
                                     flow->finished.risk,
                                     flow->finished.confidence,
                                     flow->flow_extended.detected_l7_protocol);
                if (flow->finished.hostname != NULL)
                {
                    ndpi_serialize_string_string(&workflow->ndpi_serializer, "hostname", flow->finished.hostname);
                }
                ndpi_serialize_end_of_block(&workflow->ndpi_serializer);
            }
            else if (flow_ext->flow_basic.state == FS_INFO)
            {
                struct nDPId_flow * const flow = (struct nDPId_flow *)flow_ext;

#ifdef ENABLE_ZLIB
                if (GET_CMDARG_BOOLEAN(nDPId_options.enable_zlib_compression) != 0 &&
                    flow->info.detection_data_compressed_size > 0)
                {
                    workflow->current_compression_diff -= flow->info.detection_data_compressed_size;
                    int ret = detection_data_inflate(flow);
                    if (ret <= 0)
                    {
                        workflow->current_compression_diff += flow->info.detection_data_compressed_size;
                        logger(1, "zLib decompression failed with error code: %d", ret);
                        return;
                    }
                }
#endif

                if (flow->info.detection_completed != 0)
                {
                    ndpi_serialize_start_of_block(&workflow->ndpi_serializer, "ndpi");
                    ndpi_serialize_proto(workflow->ndpi_struct,
                                         &workflow->ndpi_serializer,
                                         flow->info.detection_data->flow.risk,
                                         flow->info.detection_data->flow.confidence,
                                         flow->flow_extended.detected_l7_protocol);
                    ndpi_serialize_end_of_block(&workflow->ndpi_serializer);
                }
            }
            break;

        case FLOW_EVENT_NOT_DETECTED:
        case FLOW_EVENT_GUESSED:
        case FLOW_EVENT_DETECTED:
        case FLOW_EVENT_DETECTION_UPDATE:
            logger(1,
                   "[%8llu, %4llu] internal error / invalid function call",
                   workflow->packets_captured,
                   flow_ext->flow_id);
            break;
    }

    serialize_and_send(reader_thread);
}

static void jsonize_flow_detection_event(struct nDPId_reader_thread * const reader_thread,
                                         struct nDPId_flow * const flow,
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
    jsonize_basic(reader_thread, 1);
    jsonize_flow(workflow, &flow->flow_extended);
    jsonize_l3_l4(workflow, &flow->flow_extended.flow_basic);

    switch (event)
    {
        case FLOW_EVENT_INVALID:
        case FLOW_EVENT_COUNT:
            break;

        case FLOW_EVENT_NEW:
        case FLOW_EVENT_END:
        case FLOW_EVENT_IDLE:
        case FLOW_EVENT_UPDATE:
        case FLOW_EVENT_ANALYSE:
            logger(1,
                   "[%8llu, %4llu] internal error / invalid function call",
                   workflow->packets_captured,
                   flow->flow_extended.flow_id);
            break;

        case FLOW_EVENT_NOT_DETECTED:
        case FLOW_EVENT_GUESSED:
            if (ndpi_dpi2json(workflow->ndpi_struct,
                              &flow->info.detection_data->flow,
                              flow->info.detection_data->guessed_l7_protocol,
                              &workflow->ndpi_serializer) != 0)
            {
                logger(1,
                       "[%8llu, %4llu] ndpi_dpi2json failed for not-detected/guessed flow",
                       workflow->packets_captured,
                       flow->flow_extended.flow_id);
            }
            break;

        case FLOW_EVENT_DETECTED:
        case FLOW_EVENT_DETECTION_UPDATE:
            if (ndpi_dpi2json(workflow->ndpi_struct,
                              &flow->info.detection_data->flow,
                              flow->flow_extended.detected_l7_protocol,
                              &workflow->ndpi_serializer) != 0)
            {
                logger(1,
                       "[%8llu, %4llu] ndpi_dpi2json failed for detected/detection-update flow",
                       workflow->packets_captured,
                       flow->flow_extended.flow_id);
            }
            break;
    }

    serialize_and_send(reader_thread);
}

static void internal_format_error(ndpi_serializer * const serializer, char const * const format, uint32_t format_index)
{
    logger(1, "BUG: Internal error detected for format string `%s' at format index %u", format, format_index);
    ndpi_reset_serializer(serializer);
}

static void vjsonize_error_eventf(struct nDPId_reader_thread * const reader_thread, char const * format, va_list ap)
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
                    int s_ret = snprintf(json_key, sizeof(json_key), "%s", value);
                    if (s_ret < 0)
                    {
                        logger(1,
                               "[%8llu, %zu] Error event format failed: snprintf returned %d, buffer size %zu",
                               reader_thread->workflow->packets_captured,
                               reader_thread->array_index,
                               s_ret,
                               sizeof(json_key));
                    }
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

__attribute__((format(printf, 3, 4))) static void jsonize_error_eventf(struct nDPId_reader_thread * const reader_thread,
                                                                       enum error_event event,
                                                                       char const * format,
                                                                       ...)
{
    struct nDPId_workflow * const workflow = reader_thread->workflow;
    va_list ap;
    char const ev[] = "error_event_name";

    ndpi_serialize_string_int32(&reader_thread->workflow->ndpi_serializer, "error_event_id", event);
    if (event > ERROR_EVENT_INVALID && event < ERROR_EVENT_COUNT)
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, error_event_name_table[event]);
    }
    else
    {
        ndpi_serialize_string_string(&workflow->ndpi_serializer, ev, error_event_name_table[ERROR_EVENT_INVALID]);
    }
    ndpi_serialize_string_uint32(&reader_thread->workflow->ndpi_serializer, "threshold_n", workflow->error_count);
    ndpi_serialize_string_uint32(&reader_thread->workflow->ndpi_serializer,
                                 "threshold_n_max",
                                 GET_CMDARG_ULL(nDPId_options.error_event_threshold_n));
    ndpi_serialize_string_uint64(&reader_thread->workflow->ndpi_serializer,
                                 "threshold_time",
                                 GET_CMDARG_ULL(nDPId_options.error_event_threshold_time));
    ndpi_serialize_string_uint64(&reader_thread->workflow->ndpi_serializer,
                                 "threshold_ts_usec",
                                 workflow->last_error_time);

    switch (event)
    {
        case MAX_FLOW_TO_TRACK:
        case FLOW_MEMORY_ALLOCATION_FAILED:
            jsonize_basic(reader_thread, 1);
            break;
        default:
            jsonize_basic(reader_thread, 0);
            break;
    }

    if (format != NULL)
    {
        va_start(ap, format);
        vjsonize_error_eventf(reader_thread, format, ap);
        va_end(ap);
    }

    ndpi_serialize_string_uint64(&workflow->ndpi_serializer, "global_ts_usec", workflow->last_global_time);
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
     * with the same detection JSON message over and over again.
     * So we are building a hash over the more "stable" parts of the ndpi flow struct.
     * Stable in terms of they should only change if the detection changes for whatever reason.
     * At the time of writing, nDPI has no API function to check if the detection changed
     * or has some new information available. This is far from perfect.
     */
    uint32_t hash = murmur3_32((uint8_t const *)&ndpi_flow->protos, sizeof(ndpi_flow->protos), nDPId_FLOW_STRUCT_SEED);
    hash += ndpi_flow->category;
    hash += (ndpi_flow->risk & 0xFFFFFFFF) + (ndpi_flow->risk >> 32); // nDPI Risks are u64's (might change in the
                                                                      // future)
    hash += ndpi_flow->confidence;

    const size_t protocol_bitmask_size = sizeof(ndpi_flow->excluded_protocol_bitmask.fds_bits) /
                                         sizeof(ndpi_flow->excluded_protocol_bitmask.fds_bits[0]);
    for (size_t i = 0; i < protocol_bitmask_size; ++i)
    {
        hash += ndpi_flow->excluded_protocol_bitmask.fds_bits[i];
        hash += ndpi_flow->excluded_protocol_bitmask.fds_bits[i];
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
    int datalink_type;
    const struct ndpi_ethhdr * ethernet;

#ifdef ENABLE_PFRING
    if (GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0)
    {
        datalink_type = npfring_datalink(&reader_thread->workflow->npf);
    }
    else
#endif
    {
        datalink_type = pcap_datalink(reader_thread->workflow->pcap_handle);
    }

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
                if (is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(reader_thread,
                                         UNKNOWN_DATALINK_LAYER,
                                         "%s%u",
                                         "layer_type",
                                         ntohl(*((uint32_t *)&packet[eth_offset])));
                    jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                }
                return 1;
            }
            *ip_offset = sizeof(dlt_hdr) + eth_offset;
            break;
        }
        case DLT_PPP_SERIAL:
        {
            if (header->caplen < sizeof(struct ndpi_chdlc))
            {
                if (is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(reader_thread,
                                         PACKET_TOO_SHORT,
                                         "%s%u %s%zu",
                                         "size",
                                         header->caplen,
                                         "expected",
                                         sizeof(struct ndpi_chdlc));
                    jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                }
                return 1;
            }

            struct ndpi_chdlc const * const chdlc = (struct ndpi_chdlc const * const)&packet[eth_offset];
            *ip_offset = sizeof(struct ndpi_chdlc);
            *layer3_type = ntohs(chdlc->proto_code);
            break;
        }
        case DLT_C_HDLC:
        case DLT_PPP:
            if (header->caplen < sizeof(struct ndpi_chdlc))
            {
                if (is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(reader_thread,
                                         PACKET_TOO_SHORT,
                                         "%s%u %s%zu",
                                         "size",
                                         header->caplen,
                                         "expected",
                                         sizeof(struct ndpi_chdlc));
                    jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                }
                return 1;
            }

            if (packet[0] == 0x0f || packet[0] == 0x8f)
            {
                struct ndpi_chdlc const * const chdlc = (struct ndpi_chdlc const * const)&packet[eth_offset];
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
                if (is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(
                        reader_thread, PACKET_TOO_SHORT, "%s%u %s%u", "size", header->caplen, "expected", 16);
                    jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                }
                return 1;
            }

            *layer3_type = (packet[eth_offset + 14] << 8) + packet[eth_offset + 15];
            *ip_offset = 16 + eth_offset;
            break;
        case DLT_IEEE802_11_RADIO:
        {
            if (header->caplen < sizeof(struct ndpi_radiotap_header))
            {
                if (is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(reader_thread,
                                         PACKET_TOO_SHORT,
                                         "%s%u %s%zu",
                                         "size",
                                         header->caplen,
                                         "expected",
                                         sizeof(struct ndpi_radiotap_header));
                    jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                }
                return 1;
            }

            struct ndpi_radiotap_header const * const radiotap =
                (struct ndpi_radiotap_header const * const)&packet[eth_offset];
            uint16_t radio_len = radiotap->len;

            /* Check Bad FCS presence */
            if ((radiotap->flags & BAD_FCS) == BAD_FCS)
            {
                if (is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(reader_thread, PACKET_HEADER_INVALID, "%s%s", "reason", "Bad FCS presence");
                    jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                }
                return 1;
            }

            if (header->caplen < (eth_offset + radio_len + sizeof(struct ndpi_wifi_header)))
            {
                if (is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(reader_thread,
                                         PACKET_TOO_SHORT,
                                         "%s%u %s%zu",
                                         "size",
                                         header->caplen,
                                         "expected",
                                         (eth_offset + radio_len + sizeof(struct ndpi_wifi_header)));
                    jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                }
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
            *ip_offset = 0;
            if (header->caplen < 1)
            {
                return 1;
            }
            switch ((packet[0] & 0xF0) >> 4)
            {
                case 4:
                    *layer3_type = ETH_P_IP;
                    break;
                case 6:
                    *layer3_type = ETH_P_IPV6;
                    break;
                default:
                    return 1;
            }
            break;
        case DLT_EN10MB:
            if (header->caplen < sizeof(struct ndpi_ethhdr))
            {
                if (is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(reader_thread,
                                         PACKET_TOO_SHORT,
                                         "%s%u %s%zu",
                                         "size",
                                         header->caplen,
                                         "expected",
                                         sizeof(struct ndpi_ethhdr));
                    jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                }
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
                    if (is_error_event_threshold(reader_thread->workflow) == 0)
                    {
                        jsonize_error_eventf(reader_thread,
                                             PACKET_TOO_SHORT,
                                             "%s%u %s%zu",
                                             "size",
                                             header->caplen,
                                             "expected",
                                             sizeof(struct ndpi_ethhdr) + 2);
                        jsonize_packet_event(
                            reader_thread, header, packet, *layer3_type, *ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                    }
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
                    if (is_error_event_threshold(reader_thread->workflow) == 0)
                    {
                        jsonize_error_eventf(reader_thread,
                                             PACKET_TOO_SHORT,
                                             "%s%u %s%zu",
                                             "size",
                                             header->caplen,
                                             "expected",
                                             sizeof(struct ndpi_ethhdr) + 4);
                        jsonize_packet_event(
                            reader_thread, header, packet, *layer3_type, *ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                    }
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
                        if (is_error_event_threshold(reader_thread->workflow) == 0)
                        {
                            jsonize_error_eventf(reader_thread,
                                                 IP4_PACKET_TOO_SHORT,
                                                 "%s%u %s%zu",
                                                 "size",
                                                 header->caplen,
                                                 "expected",
                                                 sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr));
                            jsonize_packet_event(reader_thread,
                                                 header,
                                                 packet,
                                                 *layer3_type,
                                                 *ip_offset,
                                                 0,
                                                 0,
                                                 NULL,
                                                 PACKET_EVENT_PAYLOAD);
                        }
                        return 1;
                    }
                    break;
                case ETH_P_IPV6: /* IPV6 */
                    if (header->caplen < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr))
                    {
                        if (is_error_event_threshold(reader_thread->workflow) == 0)
                        {
                            jsonize_error_eventf(reader_thread,
                                                 IP6_PACKET_TOO_SHORT,
                                                 "%s%u %s%zu",
                                                 "size",
                                                 header->caplen,
                                                 "expected",
                                                 sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr));
                            jsonize_packet_event(reader_thread,
                                                 header,
                                                 packet,
                                                 *layer3_type,
                                                 *ip_offset,
                                                 0,
                                                 0,
                                                 NULL,
                                                 PACKET_EVENT_PAYLOAD);
                        }
                        return 1;
                    }
                    break;
                case ETHERTYPE_PAE: /* 802.1X Authentication */
                    return 1;
                case ETHERTYPE_ARP: /* ARP */
                    return 1;
                default:
                    if (is_error_event_threshold(reader_thread->workflow) == 0)
                    {
                        jsonize_error_eventf(reader_thread, PACKET_TYPE_UNKNOWN, "%s%u", "layer_type", *layer3_type);
                        jsonize_packet_event(
                            reader_thread, header, packet, *layer3_type, *ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
                    }
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
        /* Switch tag datalinks are not supported for now. */
        case DLT_DSA_TAG_DSA:
            return 1;
        case DLT_DSA_TAG_EDSA:
            return 1;
        default:
            if (is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(reader_thread,
                                     UNKNOWN_DATALINK_LAYER,
                                     "%s%u",
                                     "layer_type",
                                     ntohl(*((uint32_t *)&packet[eth_offset])));
                jsonize_packet_event(reader_thread, header, packet, 0, 0, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            }
            return 1;
    }

    return 0;
}

static struct nDPId_flow_basic * add_new_flow(struct nDPId_workflow * const workflow,
                                              struct nDPId_flow_basic * orig_flow_basic,
                                              enum nDPId_flow_state state,
                                              size_t hashed_index)
{
    size_t s;

    switch (state)
    {
        case FS_UNKNOWN:
        case FS_COUNT:

        case FS_FINISHED: // do not allocate something for FS_FINISHED as we are re-using memory allocated by FS_INFO
            return NULL;

        case FS_SKIPPED:
            workflow->total_skipped_flows++;
            s = sizeof(struct nDPId_flow_skipped);
            break;

        case FS_INFO:
            s = sizeof(struct nDPId_flow);
            break;
    }

    struct nDPId_flow_basic * flow_basic = (struct nDPId_flow_basic *)ndpi_malloc(s);
    if (flow_basic == NULL)
    {
        return NULL;
    }
    memset(flow_basic, 0, s);
    *flow_basic = *orig_flow_basic;
    flow_basic->state = state;
    if (ndpi_tsearch(flow_basic, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == NULL)
    {
        ndpi_free(flow_basic);
        return NULL;
    }

    workflow->cur_active_flows++;
    return flow_basic;
}

static void do_periodically_work(struct nDPId_reader_thread * const reader_thread)
{
    if (reader_thread->workflow->last_scan_time + GET_CMDARG_ULL(nDPId_options.flow_scan_interval) <=
        reader_thread->workflow->last_global_time)
    {
        check_for_idle_flows(reader_thread);
        check_for_flow_updates(reader_thread);
        reader_thread->workflow->last_scan_time = reader_thread->workflow->last_global_time;
    }
    if (reader_thread->workflow->last_status_time + GET_CMDARG_ULL(nDPId_options.daemon_status_interval) +
            reader_thread->array_index * 1000 <=
        reader_thread->workflow->last_global_time)
    {
        jsonize_daemon(reader_thread, DAEMON_EVENT_STATUS);
        reader_thread->workflow->last_status_time =
            reader_thread->workflow->last_global_time + reader_thread->array_index * 1000;
    }
#ifdef ENABLE_MEMORY_PROFILING
    if (reader_thread->workflow->last_memory_usage_log_time +
            GET_CMDARG_ULL(nDPId_options.memory_profiling_log_interval) <=
        reader_thread->workflow->last_global_time)
    {
        log_memory_usage(reader_thread);
        reader_thread->workflow->last_memory_usage_log_time = reader_thread->workflow->last_global_time;
    }
#endif
}

static int distribute_single_packet(struct nDPId_reader_thread * const reader_thread)
{
    return (reader_thread->workflow->packets_captured % GET_CMDARG_ULL(nDPId_options.reader_thread_count) ==
            reader_thread->array_index);
}

static void ndpi_process_packet(uint8_t * const args,
                                struct pcap_pkthdr const * const header,
                                uint8_t const * const packet)
{
    struct nDPId_reader_thread * const reader_thread = (struct nDPId_reader_thread *)args;
    struct nDPId_workflow * workflow;
    struct nDPId_flow_basic flow_basic = {};
    enum nDPId_flow_direction direction;

    size_t hashed_index;
    void * tree_result;
    struct nDPId_flow * flow_to_process;

    uint8_t is_new_flow = 0;

    const struct ndpi_iphdr * ip;
    struct ndpi_ipv6hdr * ip6;
    const struct ndpi_tcphdr * tcp = NULL;

    uint64_t time_us;
    uint64_t last_pkt_time;

    uint16_t ip_offset = 0;
    uint16_t ip_size;

    const uint8_t * l4_ptr = NULL;
    uint16_t l4_len = 0;
    uint16_t l4_payload_len = 0;

    uint16_t type = 0;
    size_t thread_index = nDPId_THREAD_DISTRIBUTION_SEED; // generated with `dd if=/dev/random bs=1024 count=1 |& hd'

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
    time_us = ndpi_timeval_to_microseconds(header->ts);
    if (workflow->last_global_time < time_us)
    {
        workflow->last_global_time = time_us;
    }
    if (workflow->last_thread_time == 0)
    {
        workflow->last_thread_time = time_us;
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
        if (distribute_single_packet(reader_thread) != 0 && is_error_event_threshold(reader_thread->workflow) == 0)
        {
            jsonize_error_eventf(reader_thread, UNKNOWN_L3_PROTOCOL, "%s%u", "protocol", type);
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
        }
        return;
    }
    ip_size = header->caplen - ip_offset;

    if (type == ETH_P_IP && header->caplen >= ip_offset)
    {
        if (header->caplen < header->len)
        {
            if (distribute_single_packet(reader_thread) != 0 && is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(reader_thread,
                                     CAPTURE_SIZE_SMALLER_THAN_PACKET_SIZE,
                                     "%s%u %s%u",
                                     "size",
                                     header->caplen,
                                     "expected",
                                     header->len);
                jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            }
        }
    }

    /* process layer3 e.g. IPv4 / IPv6 */
    if (ip != NULL && ip->version == 4)
    {
        if (ip_size < sizeof(*ip))
        {
            if (distribute_single_packet(reader_thread) != 0 && is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(reader_thread,
                                     IP4_SIZE_SMALLER_THAN_HEADER,
                                     "%s%u %s%zu",
                                     "size",
                                     ip_size,
                                     "expected",
                                     sizeof(*ip));
                jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            }
            return;
        }

        flow_basic.l3_type = L3_IP;

        if (ndpi_detection_get_l4(
                (uint8_t *)ip, ip_size, &l4_ptr, &l4_len, &flow_basic.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
        {
            if (distribute_single_packet(reader_thread) != 0 && is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(
                    reader_thread, IP4_L4_PAYLOAD_DETECTION_FAILED, "%s%zu", "l4_data_len", ip_size - sizeof(*ip));
                jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            }
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
            if (distribute_single_packet(reader_thread) != 0 && is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(reader_thread,
                                     IP6_SIZE_SMALLER_THAN_HEADER,
                                     "%s%u %s%zu",
                                     "size",
                                     ip_size,
                                     "expected",
                                     sizeof(ip6->ip6_hdr));
                jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            }
            return;
        }

        flow_basic.l3_type = L3_IP6;
        if (ndpi_detection_get_l4(
                (uint8_t *)ip6, ip_size, &l4_ptr, &l4_len, &flow_basic.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
        {
            if (distribute_single_packet(reader_thread) != 0 && is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(
                    reader_thread, IP6_L4_PAYLOAD_DETECTION_FAILED, "%s%zu", "l4_data_len", ip_size - sizeof(*ip));
                jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
            }
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
        if (distribute_single_packet(reader_thread) != 0 && is_error_event_threshold(reader_thread->workflow) == 0)
        {
            jsonize_error_eventf(reader_thread, UNKNOWN_L3_PROTOCOL, "%s%u", "protocol", type);
            jsonize_packet_event(reader_thread, header, packet, type, ip_offset, 0, 0, NULL, PACKET_EVENT_PAYLOAD);
        }
        return;
    }

    /* process layer4 e.g. TCP / UDP */
    if (flow_basic.l4_protocol == IPPROTO_TCP)
    {
        if (header->caplen < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr))
        {
            if (distribute_single_packet(reader_thread) != 0 && is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(reader_thread,
                                     TCP_PACKET_TOO_SHORT,
                                     "%s%u %s%zu",
                                     "size",
                                     header->caplen,
                                     "expected",
                                     (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
                jsonize_packet_event(reader_thread,
                                     header,
                                     packet,
                                     type,
                                     ip_offset,
                                     (l4_ptr - packet),
                                     l4_len,
                                     NULL,
                                     PACKET_EVENT_PAYLOAD);
            }
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
            if (distribute_single_packet(reader_thread) != 0 && is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(reader_thread,
                                     UDP_PACKET_TOO_SHORT,
                                     "%s%u %s%zu",
                                     "size",
                                     header->caplen,
                                     "expected",
                                     (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
                jsonize_packet_event(reader_thread,
                                     header,
                                     packet,
                                     type,
                                     ip_offset,
                                     (l4_ptr - packet),
                                     l4_len,
                                     NULL,
                                     PACKET_EVENT_PAYLOAD);
            }
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
    thread_index %= GET_CMDARG_ULL(nDPId_options.reader_thread_count);
    if (thread_index != reader_thread->array_index)
    {
        return;
    }

    if (workflow->last_thread_time < time_us)
    {
        workflow->last_thread_time = time_us;
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
    direction = FD_SRC2DST;
    tree_result = ndpi_tfind(&flow_basic, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
    if (tree_result == NULL)
    {
        direction = FD_DST2SRC;

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
        direction = FD_SRC2DST;

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
        if (GET_CMDARG_BOOLEAN(nDPId_options.process_internal_initial_direction) != 0 &&
            flow_basic.tcp_is_midstream_flow == 0)
        {
            if (is_ip_in_subnet(&flow_basic.src, netmask, subnet, flow_basic.l3_type) == 0)
            {
                if (add_new_flow(workflow, &flow_basic, FS_SKIPPED, hashed_index) == NULL &&
                    is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(reader_thread,
                                         FLOW_MEMORY_ALLOCATION_FAILED,
                                         "%s%zu",
                                         "size",
                                         sizeof(struct nDPId_flow_skipped));
                    jsonize_packet_event(reader_thread,
                                         header,
                                         packet,
                                         type,
                                         ip_offset,
                                         (l4_ptr - packet),
                                         l4_len,
                                         NULL,
                                         PACKET_EVENT_PAYLOAD);
                }
                return;
            }
        }
        else if (GET_CMDARG_BOOLEAN(nDPId_options.process_external_initial_direction) != 0 &&
                 flow_basic.tcp_is_midstream_flow == 0)
        {
            if (is_ip_in_subnet(&flow_basic.src, netmask, subnet, flow_basic.l3_type) != 0)
            {
                if (add_new_flow(workflow, &flow_basic, FS_SKIPPED, hashed_index) == NULL &&
                    is_error_event_threshold(reader_thread->workflow) == 0)
                {
                    jsonize_error_eventf(reader_thread,
                                         FLOW_MEMORY_ALLOCATION_FAILED,
                                         "%s%zu",
                                         "size",
                                         sizeof(struct nDPId_flow_skipped));
                    jsonize_packet_event(reader_thread,
                                         header,
                                         packet,
                                         type,
                                         ip_offset,
                                         (l4_ptr - packet),
                                         l4_len,
                                         NULL,
                                         PACKET_EVENT_PAYLOAD);
                }
                return;
            }
        }

        if (workflow->cur_active_flows == workflow->max_active_flows)
        {
            if (is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(reader_thread,
                                     MAX_FLOW_TO_TRACK,
                                     "%s%llu %s%llu %s%llu %s%llu",
                                     "current_active",
                                     workflow->cur_active_flows,
                                     "current_idle",
                                     workflow->cur_idle_flows,
                                     "max_active",
                                     workflow->max_active_flows,
                                     "max_idle",
                                     workflow->max_idle_flows);
                jsonize_packet_event(reader_thread,
                                     header,
                                     packet,
                                     type,
                                     ip_offset,
                                     (l4_ptr - packet),
                                     l4_len,
                                     NULL,
                                     PACKET_EVENT_PAYLOAD);
            }
            return;
        }

        flow_to_process = (struct nDPId_flow *)add_new_flow(workflow, &flow_basic, FS_INFO, hashed_index);
        if (flow_to_process == NULL)
        {
            if (is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(
                    reader_thread, FLOW_MEMORY_ALLOCATION_FAILED, "%s%zu", "size", sizeof(*flow_to_process));
                jsonize_packet_event(reader_thread,
                                     header,
                                     packet,
                                     type,
                                     ip_offset,
                                     (l4_ptr - packet),
                                     l4_len,
                                     NULL,
                                     PACKET_EVENT_PAYLOAD);
            }
            return;
        }

        workflow->total_active_flows++;
        flow_to_process->flow_extended.flow_id = MT_GET_AND_ADD(global_flow_id, 1);

        if (alloc_detection_data(flow_to_process) != 0)
        {
            if (is_error_event_threshold(reader_thread->workflow) == 0)
            {
                jsonize_error_eventf(
                    reader_thread, FLOW_MEMORY_ALLOCATION_FAILED, "%s%zu", "size", sizeof(*flow_to_process));
                jsonize_packet_event(reader_thread,
                                     header,
                                     packet,
                                     type,
                                     ip_offset,
                                     (l4_ptr - packet),
                                     l4_len,
                                     NULL,
                                     PACKET_EVENT_PAYLOAD);
            }
            return;
        }

        is_new_flow = 1;
    }
    else
    {
        /* flow already exists in the tree */

        struct nDPId_flow_basic * const flow_basic_to_process = *(struct nDPId_flow_basic **)tree_result;
        /* Update last seen timestamp for timeout handling. */
        last_pkt_time = flow_basic_to_process->last_pkt_time[direction];
        flow_basic_to_process->last_pkt_time[direction] = workflow->last_thread_time;
        /* TCP-FIN/TCP-RST: indicates that at least one side wants to end the connection. */
        if (flow_basic.tcp_fin_rst_seen != 0)
        {
            flow_basic_to_process->tcp_fin_rst_seen = 1;
        }

        switch (flow_basic_to_process->state)
        {
            case FS_UNKNOWN:
            case FS_COUNT:

            case FS_SKIPPED:
                return;

            case FS_FINISHED:
            case FS_INFO:
                break;
        }
        flow_to_process = (struct nDPId_flow *)flow_basic_to_process;

        if (flow_to_process->flow_extended.flow_basic.state == FS_INFO)
        {
#ifdef ENABLE_ZLIB
            if (GET_CMDARG_BOOLEAN(nDPId_options.enable_zlib_compression) != 0 &&
                flow_to_process->info.detection_data_compressed_size > 0)
            {
                workflow->current_compression_diff -= flow_to_process->info.detection_data_compressed_size;
                int ret = detection_data_inflate(flow_to_process);
                if (ret <= 0)
                {
                    workflow->current_compression_diff += flow_to_process->info.detection_data_compressed_size;
                    logger(1,
                           "zLib decompression failed for existing flow %llu with error code: %d",
                           flow_to_process->flow_extended.flow_id,
                           ret);
                    return;
                }
            }
#endif
        }
    }

    flow_to_process->flow_extended.packets_processed[direction]++;
    flow_to_process->flow_extended.total_l4_payload_len[direction] += l4_payload_len;
    workflow->packets_processed++;
    workflow->total_l4_payload_len += l4_payload_len;

    if (l4_payload_len > flow_to_process->flow_extended.max_l4_payload_len[direction])
    {
        flow_to_process->flow_extended.max_l4_payload_len[direction] = l4_payload_len;
    }
    if (l4_payload_len < flow_to_process->flow_extended.min_l4_payload_len[direction])
    {
        flow_to_process->flow_extended.min_l4_payload_len[direction] = l4_payload_len;
    }

    if (is_new_flow != 0)
    {
        last_pkt_time = flow_to_process->flow_extended.first_seen =
            flow_to_process->flow_extended.flow_basic.last_pkt_time[direction] =
                flow_to_process->flow_extended.flow_basic.last_pkt_time[1 - direction] =
                    flow_to_process->flow_extended.last_flow_update = workflow->last_thread_time;
        flow_to_process->flow_extended.max_l4_payload_len[direction] = l4_payload_len;
        flow_to_process->flow_extended.min_l4_payload_len[direction] = l4_payload_len;
        jsonize_flow_event(reader_thread, &flow_to_process->flow_extended, FLOW_EVENT_NEW);
    }

    if (GET_CMDARG_BOOLEAN(nDPId_options.enable_data_analysis) != 0 &&
        flow_to_process->flow_extended.flow_analysis != NULL &&
        flow_to_process->flow_extended.packets_processed[FD_SRC2DST] +
                flow_to_process->flow_extended.packets_processed[FD_DST2SRC] <=
            GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse))
    {
        unsigned long long int total_flow_packets = flow_to_process->flow_extended.packets_processed[FD_SRC2DST] +
                                                    flow_to_process->flow_extended.packets_processed[FD_DST2SRC];
        uint64_t tdiff_us = timer_sub(workflow->last_thread_time, last_pkt_time);

        if (total_flow_packets > 1)
        {
            ndpi_data_add_value(&flow_to_process->flow_extended.flow_analysis->iat, tdiff_us);
        }
        ndpi_data_add_value(&flow_to_process->flow_extended.flow_analysis->pktlen, ip_size);
        flow_to_process->flow_extended.flow_analysis
            ->directions[(total_flow_packets - 1) % GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse)] =
            direction;
        ndpi_inc_bin(&flow_to_process->flow_extended.flow_analysis->payload_len_bin[direction],
                     plen2slot(l4_payload_len),
                     1);
        flow_to_process->flow_extended.flow_analysis
            ->entropies[(total_flow_packets - 1) % GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse)] =
            ndpi_entropy((ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6), ip_size);

        if (total_flow_packets == GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_analyse))
        {
            jsonize_flow_event(reader_thread, &flow_to_process->flow_extended, FLOW_EVENT_ANALYSE);
            free_analysis_data(&flow_to_process->flow_extended);
        }
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

    if (flow_to_process->flow_extended.flow_basic.state != FS_INFO || flow_to_process->info.detection_data == NULL)
    {
        /* Only FS_INFO goes through the whole detection process. */
        return;
    }

    flow_to_process->flow_extended.detected_l7_protocol =
        ndpi_detection_process_packet(workflow->ndpi_struct,
                                      &flow_to_process->info.detection_data->flow,
                                      ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6,
                                      ip_size,
                                      workflow->last_thread_time / 1000,
                                      NULL);

    if (ndpi_is_protocol_detected(flow_to_process->flow_extended.detected_l7_protocol) != 0 &&
        flow_to_process->info.detection_completed == 0)
    {
        flow_to_process->info.detection_completed = 1;
        workflow->total_detected_flows++;
        /*
         * The following needs to be done, because a successful classification may happen after the first packet.
         * If there is no further extra dissection possible for this protocol, we may be saving an invalid risk.
         */
        if (flow_to_process->flow_extended.packets_processed[FD_SRC2DST] +
                flow_to_process->flow_extended.packets_processed[FD_DST2SRC] ==
            1)
        {
            ndpi_unset_risk(&flow_to_process->info.detection_data->flow, NDPI_UNIDIRECTIONAL_TRAFFIC);
        }
        jsonize_flow_detection_event(reader_thread, flow_to_process, FLOW_EVENT_DETECTED);
        flow_to_process->info.detection_data->last_ndpi_flow_struct_hash =
            calculate_ndpi_flow_struct_hash(&flow_to_process->info.detection_data->flow);
    }
    else if (flow_to_process->info.detection_completed == 1)
    {
        uint32_t hash = calculate_ndpi_flow_struct_hash(&flow_to_process->info.detection_data->flow);
        if (hash != flow_to_process->info.detection_data->last_ndpi_flow_struct_hash)
        {
            workflow->total_flow_detection_updates++;
            jsonize_flow_detection_event(reader_thread, flow_to_process, FLOW_EVENT_DETECTION_UPDATE);
            flow_to_process->info.detection_data->last_ndpi_flow_struct_hash = hash;
        }
    }

    if (flow_to_process->info.detection_data->flow.num_processed_pkts ==
            GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_process) &&
        flow_to_process->info.detection_completed == 0)
    {
        /* last chance to guess something, better then nothing */
        uint8_t protocol_was_guessed = 0;
        flow_to_process->info.detection_data->guessed_l7_protocol =
            ndpi_detection_giveup(workflow->ndpi_struct,
                                  &flow_to_process->info.detection_data->flow,
                                  &protocol_was_guessed);
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

    if (flow_to_process->info.detection_data->flow.num_processed_pkts ==
            GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_process) ||
        (ndpi_is_protocol_detected(flow_to_process->flow_extended.detected_l7_protocol) != 0 &&
         ndpi_extra_dissection_possible(workflow->ndpi_struct, &flow_to_process->info.detection_data->flow) == 0))
    {
        struct ndpi_proto detected_l7_protocol = flow_to_process->flow_extended.detected_l7_protocol;
        if (ndpi_is_protocol_detected(detected_l7_protocol) == 0)
        {
            detected_l7_protocol = flow_to_process->info.detection_data->guessed_l7_protocol;
        }

        ndpi_risk risk = flow_to_process->info.detection_data->flow.risk;
        ndpi_confidence_t confidence = flow_to_process->info.detection_data->flow.confidence;
        char * hostname = NULL;
        if (flow_to_process->info.detection_data->flow.host_server_name[0] != '\0')
        {
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
            _Static_assert(sizeof(flow_to_process->info.detection_data->flow.host_server_name) == 80,
                           "Size of nDPI flow host server name changed. Please review manually.");
#endif
            hostname = strndup(&flow_to_process->info.detection_data->flow.host_server_name[0],
                               sizeof(flow_to_process->info.detection_data->flow.host_server_name));
        }

        free_detection_data(flow_to_process);

        flow_to_process->flow_extended.flow_basic.state = FS_FINISHED;
        struct nDPId_flow * const flow = flow_to_process;
        flow->flow_extended.detected_l7_protocol = detected_l7_protocol;
        flow->finished.risk = risk;
        flow->finished.confidence = confidence;
        flow->finished.hostname = hostname;
    }

#ifdef ENABLE_ZLIB
    if (GET_CMDARG_BOOLEAN(nDPId_options.enable_zlib_compression) != 0)
    {
        check_for_compressable_flows(reader_thread);
    }
#endif
}

static void get_current_time(struct timeval * const tval)
{
    gettimeofday(tval, NULL);
}

#if !defined(__FreeBSD__) && !defined(__APPLE__)
static void ndpi_log_flow_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    struct nDPId_reader_thread const * const reader_thread = (struct nDPId_reader_thread *)user_data;
    struct nDPId_flow_basic const * const flow_basic = *(struct nDPId_flow_basic **)A;

    (void)depth;
    (void)user_data;

    if (flow_basic == NULL)
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        switch (flow_basic->state)
        {
            case FS_UNKNOWN:
                break;

            case FS_COUNT:
                break;

            case FS_SKIPPED:
                break;

            case FS_FINISHED:
            {
                struct nDPId_flow const * const flow = (struct nDPId_flow *)flow_basic;

                uint64_t last_seen = get_last_pkt_time(flow_basic);
                uint64_t idle_time = get_l4_protocol_idle_time_external(flow->flow_extended.flow_basic.l4_protocol);
                logger(0,
                       "[%2zu][%4llu][last-seen: %13llu][last-update: %13llu][idle-time: %7llu][time-until-timeout: "
                       "%7llu]",
                       reader_thread->array_index,
                       flow->flow_extended.flow_id,
                       (unsigned long long int)last_seen,
                       (unsigned long long int)flow->flow_extended.last_flow_update,
                       (unsigned long long int)idle_time,
                       (unsigned long long int)(last_seen + idle_time >= reader_thread->workflow->last_thread_time
                                                    ? last_seen + idle_time - reader_thread->workflow->last_thread_time
                                                    : 0));
                break;
            }

            case FS_INFO:
            {
                struct nDPId_flow const * const flow = (struct nDPId_flow *)flow_basic;

                uint64_t last_seen = get_last_pkt_time(flow_basic);
                uint64_t idle_time = get_l4_protocol_idle_time_external(flow->flow_extended.flow_basic.l4_protocol);
                logger(0,
                       "[%2zu][%4llu][last-seen: %13llu][last-update: %13llu][idle-time: %7llu][time-until-timeout: "
                       "%7llu]",
                       reader_thread->array_index,
                       flow->flow_extended.flow_id,
                       (unsigned long long int)last_seen,
                       (unsigned long long int)flow->flow_extended.last_flow_update,
                       (unsigned long long int)idle_time,
                       (unsigned long long int)(last_seen + idle_time >= reader_thread->workflow->last_thread_time
                                                    ? last_seen + idle_time - reader_thread->workflow->last_thread_time
                                                    : 0));
                break;
            }
        }
    }
}

static void log_all_flows(struct nDPId_reader_thread const * const reader_thread)
{
    struct nDPId_workflow const * const workflow = reader_thread->workflow;

    logger(0,
           "[%2zu][last-global-time: %13llu][last-thread-time: %13llu][last-scan-time: %13llu]",
           reader_thread->array_index,
           (unsigned long long int)workflow->last_global_time,
           (unsigned long long int)workflow->last_thread_time,
           (unsigned long long int)workflow->last_scan_time);
    for (size_t scan_index = 0; scan_index < workflow->max_active_flows; ++scan_index)
    {
        ndpi_twalk(workflow->ndpi_flows_active[scan_index], ndpi_log_flow_walker, (void *)reader_thread);
    }
}
#endif

static void run_capture_loop(struct nDPId_reader_thread * const reader_thread)
{
    if (reader_thread->workflow == NULL || (reader_thread->workflow->pcap_handle == NULL
#ifdef ENABLE_PFRING
                                            && reader_thread->workflow->npf.pfring_desc == NULL
#endif
                                            ))
    {
        return;
    }

    if (reader_thread->workflow->is_pcap_file != 0)
    {
        switch (pcap_loop(reader_thread->workflow->pcap_handle, -1, &ndpi_process_packet, (uint8_t *)reader_thread))
        {
            case PCAP_ERROR:
                logger(1, "Error while reading pcap file: '%s'", pcap_geterr(reader_thread->workflow->pcap_handle));
                MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
                return;
            case PCAP_ERROR_BREAK:
                MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
                return;
            default:
                return;
        }
    }
    else
    {
#if !defined(__FreeBSD__) && !defined(__APPLE__)
        sigset_t thread_signal_set, old_signal_set;
        sigfillset(&thread_signal_set);
        if (pthread_sigmask(SIG_BLOCK, &thread_signal_set, &old_signal_set) != 0)
        {
            logger(1, "pthread_sigmask: %s", strerror(errno));
            MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
            return;
        }

        sigaddset(&thread_signal_set, SIGINT);
        sigaddset(&thread_signal_set, SIGTERM);
        sigaddset(&thread_signal_set, SIGUSR1);
        int signal_fd = signalfd(-1, &thread_signal_set, SFD_NONBLOCK);
        if (signal_fd < 0 || set_fd_cloexec(signal_fd) < 0)
        {
            logger(1, "signalfd: %s", strerror(errno));
            MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
            return;
        }
#endif

        int capture_fd = -1;
#ifdef ENABLE_PFRING
        if (GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0)
        {
            capture_fd = npfring_get_selectable_fd(&reader_thread->workflow->npf);
        }
        else
#endif
        {
            capture_fd = pcap_get_selectable_fd(reader_thread->workflow->pcap_handle);
        }
        if (capture_fd < 0)
        {
            logger(1,
                   "Got an invalid %s fd",
                   (
#ifdef ENABLE_PFRING
                       GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0 ? "PF_RING" :
#endif
                                                                         "PCAP"));
            MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
            return;
        }

        struct nio io;
        nio_init(&io);
#ifdef ENABLE_EPOLL
        if ((GET_CMDARG_BOOLEAN(nDPId_options.use_poll) == 0 && nio_use_epoll(&io, 32) != NIO_SUCCESS) ||
            (GET_CMDARG_BOOLEAN(nDPId_options.use_poll) != 0 &&
             nio_use_poll(&io, nDPIsrvd_MAX_REMOTE_DESCRIPTORS) != NIO_SUCCESS))
#else
        if (nio_use_poll(&io, nDPIsrvd_MAX_REMOTE_DESCRIPTORS) != NIO_SUCCESS)
#endif
        {
            logger(1, "%s", "Event I/O poll/epoll setup failed");
            MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
            nio_free(&io);
            return;
        }

        errno = 0;
        if (nio_add_fd(&io, capture_fd, NIO_EVENT_INPUT, NULL) != NIO_SUCCESS)
        {
            logger(1, "Could not add pcap fd to event queue: %s", (errno != 0 ? strerror(errno) : "Internal Error"));
            MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
            nio_free(&io);
            return;
        }
#if !defined(__FreeBSD__) && !defined(__APPLE__)
        errno = 0;
        if (nio_add_fd(&io, signal_fd, NIO_EVENT_INPUT, NULL) != NIO_SUCCESS)
        {
            logger(1, "Could not add signal fd to event queue: %s", (errno != 0 ? strerror(errno) : "Internal Error"));
            MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
            nio_free(&io);
            return;
        }
#endif

        int const timeout_ms = 1000; /* TODO: Configurable? */
        struct timeval tval_before_epoll, tval_after_epoll;
        while (MT_GET_AND_ADD(nDPId_main_thread_shutdown, 0) == 0 && processing_threads_error_or_eof() == 0)
        {
            get_current_time(&tval_before_epoll);
            errno = 0;
            if (nio_run(&io, timeout_ms) != NIO_SUCCESS)
            {
                logger(1, "Event I/O returned error: %s", strerror(errno));
                MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
                break;
            }

            int nready = nio_get_nready(&io);

            if (nready == 0)
            {
                struct timeval tval_diff;
                get_current_time(&tval_after_epoll);
                ndpi_timer_sub(&tval_after_epoll, &tval_before_epoll, &tval_diff);
                uint64_t tdiff_us = tval_diff.tv_sec * 1000 * 1000 + tval_diff.tv_usec;

                reader_thread->workflow->last_global_time += tdiff_us;
                reader_thread->workflow->last_thread_time += tdiff_us;

                do_periodically_work(reader_thread);
            }

            for (int i = 0; i < nready; ++i)
            {
                if (nio_has_error(&io, i) == NIO_SUCCESS)
                {
                    logger(1, "%s", "Event I/O error");
                    MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
                }

                int fd = nio_get_fd(&io, i);

#if !defined(__FreeBSD__) && !defined(__APPLE__)
                if (fd == signal_fd)
                {
                    struct signalfd_siginfo fdsi;
                    if (read(signal_fd, &fdsi, sizeof(fdsi)) != sizeof(fdsi))
                    {
                        if (errno != EAGAIN)
                        {
                            logger(1, "Could not read signal data from fd %d: %s", signal_fd, strerror(errno));
                        }
                    }
                    else
                    {
                        int is_valid_signal = 0;
                        char const * signame = "unknown";
                        switch (fdsi.ssi_signo)
                        {
                            case SIGINT:
                                is_valid_signal = 1;
                                signame = "SIGINT";
                                sighandler(SIGINT);
                                break;
                            case SIGTERM:
                                is_valid_signal = 1;
                                signame = "SIGTERM";
                                sighandler(SIGTERM);
                                break;
                            case SIGUSR1:
                                is_valid_signal = 1;
                                signame = "SIGUSR1";
                                log_all_flows(reader_thread);
                                break;
                        }
                        if (is_valid_signal != 0)
                        {
                            logger(1, "Received signal %d (%s)", fdsi.ssi_signo, signame);
                        }
                        else
                        {
                            logger(1, "Received signal %d (%s), ignored", fdsi.ssi_signo, signame);
                        }
                    }
                }
                else
#endif
                    if (fd == capture_fd)
                {
#ifdef ENABLE_PFRING
                    if (GET_CMDARG_BOOLEAN(nDPId_options.use_pfring) != 0)
                    {
                        struct pcap_pkthdr hdr;

                        int rc = npfring_recv(&reader_thread->workflow->npf, &hdr);
                        if (rc == 0)
                        {
                            logger(1, "Error while reading packets from PF_RING: %d", rc);
                            MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
                            nio_free(&io);
                            return;
                        }

                        ndpi_process_packet((uint8_t *)reader_thread,
                                            &hdr,
                                            &reader_thread->workflow->npf.pfring_buffer[0]);
                    }
                    else
#endif
                    {
                        switch (pcap_dispatch(
                            reader_thread->workflow->pcap_handle, -1, ndpi_process_packet, (uint8_t *)reader_thread))
                        {
                            case PCAP_ERROR:
                                logger(1,
                                       "Error while reading from pcap device: '%s'",
                                       pcap_geterr(reader_thread->workflow->pcap_handle));
                                MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
                                break;
                            case PCAP_ERROR_BREAK:
                                MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
                                nio_free(&io);
                                return;
                            default:
                                break;
                        }
                    }
                }
                else
                {
                    logger(1, "Unknown event descriptor or data returned: %p", nio_get_ptr(&io, i));
                }
            }
        }

        nio_free(&io);
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

    reader_thread->collector_sockfd = -1;

    if (connect_to_collector(reader_thread) != 0)
    {
        logger(1,
               "Thread %zu: Could not connect to nDPIsrvd Collector at %s, will try again later. Error: %s",
               reader_thread->array_index,
               GET_CMDARG_STR(nDPId_options.collector_address),
               (reader_thread->collector_sock_last_errno != 0 ? strerror(reader_thread->collector_sock_last_errno)
                                                              : "Internal Error."));
    }
    else
    {
        jsonize_daemon(reader_thread, DAEMON_EVENT_INIT);
    }

    run_capture_loop(reader_thread);
    set_collector_block(reader_thread);
    MT_GET_AND_ADD(reader_thread->workflow->error_or_eof, 1);
    return NULL;
}

static WARN_UNUSED int processing_threads_error_or_eof(void)
{
    for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.reader_thread_count); ++i)
    {
        if (MT_GET_AND_ADD(reader_threads[i].workflow->error_or_eof, 0) == 0)
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
        logger_early(1, "pthread_sigmask: %s", strerror(errno));
        return 1;
    }

    if (daemonize_with_pidfile(GET_CMDARG_STR(nDPId_options.pidfile)) != 0)
    {
        return 1;
    }

    int ret = change_user_group(GET_CMDARG_STR(nDPId_options.user),
                                GET_CMDARG_STR(nDPId_options.group),
                                GET_CMDARG_STR(nDPId_options.pidfile),
                                NULL,
                                NULL);
    if (ret != 0 && ret != -EPERM)
    {
        if (GET_CMDARG_STR(nDPId_options.group) != NULL)
        {
            logger(1,
                   "Change user/group to %s/%s failed: %s",
                   GET_CMDARG_STR(nDPId_options.user),
                   GET_CMDARG_STR(nDPId_options.group),
                   strerror(-ret));
        }
        else
        {
            logger(1, "Change user to %s failed: %s", GET_CMDARG_STR(nDPId_options.user), strerror(-ret));
        }
        return 1;
    }

    for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.reader_thread_count); ++i)
    {
        reader_threads[i].array_index = i;

        if (reader_threads[i].workflow == NULL)
        {
            /* no more threads should be started */
            break;
        }

        if (pthread_create(&reader_threads[i].thread, NULL, processing_thread, &reader_threads[i]) != 0)
        {
            logger(1, "pthread_create: %s", strerror(errno));
            return 1;
        }
    }

    if (pthread_sigmask(SIG_BLOCK, &old_signal_set, NULL) != 0)
    {
        logger(1, "pthread_sigmask: %s", strerror(errno));
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

    if (workflow->cur_idle_flows == GET_CMDARG_ULL(nDPId_options.max_idle_flows_per_thread))
    {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf)
    {
        workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow_basic;
        switch (flow_basic->state)
        {
            case FS_UNKNOWN:
            case FS_COUNT:

            case FS_SKIPPED:
                break;
            case FS_INFO:
            case FS_FINISHED:
                workflow->total_idle_flows++;
                break;
        }
    }
}

static void process_remaining_flows(void)
{
    for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.reader_thread_count); ++i)
    {
        set_collector_block(&reader_threads[i]);

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
    unsigned long long int total_l4_payload_len = 0;
    unsigned long long int total_flows_skipped = 0;
    unsigned long long int total_flows_captured = 0;
    unsigned long long int total_flows_idle = 0;
    unsigned long long int total_not_detected = 0;
    unsigned long long int total_flows_guessed = 0;
    unsigned long long int total_flows_detected = 0;
    unsigned long long int total_flow_detection_updates = 0;
    unsigned long long int total_flow_updates = 0;

    for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.reader_thread_count); ++i)
    {
        break_pcap_loop(&reader_threads[i]);
    }

    printf("------------------------------------ Stopping reader threads\n");
    for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.reader_thread_count); ++i)
    {
        if (reader_threads[i].workflow == NULL)
        {
            continue;
        }

        if (pthread_join(reader_threads[i].thread, NULL) != 0)
        {
            logger(1, "pthread_join: %s", strerror(errno));
        }
    }

    printf("------------------------------------ Processing remaining flows\n");
    process_remaining_flows();

    printf("------------------------------------ Results\n");
    for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.reader_thread_count); ++i)
    {
        if (reader_threads[i].workflow == NULL)
        {
            continue;
        }

        total_packets_processed += reader_threads[i].workflow->packets_processed;
        total_l4_payload_len += reader_threads[i].workflow->total_l4_payload_len;
        total_flows_skipped += reader_threads[i].workflow->total_skipped_flows;
        total_flows_captured += reader_threads[i].workflow->total_active_flows;
        total_flows_idle += reader_threads[i].workflow->total_idle_flows;
        total_not_detected += reader_threads[i].workflow->total_not_detected_flows;
        total_flows_guessed += reader_threads[i].workflow->total_guessed_flows;
        total_flows_detected += reader_threads[i].workflow->total_detected_flows;
        total_flow_detection_updates += reader_threads[i].workflow->total_flow_detection_updates;
        total_flow_updates += reader_threads[i].workflow->total_flow_updates;

        printf(
            "Stopping Thread %2zu, processed %llu packets, %llu bytes\n"
            "\tskipped flows.....: %8llu, processed flows: %8llu, idle flows....: %8llu\n"
            "\tnot detected flows: %8llu, guessed flows..: %8llu, detected flows: %8llu\n"
            "\tdetection updates.: %8llu, updated flows..: %8llu\n",
            reader_threads[i].array_index,
            reader_threads[i].workflow->packets_processed,
            reader_threads[i].workflow->total_l4_payload_len,
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
    printf("Total packets captured.......: %llu\n",
           (reader_threads[0].workflow != NULL ? reader_threads[0].workflow->packets_captured : 0));
    printf("Total packets processed......: %llu\n", total_packets_processed);
    printf("Total layer4 payload size....: %llu\n", total_l4_payload_len);
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
    for (unsigned long long int i = 0; i < GET_CMDARG_ULL(nDPId_options.reader_thread_count); ++i)
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

    if (MT_GET_AND_ADD(nDPId_main_thread_shutdown, 0) == 0)
    {
        MT_GET_AND_ADD(nDPId_main_thread_shutdown, 1);
    }
}

static void print_subopt_usage(void)
{
    fprintf(stderr, "\tsubopts:\n");
    for (size_t i = 0; i < nDPIsrvd_ARRAY_LENGTH(tuning_config_map); ++i)
    {
        fprintf(stderr, "\t\t%s = %llu\n", tuning_config_map[i].key, tuning_config_map[i].opt->ull.default_value);
    }
}

static void print_usage(char const * const arg0)
{
    static char const usage[] =
        "Usage: %s "
        "[-f config-file]\n"
        "[-i pcap-file/interface] [-I] [-E] [-B bpf-filter]\n"
        "\t  \t"
        "[-l] [-L logfile] [-c address] [-e]"
        "[-d] [-p pidfile]\n"
        "\t  \t"
        "[-u user] [-g group] "
        "[-P path] [-C path] [-J path]\n"
        "\t  \t"
        "[-a instance-alias] [-A]\n"
        "\t \t"
        "[-o subopt=value]\n"
        "\t  \t"
        "[-v] [-h]\n\n"
        "\t-f\tLoad nDPId/libnDPI options from a configuration file.\n"
        "\t-i\tInterface or file from where to read packets from.\n"
#ifdef ENABLE_PFRING
        "\t-r\tUse PFRING to capture packets instead of libpcap.\n"
#endif
        "\t-I\tProcess only packets where the source address of the first packet\n"
        "\t  \tis part of the interface subnet. (Internal mode)\n"
        "\t-E\tProcess only packets where the source address of the first packet\n"
        "\t  \tis *NOT* part of the interface subnet. (External mode)\n"
        "\t-B\tSet an optional PCAP filter string. (BPF format)\n"
        "\t-l\tLog all messages to stderr.\n"
        "\t-L\tLog all messages to a log file.\n"
        "\t-c\tPath to a UNIX socket (nDPIsrvd Collector) or a custom UDP endpoint.\n"
        "\t  \tDefault: %s\n"
        "\t-e\tUse poll() instead of epoll().\n"
        "\t  \tDefault: epoll() on Linux, poll() otherwise\n"
        "\t-d\tFork into background after initialization.\n"
        "\t-p\tWrite the daemon PID to the given file path.\n"
        "\t  \tDefault: %s\n"
        "\t-u\tChange UID to the numeric value of user.\n"
        "\t  \tDefault: %s\n"
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
        "\t-A\tEnable flow analysis aka feature extraction. Requires more memory and cpu usage.\n"
        "\t  \tExperimental, do not rely on those values.\n"
#ifdef ENABLE_ZLIB
        "\t-z\tEnable flow memory zLib compression.\n"
#endif
        "\t-o\t(Carefully) Tune some daemon options. See subopts below.\n"
        "\t-v\tversion\n"
        "\t-h\tthis\n\n";
    fprintf(stderr,
            usage,
            arg0,
            nDPId_options.collector_address.string.default_value,
            nDPId_options.pidfile.string.default_value,
            nDPId_options.user.string.default_value);
}

static void nDPId_print_deps_version(FILE * const out)
{
    fprintf(out,
            "-------------------------------------------------------\n"
#ifdef LIBNDPI_STATIC
            "nDPI version...: %s (statically linked)\n"
#else
            "nDPI version...: %s\n"
#endif
            " API version...: %u\n"
            "pcap version...: %s\n",
            ndpi_revision(),
            ndpi_get_api_version(),
            pcap_lib_version() + strlen("libpcap version "));
    if (ndpi_get_gcrypt_version() != NULL)
    {
        fprintf(out, "gcrypt version.: %s\n", ndpi_get_gcrypt_version());
    }
#ifdef ENABLE_PFRING
    npfring_print_version(out);
#endif
    fprintf(out, "%s", "-------------------------------------------------------\n");
}

static int nDPId_parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "f:i:rIEB:lL:c:edp:u:g:P:C:J:S:a:Azo:vh")) != -1)
    {
        switch (opt)
        {
            case 'f':
                set_cmdarg_string(&nDPId_options.config_file, optarg);
                break;
            case 'i':
                set_cmdarg_string(&nDPId_options.pcap_file_or_interface, optarg);
                break;
            case 'r':
#ifdef ENABLE_PFRING
                set_cmdarg_boolean(&nDPId_options.use_pfring, 1);
                break;
#else
                logger_early(1, "%s", "nDPId was built w/o PFRING support");
                return 1;
#endif
            case 'I':
                set_cmdarg_boolean(&nDPId_options.process_internal_initial_direction, 1);
                break;
            case 'E':
                set_cmdarg_boolean(&nDPId_options.process_external_initial_direction, 1);
                break;
            case 'B':
                set_cmdarg_string(&nDPId_options.bpf_str, optarg);
                break;
            case 'l':
                enable_console_logger();
                break;
            case 'L':
                if (enable_file_logger(optarg) != 0)
                {
                    return 1;
                }
                break;
            case 'c':
                set_cmdarg_string(&nDPId_options.collector_address, optarg);
                break;
            case 'e':
#ifdef ENABLE_EPOLL
                set_cmdarg_boolean(&nDPId_options.use_poll, 1);
#else
                logger_early(1, "%s", "nDPId was built w/o epoll() support, poll() is already the default");
#endif
                break;
            case 'd':
                daemonize_enable();
                break;
            case 'p':
                set_cmdarg_string(&nDPId_options.pidfile, optarg);
                break;
            case 'u':
                set_cmdarg_string(&nDPId_options.user, optarg);
                break;
            case 'g':
                set_cmdarg_string(&nDPId_options.group, optarg);
                break;
            case 'P':
                set_cmdarg_string(&nDPId_options.custom_protocols_file, optarg);
                break;
            case 'C':
                set_cmdarg_string(&nDPId_options.custom_categories_file, optarg);
                break;
            case 'J':
                set_cmdarg_string(&nDPId_options.custom_ja3_file, optarg);
                break;
            case 'S':
                set_cmdarg_string(&nDPId_options.custom_sha1_file, optarg);
                break;
            case 'a':
                set_cmdarg_string(&nDPId_options.instance_alias, optarg);
                break;
            case 'A':
                set_cmdarg_boolean(&nDPId_options.enable_data_analysis, 1);
                break;
            case 'z':
#ifdef ENABLE_ZLIB
                set_cmdarg_boolean(&nDPId_options.enable_zlib_compression, 1);
                break;
#else
                logger_early(1, "%s", "nDPId was built w/o zLib compression");
                return 1;
#endif
            case 'o':
            {
                int errfnd = 0;
                char * subopts = optarg;
                char * value;
                char * subopt_tokens[nDPIsrvd_ARRAY_LENGTH(tuning_config_map) + 1] = {};

                for (size_t i = 0; i < nDPIsrvd_ARRAY_LENGTH(tuning_config_map); ++i)
                {
                    subopt_tokens[i] = strdup(tuning_config_map[i].key);
                }
                while (*subopts != '\0' && errfnd == 0)
                {
                    int subopt = getsubopt(&subopts, subopt_tokens, &value);
                    if (value == NULL && subopt != -1)
                    {
                        logger_early(1, "Missing value for `%s'", subopt_tokens[subopt]);
                        fprintf(stderr, "%s", "\n");
                        print_usage(argv[0]);
                        print_subopt_usage();
                        errfnd = 1;
                        break;
                    }
                    if (subopt == -1)
                    {
                        logger_early(1, "Invalid subopt: %s", value);
                        fprintf(stderr, "%s", "\n");
                        print_usage(argv[0]);
                        print_subopt_usage();
                        errfnd = 1;
                        break;
                    }

                    if (set_config_from(&tuning_config_map[subopt], value) != 0)
                    {
                        logger_early(1, "Could not set subopt: %s", tuning_config_map[subopt].key);
                        errfnd = 1;
                        break;
                    }
                }
                for (size_t i = 0; i < nDPIsrvd_ARRAY_LENGTH(tuning_config_map); ++i)
                {
                    free(subopt_tokens[i]);
                }
                if (errfnd != 0)
                {
                    return 1;
                }
                break;
            }
            case 'v':
                fprintf(stderr, "%s", get_nDPId_version());
                nDPId_print_deps_version(stderr);
                return 1;
            case 'h':
            default:
                fprintf(stderr, "%s\n", get_nDPId_version());
                print_usage(argv[0]);
                print_subopt_usage();
                return 1;
        }
    }

    if (optind < argc)
    {
        logger_early(1, "%s", "Unexpected argument after options");
        fprintf(stderr, "%s", "\n");
        print_usage(argv[0]);
        print_subopt_usage();
        return 1;
    }

    return 0;
}

static int validate_options(void)
{
    int retval = 0;

    if (is_daemonize_enabled() != 0 && is_console_logger_enabled() != 0)
    {
        logger_early(1,
                     "%s",
                     "Daemon mode `-d' and `-l' can not be used together, "
                     "because stdout/stderr is beeing redirected to /dev/null");
        retval = 1;
    }
#ifdef ENABLE_ZLIB
    if (GET_CMDARG_BOOLEAN(nDPId_options.enable_zlib_compression) != 0)
    {
        if (GET_CMDARG_ULL(nDPId_options.compression_flow_inactivity) < TIME_S_TO_US(6u) ||
            GET_CMDARG_ULL(nDPId_options.compression_scan_interval) < TIME_S_TO_US(4u))
        {
            logger_early(1,
                         "Setting compression-scan-interval / compression-flow-inactivity "
                         "to values lower than %llu / %llu are not recommended.",
                         TIME_S_TO_US(4u),
                         TIME_S_TO_US(6u));
            logger_early(1, "%s", "Your CPU usage may increase heavily.");
        }
    }
#endif
    if (nDPIsrvd_setup_address(&nDPId_options.parsed_collector_address,
                               GET_CMDARG_STR(nDPId_options.collector_address)) != 0)
    {
        retval = 1;
        logger_early(1, "Collector socket invalid address: %s.", GET_CMDARG_STR(nDPId_options.collector_address));
    }
    if (IS_CMDARG_SET(nDPId_options.instance_alias) == 0)
    {
        char hname[256];

        errno = 0;
        if (gethostname(hname, sizeof(hname)) != 0)
        {
            logger_early(1, "Could not retrieve your hostname: %s", strerror(errno));
            retval = 1;
        }
        else
        {
            set_cmdarg_string(&nDPId_options.instance_alias, hname);
            logger_early(1,
                         "No instance alias given, using your hostname '%s'",
                         GET_CMDARG_STR(nDPId_options.instance_alias));
            if (IS_CMDARG_SET(nDPId_options.instance_alias) == 0)
            {
                retval = 1;
            }
        }
    }
    if (GET_CMDARG_ULL(nDPId_options.max_flows_per_thread) < 128 ||
        GET_CMDARG_ULL(nDPId_options.max_flows_per_thread) > nDPId_MAX_FLOWS_PER_THREAD)
    {
        logger_early(1,
                     "Value not in range: 128 < max-flows-per-thread[%llu] < %d",
                     GET_CMDARG_ULL(nDPId_options.max_flows_per_thread),
                     nDPId_MAX_FLOWS_PER_THREAD);
        retval = 1;
    }
    if (GET_CMDARG_ULL(nDPId_options.max_idle_flows_per_thread) < 64 ||
        GET_CMDARG_ULL(nDPId_options.max_idle_flows_per_thread) > nDPId_MAX_IDLE_FLOWS_PER_THREAD)
    {
        logger_early(1,
                     "Value not in range: 64 < max-idle-flows-per-thread[%llu] < %d",
                     GET_CMDARG_ULL(nDPId_options.max_idle_flows_per_thread),
                     nDPId_MAX_IDLE_FLOWS_PER_THREAD);
        retval = 1;
    }
    if (GET_CMDARG_ULL(nDPId_options.reader_thread_count) < 1 ||
        GET_CMDARG_ULL(nDPId_options.reader_thread_count) > nDPId_MAX_READER_THREADS)
    {
        logger_early(1,
                     "Value not in range: 1 < reader-thread-count[%llu] < %d",
                     GET_CMDARG_ULL(nDPId_options.reader_thread_count),
                     nDPId_MAX_READER_THREADS);
        retval = 1;
    }
    if (GET_CMDARG_ULL(nDPId_options.flow_scan_interval) < TIME_S_TO_US(5u))
    {
        logger_early(1,
                     "Value not in range: idle-scan-interval[%llu] > %llu",
                     GET_CMDARG_ULL(nDPId_options.flow_scan_interval),
                     TIME_S_TO_US(5u));
        retval = 1;
    }
    if (GET_CMDARG_ULL(nDPId_options.flow_scan_interval) >= GET_CMDARG_ULL(nDPId_options.generic_max_idle_time))
    {
        logger_early(1,
                     "Value not in range: flow-scan-interval[%llu] < generic-max-idle-time[%llu]",
                     GET_CMDARG_ULL(nDPId_options.flow_scan_interval),
                     GET_CMDARG_ULL(nDPId_options.generic_max_idle_time));
        retval = 1;
    }
    if (GET_CMDARG_ULL(nDPId_options.flow_scan_interval) >= GET_CMDARG_ULL(nDPId_options.icmp_max_idle_time))
    {
        logger_early(1,
                     "Value not in range: flow-scan-interval[%llu] < icmp-max-idle-time[%llu]",
                     GET_CMDARG_ULL(nDPId_options.flow_scan_interval),
                     GET_CMDARG_ULL(nDPId_options.icmp_max_idle_time));
        retval = 1;
    }
    if (GET_CMDARG_ULL(nDPId_options.flow_scan_interval) >= GET_CMDARG_ULL(nDPId_options.tcp_max_idle_time))
    {
        logger_early(1,
                     "Value not in range: flow-scan-interval[%llu] < generic-max-idle-time[%llu]",
                     GET_CMDARG_ULL(nDPId_options.flow_scan_interval),
                     GET_CMDARG_ULL(nDPId_options.tcp_max_idle_time));
        retval = 1;
    }
    if (GET_CMDARG_ULL(nDPId_options.flow_scan_interval) >= GET_CMDARG_ULL(nDPId_options.udp_max_idle_time))
    {
        logger_early(1,
                     "Value not in range:flow-scan-interval[%llu] < udp-max-idle-time[%llu]",
                     GET_CMDARG_ULL(nDPId_options.flow_scan_interval),
                     GET_CMDARG_ULL(nDPId_options.udp_max_idle_time));
        retval = 1;
    }
    if (GET_CMDARG_BOOLEAN(nDPId_options.process_internal_initial_direction) != 0 &&
        GET_CMDARG_BOOLEAN(nDPId_options.process_external_initial_direction) != 0)
    {
        logger_early(1, "%s", "Internal and External packet processing does not make sense as this is the default.");
        retval = 1;
    }
    if (GET_CMDARG_BOOLEAN(nDPId_options.process_internal_initial_direction) != 0 ||
        GET_CMDARG_BOOLEAN(nDPId_options.process_external_initial_direction) != 0)
    {
        logger_early(1,
                     "%s",
                     "Internal and External packet processing may lead to incorrect results for flows that were active "
                     "before the daemon started.");
    }
    if (GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_process) < 1 ||
        GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_process) > 65535)
    {
        logger_early(1,
                     "Value not in range: 1 =< max-packets-per-flow-to-process[%llu] =< 65535",
                     GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_process));
        retval = 1;
    }
    if (GET_CMDARG_ULL(nDPId_options.max_packets_per_flow_to_send) > 30)
    {
        logger_early(1, "%s", "Higher values of max-packets-per-flow-to-send may cause superfluous network usage.");
    }

    return retval;
}

static int nDPId_parsed_config_line(
    int lineno, char const * const section, char const * const name, char const * const value, void * const user_data)
{
    (void)user_data;

    if (strnlen(section, INI_MAX_SECTION) == nDPIsrvd_STRLEN_SZ("general") &&
        strncmp(section, "general", INI_MAX_SECTION) == 0)
    {
        size_t i;

        for (i = 0; i < nDPIsrvd_ARRAY_LENGTH(general_config_map); ++i)
        {
            if (strnlen(name, INI_MAX_NAME) == strnlen(general_config_map[i].key, INI_MAX_NAME) &&
                strncmp(name, general_config_map[i].key, INI_MAX_NAME) == 0)
            {
                if (IS_CMDARG_SET(*general_config_map[i].opt) != 0)
                {
                    logger_early(1, "General config key `%s' already set, ignoring value `%s'", name, value);
                }
                else
                {
                    if (set_config_from(&general_config_map[i], value) != 0)
                    {
                        return 0;
                    }
                }
                break;
            }
        }
        if (i == nDPIsrvd_ARRAY_LENGTH(general_config_map))
        {
            logger_early(1, "Invalid general config key `%s' at line %d", name, lineno);
        }
    }
    else if (strnlen(section, INI_MAX_SECTION) == nDPIsrvd_STRLEN_SZ("tuning") &&
             strncmp(section, "tuning", INI_MAX_SECTION) == 0)
    {
        size_t i;

        for (i = 0; i < nDPIsrvd_ARRAY_LENGTH(tuning_config_map); ++i)
        {
            if (strnlen(name, INI_MAX_NAME) == strnlen(tuning_config_map[i].key, INI_MAX_NAME) &&
                strncmp(name, tuning_config_map[i].key, INI_MAX_NAME) == 0)
            {
                if (set_config_from(&tuning_config_map[i], value) != 0)
                {
                    logger_early(
                        1, "Non numeric tuning config value `%s' for key `%s' at line %d", value, name, lineno);
                    return 0;
                }
                break;
            }
        }
        if (i == nDPIsrvd_ARRAY_LENGTH(tuning_config_map))
        {
            logger_early(1, "Invalid tuning config key `%s' at line %d", name, lineno);
        }
    }
    else if ((strnlen(section, INI_MAX_SECTION) == nDPIsrvd_STRLEN_SZ("ndpi") &&
              strncmp(section, "ndpi", INI_MAX_SECTION) == 0) ||
             (strnlen(section, INI_MAX_SECTION) == nDPIsrvd_STRLEN_SZ("protos") &&
              strncmp(section, "protos", INI_MAX_SECTION) == 0))
    {
        // Nothing to do here right now (workflow not initialized yet)
        return 1;
    }
    else
    {
        logger_early(
            1, "Invalid config section `%s' at line %d with key `%s' and value `%s'", section, lineno, name, value);
    }

    return 1;
}

#ifndef NO_MAIN
int main(int argc, char ** argv)
{
    if (argc == 0 || stdout == NULL || stderr == NULL)
    {
        return 1;
    }

    init_logging("nDPId");

    if (nDPId_parse_options(argc, argv) != 0)
    {
        return 1;
    }
    set_config_defaults(&general_config_map[0], nDPIsrvd_ARRAY_LENGTH(general_config_map));
    set_config_defaults(&tuning_config_map[0], nDPIsrvd_ARRAY_LENGTH(tuning_config_map));
    {
        int ret;

        if (IS_CMDARG_SET(nDPId_options.config_file) != 0 &&
            (ret = parse_config_file(GET_CMDARG_STR(nDPId_options.config_file), nDPId_parsed_config_line, NULL)) != 0)
        {
            if (ret > 0)
            {
                logger_early(1, "Config file `%s' is malformed", GET_CMDARG_STR(nDPId_options.config_file));
            }
            else if (ret == -ENOENT)
            {
                logger_early(1, "Path `%s' is not a regular file", GET_CMDARG_STR(nDPId_options.config_file));
            }
            else
            {
                logger_early(1,
                             "Could not open file `%s' for reading: %s",
                             GET_CMDARG_STR(nDPId_options.config_file),
                             strerror(errno));
            }
            return 1;
        }
    }
    if (validate_options() != 0)
    {
        logger_early(1, "%s", "Option validation failed.");
        return 1;
    }

    log_app_info();

    nDPId_print_deps_version(stdout);

    if (NDPI_API_VERSION != ndpi_get_api_version())
    {
        logger_early(1,
                     "Unforeseen Consequences; nDPId was compiled with libnDPI api version %u, but the api version of "
                     "the shared library is: %u.",
                     NDPI_API_VERSION,
                     ndpi_get_api_version());
    }
    if (sizeof(struct ndpi_flow_struct) != ndpi_detection_get_sizeof_ndpi_flow_struct())
    {
        logger_early(1,
                     "FATAL: nDPI flow struct size inconsistent; expected %zu bytes, got %u bytes.",
                     sizeof(struct ndpi_flow_struct),
                     ndpi_detection_get_sizeof_ndpi_flow_struct());
        return 1;
    }

#ifdef ENABLE_MEMORY_PROFILING
    logger_early(0, "size/workflow....: %zu bytes", sizeof(struct nDPId_workflow));
    logger_early(0, "size/flow........: %zu bytes", sizeof(struct nDPId_flow) + sizeof(struct nDPId_detection_data));
    logger_early(0, "size/flow-analyse: %zu bytes", sizeof(struct nDPId_flow_analysis));
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

    while (MT_GET_AND_ADD(nDPId_main_thread_shutdown, 0) == 0 && processing_threads_error_or_eof() == 0)
    {
        sleep(1);
    }

    if (stop_reader_threads() != 0)
    {
        return 1;
    }
    free_reader_threads();

    daemonize_shutdown(GET_CMDARG_STR(nDPId_options.pidfile));
    logger(0, "%s", "Bye.");
    shutdown_logging();

    return 0;
}
#endif
