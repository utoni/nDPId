#include <arpa/inet.h> // ndpi_typedefs.h
#include <errno.h>
#include <signal.h>
#include <stdbool.h> // ndpi_typedefs.h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <ndpi_typedefs.h>

#include "nDPIsrvd.h"
#include "utils.h"

#define DEFAULT_COLLECTD_EXEC_INST "nDPIsrvd"
#define MAX_RISKS_PER_FLOW 8
#define MAX_SEVERITIES_PER_FLOW 4
#define LOGGER_EARLY(is_error, fmt, ...)                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        if (enable_console_logging != 0)                                                                               \
        {                                                                                                              \
            logger_early(is_error, fmt, __VA_ARGS__);                                                                  \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            logger(is_error, fmt, __VA_ARGS__);                                                                        \
        }                                                                                                              \
    } while (0)
// #define GENERATE_TIMESTAMP 1

struct flow_user_data
{
    nDPIsrvd_ull last_flow_src_l4_payload_len;
    nDPIsrvd_ull last_flow_dst_l4_payload_len;
    uint8_t risks[MAX_RISKS_PER_FLOW];
    uint8_t severities[MAX_SEVERITIES_PER_FLOW];
    uint8_t category;
    uint8_t breed;
    uint8_t confidence;
    // "fallthroughs" if we are not in sync with nDPI
    uint8_t risk_ndpid_invalid : 1;
    uint8_t category_ndpid_invalid : 1;
    uint8_t breed_ndpid_invalid : 1;
    uint8_t confidence_ndpid_invalid : 1;
    // detection status
    uint8_t new_seen : 1;
    uint8_t is_detected : 1;
    uint8_t is_guessed : 1;
    uint8_t is_not_detected : 1;
    // flow state
    uint8_t is_info : 1;
    uint8_t is_finished : 1;
    // Layer3 / Layer4
    uint8_t is_ip4 : 1;
    uint8_t is_ip6 : 1;
    uint8_t is_other_l3 : 1;
    uint8_t is_tcp : 1;
    uint8_t is_udp : 1;
    uint8_t is_icmp : 1;
    uint8_t is_other_l4 : 1;
};

static int main_thread_shutdown = 0;
static int collectd_timerfd = -1;
static pid_t collectd_pid;

static int enable_console_logging = 0;
static char * serv_optarg = NULL;
static char * collectd_hostname = NULL;
static char * collectd_interval = NULL;
static char * instance_name = NULL;
static nDPIsrvd_ull collectd_interval_ull = 0uL;

static struct
{
    struct
    {
        uint64_t json_lines;
        uint64_t json_bytes;

        uint64_t flow_new_count;
        uint64_t flow_end_count;
        uint64_t flow_idle_count;
        uint64_t flow_update_count;
        uint64_t flow_analyse_count;
        uint64_t flow_guessed_count;
        uint64_t flow_detected_count;
        uint64_t flow_detection_update_count;
        uint64_t flow_not_detected_count;

        uint64_t packet_count;
        uint64_t packet_flow_count;

        uint64_t init_count;
        uint64_t reconnect_count;
        uint64_t shutdown_count;
        uint64_t status_count;

        uint64_t error_unknown_datalink;
        uint64_t error_unknown_l3_protocol;
        uint64_t error_unsupported_datalink;
        uint64_t error_packet_too_short;
        uint64_t error_packet_type_unknown;
        uint64_t error_packet_header_invalid;
        uint64_t error_ip4_packet_too_short;
        uint64_t error_ip4_size_smaller_than_header;
        uint64_t error_ip4_l4_payload_detection;
        uint64_t error_ip6_packet_too_short;
        uint64_t error_ip6_size_smaller_than_header;
        uint64_t error_ip6_l4_payload_detection;
        uint64_t error_tcp_packet_too_short;
        uint64_t error_udp_packet_too_short;
        uint64_t error_capture_size_smaller_than_packet;
        uint64_t error_max_flows_to_track;
        uint64_t error_flow_memory_alloc;

        uint64_t flow_src_total_bytes;
        uint64_t flow_dst_total_bytes;
        uint64_t flow_risky_count;
    } counters;

    struct
    {
        uint64_t flow_state_info;
        uint64_t flow_state_finished;

        uint64_t flow_breed_safe_count;
        uint64_t flow_breed_acceptable_count;
        uint64_t flow_breed_fun_count;
        uint64_t flow_breed_unsafe_count;
        uint64_t flow_breed_potentially_dangerous_count;
        uint64_t flow_breed_tracker_ads_count;
        uint64_t flow_breed_dangerous_count;
        uint64_t flow_breed_unrated_count;
        uint64_t flow_breed_unknown_count;

        uint64_t flow_category_unspecified_count;
        uint64_t flow_category_media_count;
        uint64_t flow_category_vpn_count;
        uint64_t flow_category_email_count;
        uint64_t flow_category_data_transfer_count;
        uint64_t flow_category_web_count;
        uint64_t flow_category_social_network_count;
        uint64_t flow_category_download_count;
        uint64_t flow_category_game_count;
        uint64_t flow_category_chat_count;
        uint64_t flow_category_voip_count;
        uint64_t flow_category_database_count;
        uint64_t flow_category_remote_access_count;
        uint64_t flow_category_cloud_count;
        uint64_t flow_category_network_count;
        uint64_t flow_category_collaborative_count;
        uint64_t flow_category_rpc_count;
        uint64_t flow_category_streaming_count;
        uint64_t flow_category_system_count;
        uint64_t flow_category_software_update_count;
        uint64_t flow_category_music_count;
        uint64_t flow_category_video_count;
        uint64_t flow_category_shopping_count;
        uint64_t flow_category_productivity_count;
        uint64_t flow_category_file_sharing_count;
        uint64_t flow_category_conn_check_count;
        uint64_t flow_category_iot_scada_count;
        uint64_t flow_category_virt_assistant_count;
        uint64_t flow_category_cybersecurity_count;
        uint64_t flow_category_adult_content_count;
        uint64_t flow_category_mining_count;
        uint64_t flow_category_malware_count;
        uint64_t flow_category_advertisment_count;
        uint64_t flow_category_banned_site_count;
        uint64_t flow_category_site_unavail_count;
        uint64_t flow_category_allowed_site_count;
        uint64_t flow_category_antimalware_count;
        uint64_t flow_category_crypto_currency_count;
        uint64_t flow_category_gambling_count;
        uint64_t flow_category_unknown_count;

        uint64_t flow_confidence_by_port;
        uint64_t flow_confidence_dpi_partial;
        uint64_t flow_confidence_dpi_partial_cache;
        uint64_t flow_confidence_dpi_cache;
        uint64_t flow_confidence_dpi;
        uint64_t flow_confidence_nbpf;
        uint64_t flow_confidence_by_ip;
        uint64_t flow_confidence_dpi_aggressive;
        uint64_t flow_confidence_custom_rule;
        uint64_t flow_confidence_unknown;

        uint64_t flow_severity_low;
        uint64_t flow_severity_medium;
        uint64_t flow_severity_high;
        uint64_t flow_severity_severe;
        uint64_t flow_severity_critical;
        uint64_t flow_severity_emergency;
        uint64_t flow_severity_unknown;

        uint64_t flow_l3_ip4_count;
        uint64_t flow_l3_ip6_count;
        uint64_t flow_l3_other_count;

        uint64_t flow_l4_tcp_count;
        uint64_t flow_l4_udp_count;
        uint64_t flow_l4_icmp_count;
        uint64_t flow_l4_other_count;

        uint64_t flow_active_count;
        uint64_t flow_detected_count;
        uint64_t flow_guessed_count;
        uint64_t flow_not_detected_count;

        nDPIsrvd_ull flow_risk_count[NDPI_MAX_RISK - 1 /* NDPI_NO_RISK */];
        nDPIsrvd_ull flow_risk_unknown_count;
    } gauges[2]; /* values after InfluxDB push: gauges[0] -= gauges[1], gauges[1] is zero'd afterwards */
} collectd_statistics = {};

struct global_map
{
    char const * const json_key;
    struct
    {
        uint64_t * const global_stat_inc;
        uint64_t * const global_stat_dec;
    };
};

#define COLLECTD_STATS_COUNTER_PTR(member)                                                                             \
    {                                                                                                                  \
        .global_stat_inc = &(collectd_statistics.counters.member), NULL                                                \
    }
#define COLLECTD_STATS_GAUGE_PTR(member)                                                                               \
    {                                                                                                                  \
        .global_stat_inc = &(collectd_statistics.gauges[0].member),                                                    \
        .global_stat_dec = &(collectd_statistics.gauges[1].member)                                                     \
    }
#define COLLECTD_STATS_COUNTER_INC(member) (collectd_statistics.counters.member++)
#define COLLECTD_STATS_GAUGE_RES(member) (collectd_statistics.gauges[0].member--)
#define COLLECTD_STATS_GAUGE_INC(member) (collectd_statistics.gauges[0].member++)
#define COLLECTD_STATS_GAUGE_DEC(member) (collectd_statistics.gauges[1].member++)
#define COLLECTD_STATS_GAUGE_SUB(member) (collectd_statistics.gauges[0].member -= collectd_statistics.gauges[1].member)
#define COLLECTD_STATS_MAP_NOTNULL(map, index) (map[index - 1].global_stat_dec != NULL)
#define COLLECTD_STATS_MAP_DEC(map, index) ((*map[index - 1].global_stat_dec)++)

static struct global_map const flow_event_map[] = {{"new", COLLECTD_STATS_COUNTER_PTR(flow_new_count)},
                                                   {"end", COLLECTD_STATS_COUNTER_PTR(flow_end_count)},
                                                   {"idle", COLLECTD_STATS_COUNTER_PTR(flow_idle_count)},
                                                   {"update", COLLECTD_STATS_COUNTER_PTR(flow_update_count)},
                                                   {"analyse", COLLECTD_STATS_COUNTER_PTR(flow_analyse_count)},
                                                   {"guessed", COLLECTD_STATS_COUNTER_PTR(flow_guessed_count)},
                                                   {"detected", COLLECTD_STATS_COUNTER_PTR(flow_detected_count)},
                                                   {"detection-update",
                                                    COLLECTD_STATS_COUNTER_PTR(flow_detection_update_count)},
                                                   {"not-detected",
                                                    COLLECTD_STATS_COUNTER_PTR(flow_not_detected_count)}};

static struct global_map const packet_event_map[] = {{"packet", COLLECTD_STATS_COUNTER_PTR(packet_count)},
                                                     {"packet-flow", COLLECTD_STATS_COUNTER_PTR(packet_flow_count)}};

static struct global_map const daemon_event_map[] = {{"init", COLLECTD_STATS_COUNTER_PTR(init_count)},
                                                     {"reconnect", COLLECTD_STATS_COUNTER_PTR(reconnect_count)},
                                                     {"shutdown", COLLECTD_STATS_COUNTER_PTR(shutdown_count)},
                                                     {"status", COLLECTD_STATS_COUNTER_PTR(status_count)}};

static struct global_map const error_event_map[] = {
    {"Unknown datalink layer packet", COLLECTD_STATS_COUNTER_PTR(error_unknown_datalink)},
    {"Unknown L3 protocol", COLLECTD_STATS_COUNTER_PTR(error_unknown_l3_protocol)},
    {"Unsupported datalink layer", COLLECTD_STATS_COUNTER_PTR(error_unsupported_datalink)},
    {"Packet too short", COLLECTD_STATS_COUNTER_PTR(error_packet_too_short)},
    {"Unknown packet type", COLLECTD_STATS_COUNTER_PTR(error_packet_type_unknown)},
    {"Packet header invalid", COLLECTD_STATS_COUNTER_PTR(error_packet_header_invalid)},
    {"IP4 packet too short", COLLECTD_STATS_COUNTER_PTR(error_ip4_packet_too_short)},
    {"Packet smaller than IP4 header", COLLECTD_STATS_COUNTER_PTR(error_ip4_size_smaller_than_header)},
    {"nDPI IPv4\\/L4 payload detection failed", COLLECTD_STATS_COUNTER_PTR(error_ip4_l4_payload_detection)},
    {"IP6 packet too short", COLLECTD_STATS_COUNTER_PTR(error_ip6_packet_too_short)},
    {"Packet smaller than IP6 header", COLLECTD_STATS_COUNTER_PTR(error_ip6_size_smaller_than_header)},
    {"nDPI IPv6\\/L4 payload detection failed", COLLECTD_STATS_COUNTER_PTR(error_ip6_l4_payload_detection)},
    {"TCP packet smaller than expected", COLLECTD_STATS_COUNTER_PTR(error_tcp_packet_too_short)},
    {"UDP packet smaller than expected", COLLECTD_STATS_COUNTER_PTR(error_udp_packet_too_short)},
    {"Captured packet size is smaller than expected packet size",
     COLLECTD_STATS_COUNTER_PTR(error_capture_size_smaller_than_packet)},
    {"Max flows to track reached", COLLECTD_STATS_COUNTER_PTR(error_max_flows_to_track)},
    {"Flow memory allocation failed", COLLECTD_STATS_COUNTER_PTR(error_flow_memory_alloc)}};

static struct global_map const breeds_map[] = {{"Safe", COLLECTD_STATS_GAUGE_PTR(flow_breed_safe_count)},
                                               {"Acceptable", COLLECTD_STATS_GAUGE_PTR(flow_breed_acceptable_count)},
                                               {"Fun", COLLECTD_STATS_GAUGE_PTR(flow_breed_fun_count)},
                                               {"Unsafe", COLLECTD_STATS_GAUGE_PTR(flow_breed_unsafe_count)},
                                               {"Potentially Dangerous",
                                                COLLECTD_STATS_GAUGE_PTR(flow_breed_potentially_dangerous_count)},
                                               {"Tracker\\/Ads",
                                                COLLECTD_STATS_GAUGE_PTR(flow_breed_tracker_ads_count)},
                                               {"Dangerous", COLLECTD_STATS_GAUGE_PTR(flow_breed_dangerous_count)},
                                               {"Unrated", COLLECTD_STATS_GAUGE_PTR(flow_breed_unrated_count)},
                                               {NULL, COLLECTD_STATS_GAUGE_PTR(flow_breed_unknown_count)}};

static struct global_map const categories_map[] = {
    {"Unspecified", COLLECTD_STATS_GAUGE_PTR(flow_category_unspecified_count)},
    {"Media", COLLECTD_STATS_GAUGE_PTR(flow_category_media_count)},
    {"VPN", COLLECTD_STATS_GAUGE_PTR(flow_category_vpn_count)},
    {"Email", COLLECTD_STATS_GAUGE_PTR(flow_category_email_count)},
    {"DataTransfer", COLLECTD_STATS_GAUGE_PTR(flow_category_data_transfer_count)},
    {"Web", COLLECTD_STATS_GAUGE_PTR(flow_category_web_count)},
    {"SocialNetwork", COLLECTD_STATS_GAUGE_PTR(flow_category_social_network_count)},
    {"Download", COLLECTD_STATS_GAUGE_PTR(flow_category_download_count)},
    {"Game", COLLECTD_STATS_GAUGE_PTR(flow_category_game_count)},
    {"Chat", COLLECTD_STATS_GAUGE_PTR(flow_category_chat_count)},
    {"VoIP", COLLECTD_STATS_GAUGE_PTR(flow_category_voip_count)},
    {"Database", COLLECTD_STATS_GAUGE_PTR(flow_category_database_count)},
    {"RemoteAccess", COLLECTD_STATS_GAUGE_PTR(flow_category_remote_access_count)},
    {"Cloud", COLLECTD_STATS_GAUGE_PTR(flow_category_cloud_count)},
    {"Network", COLLECTD_STATS_GAUGE_PTR(flow_category_network_count)},
    {"Collaborative", COLLECTD_STATS_GAUGE_PTR(flow_category_collaborative_count)},
    {"RPC", COLLECTD_STATS_GAUGE_PTR(flow_category_rpc_count)},
    {"Streaming", COLLECTD_STATS_GAUGE_PTR(flow_category_streaming_count)},
    {"System", COLLECTD_STATS_GAUGE_PTR(flow_category_system_count)},
    {"SoftwareUpdate", COLLECTD_STATS_GAUGE_PTR(flow_category_software_update_count)},
    {"Music", COLLECTD_STATS_GAUGE_PTR(flow_category_music_count)},
    {"Video", COLLECTD_STATS_GAUGE_PTR(flow_category_video_count)},
    {"Shopping", COLLECTD_STATS_GAUGE_PTR(flow_category_shopping_count)},
    {"Productivity", COLLECTD_STATS_GAUGE_PTR(flow_category_productivity_count)},
    {"FileSharing", COLLECTD_STATS_GAUGE_PTR(flow_category_file_sharing_count)},
    {"ConnCheck", COLLECTD_STATS_GAUGE_PTR(flow_category_conn_check_count)},
    {"IoT-Scada", COLLECTD_STATS_GAUGE_PTR(flow_category_iot_scada_count)},
    {"VirtAssistant", COLLECTD_STATS_GAUGE_PTR(flow_category_virt_assistant_count)},
    {"Cybersecurity", COLLECTD_STATS_GAUGE_PTR(flow_category_cybersecurity_count)},
    {"AdultContent", COLLECTD_STATS_GAUGE_PTR(flow_category_adult_content_count)},
    {"Mining", COLLECTD_STATS_GAUGE_PTR(flow_category_mining_count)},
    {"Malware", COLLECTD_STATS_GAUGE_PTR(flow_category_malware_count)},
    {"Advertisement", COLLECTD_STATS_GAUGE_PTR(flow_category_advertisment_count)},
    {"Banned_Site", COLLECTD_STATS_GAUGE_PTR(flow_category_banned_site_count)},
    {"Site_Unavailable", COLLECTD_STATS_GAUGE_PTR(flow_category_site_unavail_count)},
    {"Allowed_Site", COLLECTD_STATS_GAUGE_PTR(flow_category_allowed_site_count)},
    {"Antimalware", COLLECTD_STATS_GAUGE_PTR(flow_category_antimalware_count)},
    {"Crypto_Currency", COLLECTD_STATS_GAUGE_PTR(flow_category_crypto_currency_count)},
    {"Gambling", COLLECTD_STATS_GAUGE_PTR(flow_category_gambling_count)},
    {NULL, COLLECTD_STATS_GAUGE_PTR(flow_category_unknown_count)}};

static struct global_map const confidence_map[] = {
    {"Match by port", COLLECTD_STATS_GAUGE_PTR(flow_confidence_by_port)},
    {"DPI (partial)", COLLECTD_STATS_GAUGE_PTR(flow_confidence_dpi_partial)},
    {"DPI (partial cache)", COLLECTD_STATS_GAUGE_PTR(flow_confidence_dpi_partial_cache)},
    {"DPI (cache)", COLLECTD_STATS_GAUGE_PTR(flow_confidence_dpi_cache)},
    {"DPI", COLLECTD_STATS_GAUGE_PTR(flow_confidence_dpi)},
    {"nBPF", COLLECTD_STATS_GAUGE_PTR(flow_confidence_nbpf)},
    {"Match by IP", COLLECTD_STATS_GAUGE_PTR(flow_confidence_by_ip)},
    {"DPI (aggressive)", COLLECTD_STATS_GAUGE_PTR(flow_confidence_dpi_aggressive)},
    {"Match by custom rule", COLLECTD_STATS_GAUGE_PTR(flow_confidence_custom_rule)},
    {NULL, COLLECTD_STATS_GAUGE_PTR(flow_confidence_unknown)}};

static struct global_map const severity_map[] = {{"Low", COLLECTD_STATS_GAUGE_PTR(flow_severity_low)},
                                                 {"Medium", COLLECTD_STATS_GAUGE_PTR(flow_severity_medium)},
                                                 {"High", COLLECTD_STATS_GAUGE_PTR(flow_severity_high)},
                                                 {"Severe", COLLECTD_STATS_GAUGE_PTR(flow_severity_severe)},
                                                 {"Critical", COLLECTD_STATS_GAUGE_PTR(flow_severity_critical)},
                                                 {"Emergency", COLLECTD_STATS_GAUGE_PTR(flow_severity_emergency)},
                                                 {NULL, COLLECTD_STATS_GAUGE_PTR(flow_severity_unknown)}};

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

static int set_collectd_timer(void)
{
    const time_t interval = collectd_interval_ull * 1000;
    struct itimerspec its;
    its.it_value.tv_sec = interval / 1000;
    its.it_value.tv_nsec = (interval % 1000) * 1000000;
    its.it_interval.tv_nsec = 0;
    its.it_interval.tv_sec = 0;

    errno = 0;
    return timerfd_settime(collectd_timerfd, 0, &its, NULL);
}

static int create_collectd_timer(void)
{
    collectd_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (collectd_timerfd < 0)
    {
        return 1;
    }

    return set_collectd_timer();
}

static void sighandler(int signum)
{
    logger(0, "Received SIGNAL %d", signum);

    if (main_thread_shutdown == 0)
    {
        logger(0, "%s", "Shutting down ..");
        main_thread_shutdown = 1;
    }
}

static int parse_options(int argc, char ** argv, struct nDPIsrvd_socket * const sock)
{
    int opt;

    static char const usage[] =
        "Usage: %s "
        "[-l] [-s host] [-c hostname] [-n collectd-instance-name] [-i interval]\n\n"
        "\t-l\tLog to console instead of syslog.\n"
        "\t-s\tDestination where nDPIsrvd is listening on.\n"
        "\t-c\tCollectd hostname.\n"
        "\t  \tThis value defaults to the environment variable COLLECTD_HOSTNAME.\n"
        "\t-n\tName of the collectd(-exec) instance.\n"
        "\t  \tDefaults to: " DEFAULT_COLLECTD_EXEC_INST
        "\n"
        "\t-i\tInterval between print statistics to stdout.\n"
        "\t  \tThis value defaults to the environment variable COLLECTD_INTERVAL.\n\n";

    while ((opt = getopt(argc, argv, "hls:c:n:i:")) != -1)
    {
        switch (opt)
        {
            case 'l':
                enable_console_logging = 1;
                break;
            case 's':
                free(serv_optarg);
                serv_optarg = strdup(optarg);
                break;
            case 'c':
                free(collectd_hostname);
                collectd_hostname = strdup(optarg);
                break;
            case 'n':
                free(instance_name);
                instance_name = strdup(optarg);
                break;
            case 'i':
                free(collectd_interval);
                collectd_interval = strdup(optarg);
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

    if (collectd_hostname == NULL)
    {
        collectd_hostname = getenv("COLLECTD_HOSTNAME");
        if (collectd_hostname == NULL)
        {
            collectd_hostname = strdup("localhost");
        }
        else
        {
            enable_console_logging = 0;
        }
    }

    if (instance_name == NULL)
    {
        instance_name = strdup(DEFAULT_COLLECTD_EXEC_INST);
    }

    if (collectd_interval == NULL)
    {
        collectd_interval = getenv("COLLECTD_INTERVAL");
        if (collectd_interval == NULL)
        {
            collectd_interval = strdup("60");
        }
        else
        {
            enable_console_logging = 0;
        }
    }

    if (enable_console_logging != 0)
    {
        enable_console_logger();
    }

    if (str_value_to_ull(collectd_interval, &collectd_interval_ull) != CONVERSION_OK)
    {
        LOGGER_EARLY(1, "Collectd interval `%s' is not a valid number", collectd_interval);
        return 1;
    }

    if (nDPIsrvd_setup_address(&sock->address, serv_optarg) != 0)
    {
        LOGGER_EARLY(1, "Could not parse address `%s'", serv_optarg);
        return 1;
    }

    if (optind < argc)
    {
        LOGGER_EARLY(1, "%s", "Unexpected argument after options");
        LOGGER_EARLY(1, "%s", "");
        LOGGER_EARLY(1, usage, argv[0]);
        return 1;
    }

    return 0;
}

#ifdef GENERATE_TIMESTAMP
#define COLLECTD_COUNTER_PREFIX "PUTVAL \"%s/exec-%s/counter-"
#define COLLECTD_COUNTER_SUFFIX "\" interval=%llu %llu:%llu\n"
#define COLLECTD_COUNTER_N(value)                                                                                      \
    collectd_hostname, instance_name, #value, collectd_interval_ull, (unsigned long long int)now,                      \
        (unsigned long long int)collectd_statistics.value
#define COLLECTD_COUNTER_N2(name, value)                                                                               \
    collectd_hostname, instance_name, name, collectd_interval_ull, (unsigned long long int)now,                        \
        (unsigned long long int)collectd_statistics.value

#define COLLECTD_GAUGE_PREFIX "PUTVAL \"%s/exec-%s/gauge-"
#define COLLECTD_GAUGE_SUFFIX "\" interval=%llu %llu:%llu\n"
#define COLLECTD_GAUGE_N(value)                                                                                        \
    collectd_hostname, instance_name, #value, collectd_interval_ull, (unsigned long long int)now,                      \
        (unsigned long long int)collectd_statistics.value
#define COLLECTD_GAUGE_N2(name, value)                                                                                 \
    collectd_hostname, instance_name, name, collectd_interval_ull, (unsigned long long int)now,                        \
        (unsigned long long int)collectd_statistics.value
#else
#define COLLECTD_COUNTER_PREFIX "PUTVAL \"%s/exec-%s/counter-"
#define COLLECTD_COUNTER_SUFFIX "\" interval=%llu N:%llu\n"
#define COLLECTD_COUNTER_N(value)                                                                                      \
    collectd_hostname, instance_name, #value, collectd_interval_ull,                                                   \
        (unsigned long long int)collectd_statistics.counters.value
#define COLLECTD_COUNTER_N2(name, value)                                                                               \
    collectd_hostname, instance_name, name, collectd_interval_ull,                                                     \
        (unsigned long long int)collectd_statistics.counters.value

#define COLLECTD_GAUGE_PREFIX "PUTVAL \"%s/exec-%s/gauge-"
#define COLLECTD_GAUGE_SUFFIX "\" interval=%llu N:%llu\n"
#define COLLECTD_GAUGE_N(value)                                                                                        \
    collectd_hostname, instance_name, #value, collectd_interval_ull,                                                   \
        (unsigned long long int)collectd_statistics.gauges[0].value
#define COLLECTD_GAUGE_N2(name, value)                                                                                 \
    collectd_hostname, instance_name, name, collectd_interval_ull,                                                     \
        (unsigned long long int)collectd_statistics.gauges[0].value
#endif

#define COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_PREFIX "%s" COLLECTD_COUNTER_SUFFIX
#define COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_PREFIX "%s" COLLECTD_GAUGE_SUFFIX
static void print_collectd_exec_output(void)
{
    size_t i;
#ifdef GENERATE_TIMESTAMP
    time_t now = time(NULL);
#endif

    printf(COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
               COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                   COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                       COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                           COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                               COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                                   COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                                       COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                                           COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                                               COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                                                   COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                                                       COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                                                           COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                                                               COLLECTD_COUNTER_N_FORMAT() COLLECTD_COUNTER_N_FORMAT()
                                                                   COLLECTD_COUNTER_N_FORMAT()
                                                                       COLLECTD_COUNTER_N_FORMAT(),

           COLLECTD_COUNTER_N(json_lines),
           COLLECTD_COUNTER_N(json_bytes),
           COLLECTD_COUNTER_N(flow_new_count),
           COLLECTD_COUNTER_N(flow_end_count),
           COLLECTD_COUNTER_N(flow_idle_count),
           COLLECTD_COUNTER_N(flow_update_count),
           COLLECTD_COUNTER_N(flow_analyse_count),
           COLLECTD_COUNTER_N(flow_guessed_count),
           COLLECTD_COUNTER_N(flow_detected_count),
           COLLECTD_COUNTER_N(flow_detection_update_count),
           COLLECTD_COUNTER_N(flow_not_detected_count),
           COLLECTD_COUNTER_N(flow_src_total_bytes),
           COLLECTD_COUNTER_N(flow_dst_total_bytes),
           COLLECTD_COUNTER_N(flow_risky_count),
           COLLECTD_COUNTER_N(packet_count),
           COLLECTD_COUNTER_N(packet_flow_count),
           COLLECTD_COUNTER_N(init_count),
           COLLECTD_COUNTER_N(reconnect_count),
           COLLECTD_COUNTER_N(shutdown_count),
           COLLECTD_COUNTER_N(status_count),
           COLLECTD_COUNTER_N(error_unknown_datalink),
           COLLECTD_COUNTER_N(error_unknown_l3_protocol),
           COLLECTD_COUNTER_N(error_unsupported_datalink),
           COLLECTD_COUNTER_N(error_packet_too_short),
           COLLECTD_COUNTER_N(error_packet_type_unknown),
           COLLECTD_COUNTER_N(error_packet_header_invalid),
           COLLECTD_COUNTER_N(error_ip4_packet_too_short),
           COLLECTD_COUNTER_N(error_ip4_size_smaller_than_header),
           COLLECTD_COUNTER_N(error_ip4_l4_payload_detection),
           COLLECTD_COUNTER_N(error_ip6_packet_too_short),
           COLLECTD_COUNTER_N(error_ip6_size_smaller_than_header),
           COLLECTD_COUNTER_N(error_ip6_l4_payload_detection),
           COLLECTD_COUNTER_N(error_tcp_packet_too_short),
           COLLECTD_COUNTER_N(error_udp_packet_too_short),
           COLLECTD_COUNTER_N(error_capture_size_smaller_than_packet),
           COLLECTD_COUNTER_N(error_max_flows_to_track),
           COLLECTD_COUNTER_N(error_flow_memory_alloc));

    printf(COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
               COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                   COLLECTD_GAUGE_N_FORMAT(),

           COLLECTD_GAUGE_N(flow_breed_safe_count),
           COLLECTD_GAUGE_N(flow_breed_acceptable_count),
           COLLECTD_GAUGE_N(flow_breed_fun_count),
           COLLECTD_GAUGE_N(flow_breed_unsafe_count),
           COLLECTD_GAUGE_N(flow_breed_potentially_dangerous_count),
           COLLECTD_GAUGE_N(flow_breed_tracker_ads_count),
           COLLECTD_GAUGE_N(flow_breed_dangerous_count),
           COLLECTD_GAUGE_N(flow_breed_unrated_count),
           COLLECTD_GAUGE_N(flow_breed_unknown_count));

    printf(COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
               COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                   COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                       COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                           COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                               COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                                   COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                                       COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                                           COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                                               COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                                                   COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                                                       COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                                                           COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                                                               COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                                                                   COLLECTD_GAUGE_N_FORMAT(),

           COLLECTD_GAUGE_N(flow_category_unspecified_count),
           COLLECTD_GAUGE_N(flow_category_media_count),
           COLLECTD_GAUGE_N(flow_category_vpn_count),
           COLLECTD_GAUGE_N(flow_category_email_count),
           COLLECTD_GAUGE_N(flow_category_data_transfer_count),
           COLLECTD_GAUGE_N(flow_category_web_count),
           COLLECTD_GAUGE_N(flow_category_social_network_count),
           COLLECTD_GAUGE_N(flow_category_download_count),
           COLLECTD_GAUGE_N(flow_category_game_count),
           COLLECTD_GAUGE_N(flow_category_chat_count),
           COLLECTD_GAUGE_N(flow_category_voip_count),
           COLLECTD_GAUGE_N(flow_category_database_count),
           COLLECTD_GAUGE_N(flow_category_remote_access_count),
           COLLECTD_GAUGE_N(flow_category_cloud_count),
           COLLECTD_GAUGE_N(flow_category_network_count),
           COLLECTD_GAUGE_N(flow_category_collaborative_count),
           COLLECTD_GAUGE_N(flow_category_rpc_count),
           COLLECTD_GAUGE_N(flow_category_streaming_count),
           COLLECTD_GAUGE_N(flow_category_system_count),
           COLLECTD_GAUGE_N(flow_category_software_update_count),
           COLLECTD_GAUGE_N(flow_category_music_count),
           COLLECTD_GAUGE_N(flow_category_video_count),
           COLLECTD_GAUGE_N(flow_category_shopping_count),
           COLLECTD_GAUGE_N(flow_category_productivity_count),
           COLLECTD_GAUGE_N(flow_category_file_sharing_count),
           COLLECTD_GAUGE_N(flow_category_conn_check_count),
           COLLECTD_GAUGE_N(flow_category_iot_scada_count),
           COLLECTD_GAUGE_N(flow_category_virt_assistant_count),
           COLLECTD_GAUGE_N(flow_category_cybersecurity_count),
           COLLECTD_GAUGE_N(flow_category_adult_content_count),
           COLLECTD_GAUGE_N(flow_category_mining_count),
           COLLECTD_GAUGE_N(flow_category_malware_count),
           COLLECTD_GAUGE_N(flow_category_advertisment_count),
           COLLECTD_GAUGE_N(flow_category_banned_site_count),
           COLLECTD_GAUGE_N(flow_category_site_unavail_count),
           COLLECTD_GAUGE_N(flow_category_allowed_site_count),
           COLLECTD_GAUGE_N(flow_category_antimalware_count),
           COLLECTD_GAUGE_N(flow_category_crypto_currency_count),
           COLLECTD_GAUGE_N(flow_category_gambling_count),
           COLLECTD_GAUGE_N(flow_category_unknown_count));

    printf(COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
               COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
                   COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT(),

           COLLECTD_GAUGE_N(flow_confidence_by_port),
           COLLECTD_GAUGE_N(flow_confidence_dpi_partial),
           COLLECTD_GAUGE_N(flow_confidence_dpi_partial_cache),
           COLLECTD_GAUGE_N(flow_confidence_dpi_cache),
           COLLECTD_GAUGE_N(flow_confidence_dpi),
           COLLECTD_GAUGE_N(flow_confidence_nbpf),
           COLLECTD_GAUGE_N(flow_confidence_by_ip),
           COLLECTD_GAUGE_N(flow_confidence_dpi_aggressive),
           COLLECTD_GAUGE_N(flow_confidence_custom_rule),
           COLLECTD_GAUGE_N(flow_confidence_unknown));

    printf(COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
               COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT(),

           COLLECTD_GAUGE_N(flow_severity_low),
           COLLECTD_GAUGE_N(flow_severity_medium),
           COLLECTD_GAUGE_N(flow_severity_high),
           COLLECTD_GAUGE_N(flow_severity_severe),
           COLLECTD_GAUGE_N(flow_severity_critical),
           COLLECTD_GAUGE_N(flow_severity_emergency),
           COLLECTD_GAUGE_N(flow_severity_unknown));

    printf(COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT()
               COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT(),

           COLLECTD_GAUGE_N(flow_l3_ip4_count),
           COLLECTD_GAUGE_N(flow_l3_ip6_count),
           COLLECTD_GAUGE_N(flow_l3_other_count),
           COLLECTD_GAUGE_N(flow_l4_tcp_count),
           COLLECTD_GAUGE_N(flow_l4_udp_count),
           COLLECTD_GAUGE_N(flow_l4_icmp_count),
           COLLECTD_GAUGE_N(flow_l4_other_count),
           COLLECTD_GAUGE_N(flow_risk_unknown_count));

    printf(COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT() COLLECTD_GAUGE_N_FORMAT(),
           COLLECTD_GAUGE_N(flow_active_count),
           COLLECTD_GAUGE_N(flow_detected_count),
           COLLECTD_GAUGE_N(flow_guessed_count),
           COLLECTD_GAUGE_N(flow_not_detected_count));

    for (i = 0; i < NDPI_MAX_RISK - 1 /* NDPI_NO_RISK */; ++i)
    {
        char gauge_name[BUFSIZ];
        snprintf(gauge_name, sizeof(gauge_name), "flow_risk_%zu_count", i + 1);
        printf(COLLECTD_GAUGE_N_FORMAT(), COLLECTD_GAUGE_N2(gauge_name, flow_risk_count[i]));
    }

    COLLECTD_STATS_GAUGE_SUB(flow_state_info);
    COLLECTD_STATS_GAUGE_SUB(flow_state_finished);

    COLLECTD_STATS_GAUGE_SUB(flow_breed_safe_count);
    COLLECTD_STATS_GAUGE_SUB(flow_breed_acceptable_count);
    COLLECTD_STATS_GAUGE_SUB(flow_breed_fun_count);
    COLLECTD_STATS_GAUGE_SUB(flow_breed_unsafe_count);
    COLLECTD_STATS_GAUGE_SUB(flow_breed_potentially_dangerous_count);
    COLLECTD_STATS_GAUGE_SUB(flow_breed_tracker_ads_count);
    COLLECTD_STATS_GAUGE_SUB(flow_breed_dangerous_count);
    COLLECTD_STATS_GAUGE_SUB(flow_breed_unrated_count);
    COLLECTD_STATS_GAUGE_SUB(flow_breed_unknown_count);

    COLLECTD_STATS_GAUGE_SUB(flow_category_unspecified_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_media_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_vpn_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_email_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_data_transfer_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_web_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_social_network_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_download_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_game_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_chat_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_voip_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_database_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_remote_access_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_cloud_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_network_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_collaborative_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_rpc_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_streaming_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_system_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_software_update_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_music_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_video_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_shopping_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_productivity_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_file_sharing_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_conn_check_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_iot_scada_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_virt_assistant_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_cybersecurity_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_adult_content_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_mining_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_malware_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_advertisment_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_banned_site_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_site_unavail_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_allowed_site_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_antimalware_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_crypto_currency_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_gambling_count);
    COLLECTD_STATS_GAUGE_SUB(flow_category_unknown_count);

    COLLECTD_STATS_GAUGE_SUB(flow_confidence_by_port);
    COLLECTD_STATS_GAUGE_SUB(flow_confidence_dpi_partial);
    COLLECTD_STATS_GAUGE_SUB(flow_confidence_dpi_partial_cache);
    COLLECTD_STATS_GAUGE_SUB(flow_confidence_dpi_cache);
    COLLECTD_STATS_GAUGE_SUB(flow_confidence_dpi);
    COLLECTD_STATS_GAUGE_SUB(flow_confidence_nbpf);
    COLLECTD_STATS_GAUGE_SUB(flow_confidence_by_ip);
    COLLECTD_STATS_GAUGE_SUB(flow_confidence_dpi_aggressive);
    COLLECTD_STATS_GAUGE_SUB(flow_confidence_custom_rule);
    COLLECTD_STATS_GAUGE_SUB(flow_confidence_unknown);

    COLLECTD_STATS_GAUGE_SUB(flow_severity_low);
    COLLECTD_STATS_GAUGE_SUB(flow_severity_medium);
    COLLECTD_STATS_GAUGE_SUB(flow_severity_high);
    COLLECTD_STATS_GAUGE_SUB(flow_severity_severe);
    COLLECTD_STATS_GAUGE_SUB(flow_severity_critical);
    COLLECTD_STATS_GAUGE_SUB(flow_severity_emergency);
    COLLECTD_STATS_GAUGE_SUB(flow_severity_unknown);

    COLLECTD_STATS_GAUGE_SUB(flow_l3_ip4_count);
    COLLECTD_STATS_GAUGE_SUB(flow_l3_ip6_count);
    COLLECTD_STATS_GAUGE_SUB(flow_l3_other_count);

    COLLECTD_STATS_GAUGE_SUB(flow_l4_tcp_count);
    COLLECTD_STATS_GAUGE_SUB(flow_l4_udp_count);
    COLLECTD_STATS_GAUGE_SUB(flow_l4_icmp_count);
    COLLECTD_STATS_GAUGE_SUB(flow_l4_other_count);

    COLLECTD_STATS_GAUGE_SUB(flow_active_count);
    COLLECTD_STATS_GAUGE_SUB(flow_detected_count);
    COLLECTD_STATS_GAUGE_SUB(flow_guessed_count);
    COLLECTD_STATS_GAUGE_SUB(flow_not_detected_count);

    for (i = 0; i < NDPI_MAX_RISK - 1 /* NDPI_NO_RISK */; ++i)
    {
        COLLECTD_STATS_GAUGE_SUB(flow_risk_count[i]);
    }
    COLLECTD_STATS_GAUGE_SUB(flow_risk_unknown_count);

    memset(&collectd_statistics.gauges[1], 0, sizeof(collectd_statistics.gauges[1]));
}

static int mainloop(int epollfd, struct nDPIsrvd_socket * const sock)
{
    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);

    while (main_thread_shutdown == 0)
    {
        int nready = epoll_wait(epollfd, events, events_size, -1);

        for (int i = 0; i < nready; i++)
        {
            if (events[i].events & EPOLLERR)
            {
                logger(1, "Epoll event error: %s", (errno != 0 ? strerror(errno) : "EPOLLERR"));
                break;
            }

            if (events[i].data.fd == collectd_timerfd)
            {
                uint64_t expirations;

                /*
                 * Check if collectd parent process is still running.
                 * May happen if collectd was killed with singals e.g. SIGKILL.
                 */
                if (getppid() != collectd_pid)
                {
                    logger(1, "Parent process %d exited. Nothing left to do here, bye.", collectd_pid);
                    return 1;
                }

                errno = 0;
                if (read(collectd_timerfd, &expirations, sizeof(expirations)) != sizeof(expirations))
                {
                    logger(1, "Could not read timer expirations: %s", strerror(errno));
                    return 1;
                }
                if (set_collectd_timer() != 0)
                {
                    logger(1, "Could not set timer: %s", strerror(errno));
                    return 1;
                }

                print_collectd_exec_output();
            }
            else if (events[i].data.fd == sock->fd)
            {
                errno = 0;
                enum nDPIsrvd_read_return read_ret = nDPIsrvd_read(sock);
                if (read_ret != READ_OK)
                {
                    logger(1, "nDPIsrvd read failed with: %s", nDPIsrvd_enum_to_string(read_ret));
                    return 1;
                }

                enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(sock);
                if (parse_ret != PARSE_NEED_MORE_DATA)
                {
                    logger(1, "nDPIsrvd parse failed with: %s", nDPIsrvd_enum_to_string(parse_ret));
                    return 1;
                }
            }
        }
    }

    return 0;
}

static int collectd_map_to_stat(char const * const token_str,
                                size_t token_length,
                                struct global_map const * const map,
                                size_t map_length)
{
    size_t i, null_i = map_length;

    for (i = 0; i < map_length; ++i)
    {
        if (map[i].json_key == NULL)
        {
            null_i = i;
            break;
        }

        size_t key_length = strlen(map[i].json_key);
        if (key_length == token_length && strncmp(map[i].json_key, token_str, token_length) == 0)
        {
            (*map[i].global_stat_inc)++;
            return 0;
        }
    }

    if (null_i < map_length && map[null_i].global_stat_inc != NULL)
    {
        (*map[null_i].global_stat_inc)++;
        return 0;
    }

    return 1;
}

static int collectd_map_value_to_stat(struct nDPIsrvd_socket * const sock,
                                      struct nDPIsrvd_json_token const * const token,
                                      struct global_map const * const map,
                                      size_t map_length)
{
    char const * value_str = NULL;
    size_t value_length = 0;

    value_str = TOKEN_GET_VALUE(sock, token, &value_length);
    if (value_length == 0 || value_str == NULL)
    {
        return 1;
    }

    return collectd_map_to_stat(value_str, value_length, map, map_length);
}

static void collectd_unmap_flow_from_stat(struct flow_user_data * const flow_user_data)
{
    if (flow_user_data->is_ip4 != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_l3_ip4_count);
    }

    if (flow_user_data->is_ip6 != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_l3_ip6_count);
    }

    if (flow_user_data->is_other_l3 != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_l3_other_count);
    }

    if (flow_user_data->is_tcp != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_l4_tcp_count);
    }

    if (flow_user_data->is_udp != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_l4_udp_count);
    }

    if (flow_user_data->is_icmp != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_l4_icmp_count);
    }

    if (flow_user_data->is_other_l4 != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_l4_other_count);
    }

    if (flow_user_data->new_seen != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_active_count);
    }

    if (flow_user_data->is_detected != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_detected_count);
    }

    if (flow_user_data->is_guessed != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_guessed_count);
    }

    if (flow_user_data->is_not_detected != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_not_detected_count);
    }

    if (flow_user_data->is_info != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_state_info);
    }

    if (flow_user_data->is_finished != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_state_finished);
    }

    if (flow_user_data->breed > 0 && flow_user_data->breed_ndpid_invalid == 0 &&
        COLLECTD_STATS_MAP_NOTNULL(breeds_map, flow_user_data->breed) != 0)
    {
        COLLECTD_STATS_MAP_DEC(breeds_map, flow_user_data->breed);
    }

    if (flow_user_data->category > 0 && flow_user_data->category_ndpid_invalid == 0 &&
        COLLECTD_STATS_MAP_NOTNULL(categories_map, flow_user_data->category) != 0)
    {
        COLLECTD_STATS_MAP_DEC(categories_map, flow_user_data->category);
    }

    if (flow_user_data->confidence > 0 && flow_user_data->confidence_ndpid_invalid == 0 &&
        COLLECTD_STATS_MAP_NOTNULL(confidence_map, flow_user_data->confidence) != 0)
    {
        COLLECTD_STATS_MAP_DEC(confidence_map, flow_user_data->confidence);
    }

    for (uint8_t i = 0; i < MAX_SEVERITIES_PER_FLOW; ++i)
    {
        if (flow_user_data->severities[i] > 0)
        {
            COLLECTD_STATS_MAP_DEC(severity_map, flow_user_data->severities[i]);
        }
    }

    for (uint8_t i = 0; i < MAX_RISKS_PER_FLOW; ++i)
    {
        if (flow_user_data->risks[i] > 0)
        {
            COLLECTD_STATS_GAUGE_DEC(flow_risk_count[flow_user_data->risks[i]]);
        }
    }

    if (flow_user_data->risk_ndpid_invalid != 0)
    {
        COLLECTD_STATS_GAUGE_DEC(flow_risk_unknown_count);
    }
}

static ssize_t collectd_map_index(char const * const json_key,
                                  size_t key_length,
                                  struct global_map const * const map,
                                  size_t map_length)
{
    ssize_t unknown_key = -1;

    if (json_key == NULL || key_length == 0)
    {
        return -1;
    }

    for (size_t i = 0; i < map_length; ++i)
    {
        if (map[i].json_key == NULL)
        {
            unknown_key = i;
            continue;
        }

        if (key_length == strlen(map[i].json_key) && strncmp(json_key, map[i].json_key, key_length) == 0)
        {
            return i;
        }
    }

    return unknown_key;
}

static int collectd_map_flow_u8(struct nDPIsrvd_socket * const sock,
                                struct nDPIsrvd_json_token const * const token,
                                struct global_map const * const map,
                                size_t map_length,
                                uint8_t * const dest)
{
    if (token == NULL || dest == NULL)
    {
        return 1;
    }

    size_t len;
    char const * const str = TOKEN_GET_VALUE(sock, token, &len);
    if (str == NULL || len == 0)
    {
        return 1;
    }

    ssize_t const map_index = collectd_map_index(str, len, map, map_length);
    if (map_index < 0 || map_index > UCHAR_MAX)
    {
        return 1;
    }

    *dest = map_index + 1;
    return 0;
}

static void process_flow_stats(struct nDPIsrvd_socket * const sock, struct nDPIsrvd_flow * const flow)
{
    struct flow_user_data * flow_user_data;
    struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");
    struct nDPIsrvd_json_token const * const flow_state = TOKEN_GET_SZ(sock, "flow_state");
    nDPIsrvd_ull total_bytes_ull[2];

    if (flow == NULL)
    {
        return;
    }
    flow_user_data = (struct flow_user_data *)flow->flow_user_data;
    if (flow_user_data == NULL)
    {
        return;
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "new") != 0)
    {
        flow_user_data->new_seen = 1;
        COLLECTD_STATS_GAUGE_INC(flow_active_count);

        struct nDPIsrvd_json_token const * const l3_proto = TOKEN_GET_SZ(sock, "l3_proto");
        if (TOKEN_VALUE_EQUALS_SZ(sock, l3_proto, "ip4") != 0)
        {
            flow_user_data->is_ip4 = 1;
            COLLECTD_STATS_GAUGE_INC(flow_l3_ip4_count);
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l3_proto, "ip6") != 0)
        {
            flow_user_data->is_ip6 = 1;
            COLLECTD_STATS_GAUGE_INC(flow_l3_ip6_count);
        }
        else if (l3_proto != NULL)
        {
            flow_user_data->is_other_l3 = 1;
            COLLECTD_STATS_GAUGE_INC(flow_l3_other_count);
        }

        struct nDPIsrvd_json_token const * const l4_proto = TOKEN_GET_SZ(sock, "l4_proto");
        if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "tcp") != 0)
        {
            flow_user_data->is_tcp = 1;
            COLLECTD_STATS_GAUGE_INC(flow_l4_tcp_count);
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "udp") != 0)
        {
            flow_user_data->is_udp = 1;
            COLLECTD_STATS_GAUGE_INC(flow_l4_udp_count);
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "icmp") != 0)
        {
            flow_user_data->is_icmp = 1;
            COLLECTD_STATS_GAUGE_INC(flow_l4_icmp_count);
        }
        else if (l4_proto != NULL)
        {
            flow_user_data->is_other_l4 = 1;
            COLLECTD_STATS_GAUGE_INC(flow_l4_other_count);
        }
    }
    else if (flow_user_data->new_seen == 0)
    {
        return;
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "not-detected") != 0)
    {
        flow_user_data->is_not_detected = 1;
        COLLECTD_STATS_GAUGE_INC(flow_not_detected_count);
    }
    else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "guessed") != 0)
    {
        flow_user_data->is_guessed = 1;
        COLLECTD_STATS_GAUGE_INC(flow_guessed_count);
    }
    else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detected") != 0 ||
             TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detection-update") != 0)
    {
        struct nDPIsrvd_json_token const * const flow_risk = TOKEN_GET_SZ(sock, "ndpi", "flow_risk");
        struct nDPIsrvd_json_token const * current = NULL;
        int next_child_index = -1;

        if (flow_user_data->is_detected == 0)
        {
            flow_user_data->is_detected = 1;
            COLLECTD_STATS_GAUGE_INC(flow_detected_count);
        }

        if (flow_risk != NULL)
        {
            if (flow_user_data->risks[0] == 0)
            {
                COLLECTD_STATS_COUNTER_INC(flow_risky_count);
            }

            while ((current = nDPIsrvd_get_next_token(sock, flow_risk, &next_child_index)) != NULL)
            {
                size_t numeric_risk_len = 0;
                char const * const numeric_risk_str = TOKEN_GET_KEY(sock, current, &numeric_risk_len);
                nDPIsrvd_ull numeric_risk_value = 0;
                char numeric_risk_buf[numeric_risk_len + 1];

                if (numeric_risk_len == 0 || numeric_risk_str == NULL)
                {
                    logger(1, "%s", "Missing numeric risk value");
                    continue;
                }

                strncpy(numeric_risk_buf, numeric_risk_str, numeric_risk_len);
                numeric_risk_buf[numeric_risk_len] = '\0';

                struct nDPIsrvd_json_token const * const severity =
                    TOKEN_GET_SZ(sock, "ndpi", "flow_risk", numeric_risk_buf, "severity");
                uint8_t severity_index;

                if (collectd_map_flow_u8(
                        sock, severity, severity_map, nDPIsrvd_ARRAY_LENGTH(severity_map), &severity_index) != 0)
                {
                    severity_index = 0;
                }

                if (severity_index != 0)
                {
                    for (uint8_t i = 0; i < MAX_SEVERITIES_PER_FLOW; ++i)
                    {
                        if (flow_user_data->severities[i] != 0)
                        {
                            continue;
                        }
                        if (flow_user_data->severities[i] == severity_index)
                        {
                            break;
                        }

                        if (collectd_map_value_to_stat(
                                sock, severity, severity_map, nDPIsrvd_ARRAY_LENGTH(severity_map)) != 0)
                        {
                            severity_index = 0;
                            break;
                        }
                        flow_user_data->severities[i] = severity_index;
                        break;
                    }
                }

                if (severity_index == 0)
                {
                    size_t value_len = 0;
                    char const * const value_str = TOKEN_GET_VALUE(sock, severity, &value_len);

                    if (value_len > 0 && value_str != NULL)
                    {
                        logger(1, "Unknown/Invalid JSON value for key 'ndpi','breed': %.*s", (int)value_len, value_str);
                    }
                }

                if (str_value_to_ull(numeric_risk_str, &numeric_risk_value) == CONVERSION_OK)
                {
                    if (numeric_risk_value < NDPI_MAX_RISK && numeric_risk_value > 0)
                    {
                        for (uint8_t i = 0; i < MAX_RISKS_PER_FLOW; ++i)
                        {
                            if (flow_user_data->risks[i] != 0)
                            {
                                continue;
                            }
                            if (flow_user_data->risks[i] == numeric_risk_value - 1)
                            {
                                break;
                            }

                            COLLECTD_STATS_GAUGE_INC(flow_risk_count[numeric_risk_value - 1]);
                            flow_user_data->risks[i] = numeric_risk_value - 1;
                            break;
                        }
                    }
                    else if (flow_user_data->risk_ndpid_invalid == 0)
                    {
                        flow_user_data->risk_ndpid_invalid = 1;
                        COLLECTD_STATS_GAUGE_INC(flow_risk_unknown_count);
                    }
                }
                else
                {
                    logger(1, "Invalid numeric risk value: %s", numeric_risk_buf);
                }
            }
        }

        if (flow_user_data->breed == 0 && flow_user_data->breed_ndpid_invalid == 0)
        {
            struct nDPIsrvd_json_token const * const breed = TOKEN_GET_SZ(sock, "ndpi", "breed");
            if (collectd_map_flow_u8(
                    sock, breed, breeds_map, nDPIsrvd_ARRAY_LENGTH(breeds_map), &flow_user_data->breed) != 0 ||
                collectd_map_value_to_stat(sock, breed, breeds_map, nDPIsrvd_ARRAY_LENGTH(breeds_map)) != 0)
            {
                size_t value_len = 0;
                char const * const value_str = TOKEN_GET_VALUE(sock, breed, &value_len);

                flow_user_data->breed = 0;
                flow_user_data->breed_ndpid_invalid = 1;
                if (value_len > 0 && value_str != NULL)
                {
                    logger(1, "Unknown/Invalid JSON value for key 'ndpi','breed': %.*s", (int)value_len, value_str);
                }
            }
        }

        if (flow_user_data->category == 0 && flow_user_data->category_ndpid_invalid == 0)
        {
            struct nDPIsrvd_json_token const * const category = TOKEN_GET_SZ(sock, "ndpi", "category");
            if (collectd_map_flow_u8(
                    sock, category, categories_map, nDPIsrvd_ARRAY_LENGTH(categories_map), &flow_user_data->category) !=
                    0 ||
                collectd_map_value_to_stat(sock, category, categories_map, nDPIsrvd_ARRAY_LENGTH(categories_map)) != 0)
            {
                size_t value_len = 0;
                char const * const value_str = TOKEN_GET_VALUE(sock, category, &value_len);

                flow_user_data->category = 0;
                flow_user_data->category_ndpid_invalid = 1;
                if (value_len > 0 && value_str != NULL)
                {
                    logger(1, "Unknown/Invalid JSON value for key 'ndpi','category': %.*s", (int)value_len, value_str);
                }
            }
        }

        if (flow_user_data->confidence == 0 && flow_user_data->confidence_ndpid_invalid == 0)
        {
            struct nDPIsrvd_json_token const * const token = TOKEN_GET_SZ(sock, "ndpi", "confidence");
            struct nDPIsrvd_json_token const * confi_current = NULL;
            int confi_next_child_index = -1;

            if ((confi_current = nDPIsrvd_get_next_token(sock, token, &confi_next_child_index)) == NULL)
            {
                flow_user_data->confidence_ndpid_invalid = 1;
            }
            else if (nDPIsrvd_get_next_token(sock, token, &confi_next_child_index) == NULL)
            {
                if (collectd_map_flow_u8(sock,
                                         confi_current,
                                         confidence_map,
                                         nDPIsrvd_ARRAY_LENGTH(confidence_map),
                                         &flow_user_data->confidence) != 0 ||
                    collectd_map_value_to_stat(
                        sock, confi_current, confidence_map, nDPIsrvd_ARRAY_LENGTH(confidence_map)) != 0)
                {
                    flow_user_data->confidence = 0;
                    flow_user_data->confidence_ndpid_invalid = 1;
                }
            }
            else
            {
                flow_user_data->confidence_ndpid_invalid = 1;
            }

            if (flow_user_data->confidence_ndpid_invalid != 0)
            {
                size_t value_len = 0;
                char const * const value_str = TOKEN_GET_VALUE(sock, confi_current, &value_len);

                logger(1, "Unknown/Invalid JSON value for key 'ndpi','confidence': %.*s", (int)value_len, value_str);
            }
        }
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_state, "info") != 0)
    {
        if (flow_user_data->is_info == 0)
        {
            flow_user_data->is_info = 1;
            COLLECTD_STATS_GAUGE_INC(flow_state_info);
        }
    }
    else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_state, "finished") != 0)
    {
        if (flow_user_data->is_finished == 0)
        {
            if (flow_user_data->is_info != 0)
            {
                flow_user_data->is_info = 0;
                COLLECTD_STATS_GAUGE_RES(flow_state_info);
            }
            flow_user_data->is_finished = 1;
            COLLECTD_STATS_GAUGE_INC(flow_state_finished);
        }
    }

    if (TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_src_tot_l4_payload_len"), &total_bytes_ull[0]) ==
            CONVERSION_OK &&
        TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_dst_tot_l4_payload_len"), &total_bytes_ull[1]) ==
            CONVERSION_OK)
    {
        collectd_statistics.counters.flow_src_total_bytes +=
            total_bytes_ull[0] - flow_user_data->last_flow_src_l4_payload_len;
        collectd_statistics.counters.flow_dst_total_bytes +=
            total_bytes_ull[1] - flow_user_data->last_flow_dst_l4_payload_len;

        flow_user_data->last_flow_src_l4_payload_len = total_bytes_ull[0];
        flow_user_data->last_flow_dst_l4_payload_len = total_bytes_ull[1];
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "end") != 0 ||
        TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "idle") != 0)
    {
        collectd_unmap_flow_from_stat(flow_user_data);
    }
}

static enum nDPIsrvd_callback_return collectd_json_callback(struct nDPIsrvd_socket * const sock,
                                                            struct nDPIsrvd_instance * const instance,
                                                            struct nDPIsrvd_thread_data * const thread_data,
                                                            struct nDPIsrvd_flow * const flow)
{
    (void)instance;
    (void)thread_data;

    struct nDPIsrvd_json_token const * const flow_event = TOKEN_GET_SZ(sock, "flow_event_name");
    struct nDPIsrvd_json_token const * const packet_event = TOKEN_GET_SZ(sock, "packet_event_name");
    struct nDPIsrvd_json_token const * const daemon_event = TOKEN_GET_SZ(sock, "daemon_event_name");
    struct nDPIsrvd_json_token const * const error_event = TOKEN_GET_SZ(sock, "error_event_name");

    COLLECTD_STATS_COUNTER_INC(json_lines);
    collectd_statistics.counters.json_bytes += sock->buffer.json_message_length + NETWORK_BUFFER_LENGTH_DIGITS;

    process_flow_stats(sock, flow);

    if (flow_event != NULL &&
        collectd_map_value_to_stat(sock, flow_event, flow_event_map, nDPIsrvd_ARRAY_LENGTH(flow_event_map)) != 0)
    {
        logger(1, "%s", "Unknown flow_event_name");
    }

    if (packet_event != NULL &&
        collectd_map_value_to_stat(sock, packet_event, packet_event_map, nDPIsrvd_ARRAY_LENGTH(packet_event_map)) != 0)
    {
        logger(1, "%s", "Unknown packet_event_name");
    }

    if (daemon_event != NULL &&
        collectd_map_value_to_stat(sock, daemon_event, daemon_event_map, nDPIsrvd_ARRAY_LENGTH(daemon_event_map)) != 0)
    {
        logger(1, "%s", "Unknown daemon_event_name");
    }

    if (error_event != NULL &&
        collectd_map_value_to_stat(sock, error_event, error_event_map, nDPIsrvd_ARRAY_LENGTH(error_event_map)) != 0)
    {
        logger(1, "%s", "Unknown error_event_name");
    }

    return CALLBACK_OK;
}

int main(int argc, char ** argv)
{
    enum nDPIsrvd_connect_return connect_ret;
    int retval = 1, epollfd = -1;

    init_logging("nDPIsrvd-collectd");

    struct nDPIsrvd_socket * sock =
        nDPIsrvd_socket_init(0, 0, 0, sizeof(struct flow_user_data), collectd_json_callback, NULL, NULL);
    if (sock == NULL)
    {
        LOGGER_EARLY(1, "%s", "nDPIsrvd socket memory allocation failed!");
        return 1;
    }

    if (parse_options(argc, argv, sock) != 0)
    {
        goto failure;
    }

    if (getenv("COLLECTD_HOSTNAME") == NULL && getenv("COLLECTD_INTERVAL") == NULL)
    {
        logger(0, "Recv buffer size: %u", NETWORK_BUFFER_MAX_SIZE);
        logger(0, "Connecting to `%s'..", serv_optarg);
    }
    else
    {
        LOGGER_EARLY(0, "Collectd hostname: %s", getenv("COLLECTD_HOSTNAME"));
        LOGGER_EARLY(0, "Collectd interval: %llu", collectd_interval_ull);
    }

    if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
    {
        LOGGER_EARLY(1,
                     "Could not set stdout unbuffered: %s. Collectd may receive too old PUTVALs and complain.",
                     strerror(errno));
    }

    connect_ret = nDPIsrvd_connect(sock);
    if (connect_ret != CONNECT_OK)
    {
        LOGGER_EARLY(1, "nDPIsrvd socket connect to %s failed!", serv_optarg);
        goto failure;
    }

    if (nDPIsrvd_set_nonblock(sock) != 0)
    {
        LOGGER_EARLY(1, "nDPIsrvd set nonblock failed: %s", strerror(errno));
        goto failure;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    collectd_pid = getppid();

    epollfd = epoll_create1(0);
    if (epollfd < 0)
    {
        LOGGER_EARLY(1, "Error creating epoll: %s", strerror(errno));
        goto failure;
    }

    if (create_collectd_timer() != 0)
    {
        LOGGER_EARLY(1, "Error creating timer: %s", strerror(errno));
        goto failure;
    }

    {
        struct epoll_event timer_event = {.data.fd = collectd_timerfd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, collectd_timerfd, &timer_event) < 0)
        {
            LOGGER_EARLY(1, "Error adding JSON fd to epoll: %s", strerror(errno));
            goto failure;
        }
    }

    {
        struct epoll_event socket_event = {.data.fd = sock->fd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock->fd, &socket_event) < 0)
        {
            LOGGER_EARLY(1, "Error adding nDPIsrvd socket fd to epoll: %s", strerror(errno));
            goto failure;
        }
    }

    logger(0, "%s", "Initialization succeeded.");
    retval = mainloop(epollfd, sock);

    if (getenv("COLLECTD_INTERVAL") == NULL)
    {
        print_collectd_exec_output();
    }

failure:
    nDPIsrvd_socket_free(&sock);
    close(collectd_timerfd);
    close(epollfd);
    shutdown_logging();

    return retval;
}
