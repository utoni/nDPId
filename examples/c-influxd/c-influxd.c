#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <syslog.h>

#include <ndpi_typedefs.h>

#include "nDPIsrvd.h"
#include "utils.h"

#define MAX_RISKS_PER_FLOW 8

static int main_thread_shutdown = 0;
static int influxd_timerfd = -1;

static char * pidfile = NULL;
static char * serv_optarg = NULL;
static char * user = NULL;
static char * group = NULL;
static char * influxdb_interval = NULL;
static nDPIsrvd_ull influxdb_interval_ull = 0uL;
static char * influxdb_url = NULL;
static char * influxdb_token = NULL;

struct flow_user_data
{
    nDPIsrvd_ull last_flow_src_l4_payload_len;
    nDPIsrvd_ull last_flow_dst_l4_payload_len;
    uint8_t risks[MAX_RISKS_PER_FLOW];
    uint8_t category;
    uint8_t breed;
    uint8_t confidence;
    uint8_t severity;
    // "fallthroughs" if we are not in sync with nDPI
    uint8_t risk_ndpid_invalid : 1;
    uint8_t category_ndpid_invalid : 1;
    uint8_t breed_ndpid_invalid : 1;
    uint8_t confidence_ndpid_invalid : 1;
    uint8_t severity_ndpid_invalid : 1;
    // detection status
    uint8_t new_seen : 1;
    uint8_t is_detected : 1;
    uint8_t is_guessed : 1;
    uint8_t is_not_detected : 1;
    // Layer3 / Layer4
    uint8_t is_ip4 : 1;
    uint8_t is_ip6 : 1;
    uint8_t is_other_l3 : 1;
    uint8_t is_tcp : 1;
    uint8_t is_udp : 1;
    uint8_t is_icmp : 1;
    uint8_t is_other_l4 : 1;
};

struct influx_ctx
{
    CURL * curl;
    CURLcode last_result;
    struct curl_slist * http_header;
};

static struct
{
    pthread_mutex_t rw_lock;

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

        nDPIsrvd_ull flow_risk_count[NDPI_MAX_RISK - 1];
        nDPIsrvd_ull flow_risk_unknown_count;
    } gauges;
} influxd_statistics = {.rw_lock = PTHREAD_MUTEX_INITIALIZER};

struct global_map
{
    char const * const json_key;
    uint64_t * const global_stat;
};

static struct global_map const flow_event_map[] = {{"new", &influxd_statistics.counters.flow_new_count},
                                                   {"end", &influxd_statistics.counters.flow_end_count},
                                                   {"idle", &influxd_statistics.counters.flow_idle_count},
                                                   {"update", &influxd_statistics.counters.flow_update_count},
                                                   {"analyse", &influxd_statistics.counters.flow_analyse_count},
                                                   {"guessed", &influxd_statistics.counters.flow_guessed_count},
                                                   {"detected", &influxd_statistics.counters.flow_detected_count},
                                                   {"detection-update",
                                                    &influxd_statistics.counters.flow_detection_update_count},
                                                   {"not-detected",
                                                    &influxd_statistics.counters.flow_not_detected_count}};

static struct global_map const packet_event_map[] = {{"packet", &influxd_statistics.counters.packet_count},
                                                     {"packet-flow", &influxd_statistics.counters.packet_flow_count}};

static struct global_map const daemon_event_map[] = {{"init", &influxd_statistics.counters.init_count},
                                                     {"reconnect", &influxd_statistics.counters.reconnect_count},
                                                     {"shutdown", &influxd_statistics.counters.shutdown_count},
                                                     {"status", &influxd_statistics.counters.status_count}};

static struct global_map const error_event_map[] = {
    {"Unknown datalink layer packet", &influxd_statistics.counters.error_unknown_datalink},
    {"Unknown L3 protocol", &influxd_statistics.counters.error_unknown_l3_protocol},
    {"Unsupported datalink layer", &influxd_statistics.counters.error_unsupported_datalink},
    {"Packet too short", &influxd_statistics.counters.error_packet_too_short},
    {"Unknown packet type", &influxd_statistics.counters.error_packet_type_unknown},
    {"Packet header invalid", &influxd_statistics.counters.error_packet_header_invalid},
    {"IP4 packet too short", &influxd_statistics.counters.error_ip4_packet_too_short},
    {"Packet smaller than IP4 header", &influxd_statistics.counters.error_ip4_size_smaller_than_header},
    {"nDPI IPv4\\/L4 payload detection failed", &influxd_statistics.counters.error_ip4_l4_payload_detection},
    {"IP6 packet too short", &influxd_statistics.counters.error_ip6_packet_too_short},
    {"Packet smaller than IP6 header", &influxd_statistics.counters.error_ip6_size_smaller_than_header},
    {"nDPI IPv6\\/L4 payload detection failed", &influxd_statistics.counters.error_ip6_l4_payload_detection},
    {"TCP packet smaller than expected", &influxd_statistics.counters.error_tcp_packet_too_short},
    {"UDP packet smaller than expected", &influxd_statistics.counters.error_udp_packet_too_short},
    {"Captured packet size is smaller than expected packet size",
     &influxd_statistics.counters.error_capture_size_smaller_than_packet},
    {"Max flows to track reached", &influxd_statistics.counters.error_max_flows_to_track},
    {"Flow memory allocation failed", &influxd_statistics.counters.error_flow_memory_alloc}};

static struct global_map const breeds_map[] = {{"Safe", &influxd_statistics.gauges.flow_breed_safe_count},
                                               {"Acceptable", &influxd_statistics.gauges.flow_breed_acceptable_count},
                                               {"Fun", &influxd_statistics.gauges.flow_breed_fun_count},
                                               {"Unsafe", &influxd_statistics.gauges.flow_breed_unsafe_count},
                                               {"Potentially Dangerous",
                                                &influxd_statistics.gauges.flow_breed_potentially_dangerous_count},
                                               {"Tracker\\/Ads",
                                                &influxd_statistics.gauges.flow_breed_tracker_ads_count},
                                               {"Dangerous", &influxd_statistics.gauges.flow_breed_dangerous_count},
                                               {"Unrated", &influxd_statistics.gauges.flow_breed_unrated_count},
                                               {NULL, &influxd_statistics.gauges.flow_breed_unknown_count}};

static struct global_map const categories_map[] = {
    {"Unspecified", &influxd_statistics.gauges.flow_category_unspecified_count},
    {"Media", &influxd_statistics.gauges.flow_category_media_count},
    {"VPN", &influxd_statistics.gauges.flow_category_vpn_count},
    {"Email", &influxd_statistics.gauges.flow_category_email_count},
    {"DataTransfer", &influxd_statistics.gauges.flow_category_data_transfer_count},
    {"Web", &influxd_statistics.gauges.flow_category_web_count},
    {"SocialNetwork", &influxd_statistics.gauges.flow_category_social_network_count},
    {"Download", &influxd_statistics.gauges.flow_category_download_count},
    {"Game", &influxd_statistics.gauges.flow_category_game_count},
    {"Chat", &influxd_statistics.gauges.flow_category_chat_count},
    {"VoIP", &influxd_statistics.gauges.flow_category_voip_count},
    {"Database", &influxd_statistics.gauges.flow_category_database_count},
    {"RemoteAccess", &influxd_statistics.gauges.flow_category_remote_access_count},
    {"Cloud", &influxd_statistics.gauges.flow_category_cloud_count},
    {"Network", &influxd_statistics.gauges.flow_category_network_count},
    {"Collaborative", &influxd_statistics.gauges.flow_category_collaborative_count},
    {"RPC", &influxd_statistics.gauges.flow_category_rpc_count},
    {"Streaming", &influxd_statistics.gauges.flow_category_streaming_count},
    {"System", &influxd_statistics.gauges.flow_category_system_count},
    {"SoftwareUpdate", &influxd_statistics.gauges.flow_category_software_update_count},
    {"Music", &influxd_statistics.gauges.flow_category_music_count},
    {"Video", &influxd_statistics.gauges.flow_category_video_count},
    {"Shopping", &influxd_statistics.gauges.flow_category_shopping_count},
    {"Productivity", &influxd_statistics.gauges.flow_category_productivity_count},
    {"FileSharing", &influxd_statistics.gauges.flow_category_file_sharing_count},
    {"ConnCheck", &influxd_statistics.gauges.flow_category_conn_check_count},
    {"IoT-Scada", &influxd_statistics.gauges.flow_category_iot_scada_count},
    {"VirtAssistant", &influxd_statistics.gauges.flow_category_virt_assistant_count},
    {"Cybersecurity", &influxd_statistics.gauges.flow_category_cybersecurity_count},
    {"AdultContent", &influxd_statistics.gauges.flow_category_adult_content_count},
    {"Mining", &influxd_statistics.gauges.flow_category_mining_count},
    {"Malware", &influxd_statistics.gauges.flow_category_malware_count},
    {"Advertisement", &influxd_statistics.gauges.flow_category_advertisment_count},
    {"Banned_Site", &influxd_statistics.gauges.flow_category_banned_site_count},
    {"Site_Unavailable", &influxd_statistics.gauges.flow_category_site_unavail_count},
    {"Allowed_Site", &influxd_statistics.gauges.flow_category_allowed_site_count},
    {"Antimalware", &influxd_statistics.gauges.flow_category_antimalware_count},
    {"Crypto_Currency", &influxd_statistics.gauges.flow_category_crypto_currency_count},
    {"Gambling", &influxd_statistics.gauges.flow_category_gambling_count},
    {NULL, &influxd_statistics.gauges.flow_category_unknown_count}};

static struct global_map const confidence_map[] = {
    {"Match by port", &influxd_statistics.gauges.flow_confidence_by_port},
    {"DPI (partial)", &influxd_statistics.gauges.flow_confidence_dpi_partial},
    {"DPI (partial cache)", &influxd_statistics.gauges.flow_confidence_dpi_partial_cache},
    {"DPI (cache)", &influxd_statistics.gauges.flow_confidence_dpi_cache},
    {"DPI", &influxd_statistics.gauges.flow_confidence_dpi},
    {"nBPF", &influxd_statistics.gauges.flow_confidence_nbpf},
    {"Match by IP", &influxd_statistics.gauges.flow_confidence_by_ip},
    {"DPI (aggressive)", &influxd_statistics.gauges.flow_confidence_dpi_aggressive},
    {NULL, &influxd_statistics.gauges.flow_confidence_unknown}};

static struct global_map const severity_map[] = {{"Low", &influxd_statistics.gauges.flow_severity_low},
                                                 {"Medium", &influxd_statistics.gauges.flow_severity_medium},
                                                 {"High", &influxd_statistics.gauges.flow_severity_high},
                                                 {"Severe", &influxd_statistics.gauges.flow_severity_severe},
                                                 {"Critical", &influxd_statistics.gauges.flow_severity_critical},
                                                 {"Emergency", &influxd_statistics.gauges.flow_severity_emergency},
                                                 {NULL, &influxd_statistics.gauges.flow_severity_unknown}};

#define INFLUXDB_FORMAT() "%s=%llu,"
#define INFLUXDB_FORMAT_END() "%s=%llu\n"
#define INFLUXDB_VALUE_COUNTER(value) #value, (unsigned long long int)influxd_statistics.counters.value
#define INFLUXDB_VALUE_GAUGE(value) #value, (unsigned long long int)influxd_statistics.gauges.value
#define CHECK_SNPRINTF_RET(bytes)                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        if (bytes <= 0 || (size_t)bytes >= siz)                                                                        \
        {                                                                                                              \
            goto failure;                                                                                              \
        }                                                                                                              \
        else                                                                                                           \
        {                                                                                                              \
            buf += bytes;                                                                                              \
            siz -= bytes;                                                                                              \
        }                                                                                                              \
    } while (0)
static int serialize_influx_line(char * buf, size_t siz)
{
    int bytes;

    pthread_mutex_lock(&influxd_statistics.rw_lock);

    bytes = snprintf(buf,
                     siz,
                     "%s " INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT_END(),
                     "general",
                     INFLUXDB_VALUE_COUNTER(json_lines),
                     INFLUXDB_VALUE_COUNTER(json_bytes),
                     INFLUXDB_VALUE_COUNTER(flow_src_total_bytes),
                     INFLUXDB_VALUE_COUNTER(flow_dst_total_bytes));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     "%s " INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                         INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                             INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                 INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                     INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                         INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                             INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT_END(),
                     "events",
                     INFLUXDB_VALUE_COUNTER(flow_new_count),
                     INFLUXDB_VALUE_COUNTER(flow_end_count),
                     INFLUXDB_VALUE_COUNTER(flow_idle_count),
                     INFLUXDB_VALUE_COUNTER(flow_update_count),
                     INFLUXDB_VALUE_COUNTER(flow_analyse_count),
                     INFLUXDB_VALUE_COUNTER(flow_guessed_count),
                     INFLUXDB_VALUE_COUNTER(flow_detected_count),
                     INFLUXDB_VALUE_COUNTER(flow_detection_update_count),
                     INFLUXDB_VALUE_COUNTER(flow_not_detected_count),
                     INFLUXDB_VALUE_COUNTER(flow_risky_count),
                     INFLUXDB_VALUE_COUNTER(packet_count),
                     INFLUXDB_VALUE_COUNTER(packet_flow_count),
                     INFLUXDB_VALUE_COUNTER(init_count),
                     INFLUXDB_VALUE_COUNTER(reconnect_count),
                     INFLUXDB_VALUE_COUNTER(shutdown_count),
                     INFLUXDB_VALUE_COUNTER(status_count),
                     INFLUXDB_VALUE_COUNTER(error_unknown_datalink),
                     INFLUXDB_VALUE_COUNTER(error_unknown_l3_protocol),
                     INFLUXDB_VALUE_COUNTER(error_unsupported_datalink),
                     INFLUXDB_VALUE_COUNTER(error_packet_too_short),
                     INFLUXDB_VALUE_COUNTER(error_packet_type_unknown),
                     INFLUXDB_VALUE_COUNTER(error_packet_header_invalid),
                     INFLUXDB_VALUE_COUNTER(error_ip4_packet_too_short),
                     INFLUXDB_VALUE_COUNTER(error_ip4_size_smaller_than_header),
                     INFLUXDB_VALUE_COUNTER(error_ip4_l4_payload_detection),
                     INFLUXDB_VALUE_COUNTER(error_ip6_packet_too_short),
                     INFLUXDB_VALUE_COUNTER(error_ip6_size_smaller_than_header),
                     INFLUXDB_VALUE_COUNTER(error_ip6_l4_payload_detection),
                     INFLUXDB_VALUE_COUNTER(error_tcp_packet_too_short),
                     INFLUXDB_VALUE_COUNTER(error_udp_packet_too_short));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     "%s " INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                         INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT_END(),
                     "breed",
                     INFLUXDB_VALUE_GAUGE(flow_breed_safe_count),
                     INFLUXDB_VALUE_GAUGE(flow_breed_acceptable_count),
                     INFLUXDB_VALUE_GAUGE(flow_breed_fun_count),
                     INFLUXDB_VALUE_GAUGE(flow_breed_unsafe_count),
                     INFLUXDB_VALUE_GAUGE(flow_breed_potentially_dangerous_count),
                     INFLUXDB_VALUE_GAUGE(flow_breed_tracker_ads_count),
                     INFLUXDB_VALUE_GAUGE(flow_breed_dangerous_count),
                     INFLUXDB_VALUE_GAUGE(flow_breed_unrated_count),
                     INFLUXDB_VALUE_GAUGE(flow_breed_unknown_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     "%s " INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                         INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                             INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                 INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                     INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                         INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                             INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                                 INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                                     INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                                                         INFLUXDB_FORMAT() INFLUXDB_FORMAT_END(),

                     "category",
                     INFLUXDB_VALUE_GAUGE(flow_category_unspecified_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_media_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_vpn_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_email_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_data_transfer_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_web_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_social_network_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_download_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_game_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_chat_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_voip_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_database_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_remote_access_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_cloud_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_network_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_collaborative_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_rpc_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_streaming_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_system_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_software_update_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_music_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_video_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_shopping_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_productivity_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_file_sharing_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_conn_check_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_iot_scada_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_virt_assistant_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_cybersecurity_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_adult_content_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_mining_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_malware_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_advertisment_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_banned_site_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_site_unavail_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_allowed_site_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_antimalware_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_crypto_currency_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_gambling_count),
                     INFLUXDB_VALUE_GAUGE(flow_category_unknown_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     "%s " INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                         INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT_END(),
                     "confidence",
                     INFLUXDB_VALUE_GAUGE(flow_confidence_by_port),
                     INFLUXDB_VALUE_GAUGE(flow_confidence_dpi_partial),
                     INFLUXDB_VALUE_GAUGE(flow_confidence_dpi_partial_cache),
                     INFLUXDB_VALUE_GAUGE(flow_confidence_dpi_cache),
                     INFLUXDB_VALUE_GAUGE(flow_confidence_dpi),
                     INFLUXDB_VALUE_GAUGE(flow_confidence_nbpf),
                     INFLUXDB_VALUE_GAUGE(flow_confidence_by_ip),
                     INFLUXDB_VALUE_GAUGE(flow_confidence_dpi_aggressive),
                     INFLUXDB_VALUE_GAUGE(flow_confidence_unknown));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     "%s " INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT()
                         INFLUXDB_FORMAT() INFLUXDB_FORMAT_END(),
                     "severity",
                     INFLUXDB_VALUE_GAUGE(flow_severity_low),
                     INFLUXDB_VALUE_GAUGE(flow_severity_medium),
                     INFLUXDB_VALUE_GAUGE(flow_severity_high),
                     INFLUXDB_VALUE_GAUGE(flow_severity_severe),
                     INFLUXDB_VALUE_GAUGE(flow_severity_critical),
                     INFLUXDB_VALUE_GAUGE(flow_severity_emergency),
                     INFLUXDB_VALUE_GAUGE(flow_severity_unknown));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     "%s " INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT_END(),
                     "layer3",
                     INFLUXDB_VALUE_GAUGE(flow_l3_ip4_count),
                     INFLUXDB_VALUE_GAUGE(flow_l3_ip6_count),
                     INFLUXDB_VALUE_GAUGE(flow_l3_other_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     "%s " INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT_END(),
                     "layer4",
                     INFLUXDB_VALUE_GAUGE(flow_l4_tcp_count),
                     INFLUXDB_VALUE_GAUGE(flow_l4_udp_count),
                     INFLUXDB_VALUE_GAUGE(flow_l4_icmp_count),
                     INFLUXDB_VALUE_GAUGE(flow_l4_other_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     "%s " INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT() INFLUXDB_FORMAT_END(),
                     "detection",
                     INFLUXDB_VALUE_GAUGE(flow_active_count),
                     INFLUXDB_VALUE_GAUGE(flow_detected_count),
                     INFLUXDB_VALUE_GAUGE(flow_guessed_count),
                     INFLUXDB_VALUE_GAUGE(flow_not_detected_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf, siz, "%s " INFLUXDB_FORMAT(), "risks", INFLUXDB_VALUE_GAUGE(flow_risk_unknown_count));
    CHECK_SNPRINTF_RET(bytes);

    for (size_t i = 0; i < NDPI_MAX_RISK - 1; ++i)
    {
        bytes = snprintf(buf,
                         siz,
                         "flow_risk_%zu_count=%llu,",
                         i + 1,
                         (unsigned long long int)influxd_statistics.gauges.flow_risk_count[i]);
        CHECK_SNPRINTF_RET(bytes);
    }
    buf[-1] = '\n';

failure:
    memset(&influxd_statistics.counters, 0, sizeof(influxd_statistics.counters));
    pthread_mutex_unlock(&influxd_statistics.rw_lock);

    return 0;
}

static int init_influx_ctx(struct influx_ctx * const ctx, char const * const url, char const * const api_token)
{
    char auth[128];

    ctx->http_header = curl_slist_append(ctx->http_header, "Content-Type: application/json");
    if (ctx->http_header == NULL)
    {
        return -1;
    }
    if (snprintf(auth, sizeof(auth), "Authorization: Token %s", api_token) >= (int)sizeof(auth))
    {
        return -1;
    }
    ctx->http_header = curl_slist_append(ctx->http_header, auth);
    memset(auth, '\0', sizeof(auth));
    if (ctx->http_header == NULL)
    {
        return -1;
    }

    ctx->curl = curl_easy_init();
    if (ctx->curl == NULL)
    {
        return -1;
    }

    if (curl_easy_setopt(ctx->curl, CURLOPT_URL, url) != CURLE_OK ||
        curl_easy_setopt(ctx->curl, CURLOPT_USERAGENT, "nDPIsrvd-influxd") != CURLE_OK ||
        curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, ctx->http_header) != CURLE_OK ||
        curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, influxdb_interval_ull) != CURLE_OK)
    {
        return -1;
    }

    return 0;
}

static void free_influx_ctx(struct influx_ctx * const ctx)
{
    curl_easy_cleanup(ctx->curl);
    curl_slist_free_all(ctx->http_header);
    ctx->curl = NULL;
    ctx->http_header = NULL;
}

static void post_influx_ctx(struct influx_ctx * const ctx)
{
    CURLcode res;
    char post_buffer[BUFSIZ];

    if (serialize_influx_line(post_buffer, sizeof(post_buffer)) != 0)
    {
        logger(1, "%s", "Could not serialize influx buffer");
        return;
    }
    curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, post_buffer);
    res = curl_easy_perform(ctx->curl);
    if (res != CURLE_OK)
    {
        logger(1, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
        return;
    }
}

static void * send_to_influxdb(void * thread_data)
{
    struct influx_ctx influx_ctx;

    (void)thread_data;
    init_influx_ctx(&influx_ctx, influxdb_url, influxdb_token);
    post_influx_ctx(&influx_ctx);
    free_influx_ctx(&influx_ctx);

    return NULL;
}

static int start_influxdb_thread(void)
{
    pthread_t tid;
    pthread_attr_t att;

    if (pthread_attr_init(&att) != 0)
    {
        return 1;
    }
    if (pthread_attr_setdetachstate(&att, PTHREAD_CREATE_DETACHED) != 0)
    {
        return 1;
    }

    int error = pthread_create(&tid, &att, send_to_influxdb, NULL);
    if (0 != error)
    {
        logger(1, "Couldn't run thread, errno %d", error);
    }

    pthread_attr_destroy(&att);
    return 0;
}

static int influxd_map_to_stat(char const * const token_str,
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
            (*map[i].global_stat)++;
            return 0;
        }
    }

    if (null_i < map_length && map[null_i].global_stat != NULL)
    {
        (*map[null_i].global_stat)++;
        return 0;
    }

    return 1;
}

static int influxd_map_value_to_stat(struct nDPIsrvd_socket * const sock,
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

    return influxd_map_to_stat(value_str, value_length, map, map_length);
}

static void influxd_unmap_flow_from_stat(struct flow_user_data * const flow_user_data)
{
    if (flow_user_data->is_ip4 != 0)
    {
        influxd_statistics.gauges.flow_l3_ip4_count--;
    }

    if (flow_user_data->is_ip6 != 0)
    {
        influxd_statistics.gauges.flow_l3_ip6_count--;
    }

    if (flow_user_data->is_other_l3 != 0)
    {
        influxd_statistics.gauges.flow_l3_other_count--;
    }

    if (flow_user_data->is_tcp != 0)
    {
        influxd_statistics.gauges.flow_l4_tcp_count--;
    }

    if (flow_user_data->is_udp != 0)
    {
        influxd_statistics.gauges.flow_l4_udp_count--;
    }

    if (flow_user_data->is_icmp != 0)
    {
        influxd_statistics.gauges.flow_l4_icmp_count--;
    }

    if (flow_user_data->is_other_l4 != 0)
    {
        influxd_statistics.gauges.flow_l4_other_count--;
    }

    if (flow_user_data->new_seen != 0)
    {
        influxd_statistics.gauges.flow_active_count--;
    }

    if (flow_user_data->is_detected != 0)
    {
        influxd_statistics.gauges.flow_detected_count--;
    }

    if (flow_user_data->is_guessed != 0)
    {
        influxd_statistics.gauges.flow_guessed_count--;
    }

    if (flow_user_data->is_not_detected != 0)
    {
        influxd_statistics.gauges.flow_not_detected_count--;
    }

    if (flow_user_data->breed > 0 && flow_user_data->breed_ndpid_invalid == 0 &&
        breeds_map[flow_user_data->breed - 1].global_stat != NULL)
    {
        (*breeds_map[flow_user_data->breed - 1].global_stat)--;
    }

    if (flow_user_data->category > 0 && flow_user_data->category_ndpid_invalid == 0 &&
        categories_map[flow_user_data->category - 1].global_stat != NULL)
    {
        (*categories_map[flow_user_data->category - 1].global_stat)--;
    }

    if (flow_user_data->confidence > 0 && flow_user_data->confidence_ndpid_invalid == 0 &&
        confidence_map[flow_user_data->confidence - 1].global_stat != NULL)
    {
        (*confidence_map[flow_user_data->confidence - 1].global_stat)--;
    }

    if (flow_user_data->severity > 0 && flow_user_data->severity_ndpid_invalid == 0 &&
        severity_map[flow_user_data->severity - 1].global_stat != NULL)
    {
        (*severity_map[flow_user_data->severity - 1].global_stat)--;
    }

    for (uint8_t i = 0; i < MAX_RISKS_PER_FLOW; ++i)
    {
        if (flow_user_data->risks[i] > 0)
        {
            influxd_statistics.gauges.flow_risk_count[flow_user_data->risks[i]]--;
        }
    }

    if (flow_user_data->risk_ndpid_invalid != 0)
    {
        influxd_statistics.gauges.flow_risk_unknown_count--;
    }
}

static ssize_t influxd_map_index(char const * const json_key,
                                 size_t key_length,
                                 struct global_map const * const map,
                                 size_t map_length)
{
    if (json_key == NULL || key_length == 0)
    {
        return -1;
    }

    for (size_t i = 0; i < map_length; ++i)
    {
        if (map[i].json_key == NULL)
        {
            continue;
        }

        if (key_length == strlen(map[i].json_key) && strncmp(json_key, map[i].json_key, key_length) == 0)
        {
            return i;
        }
    }

    return -1;
}

static int influxd_map_flow_u8(struct nDPIsrvd_socket * const sock,
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

    ssize_t const map_index = influxd_map_index(str, len, map, map_length);
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

    if (TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_src_tot_l4_payload_len"), &total_bytes_ull[0]) ==
            CONVERSION_OK &&
        TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_dst_tot_l4_payload_len"), &total_bytes_ull[1]) ==
            CONVERSION_OK)
    {
        influxd_statistics.counters.flow_src_total_bytes +=
            total_bytes_ull[0] - flow_user_data->last_flow_src_l4_payload_len;
        influxd_statistics.counters.flow_dst_total_bytes +=
            total_bytes_ull[1] - flow_user_data->last_flow_dst_l4_payload_len;

        flow_user_data->last_flow_src_l4_payload_len = total_bytes_ull[0];
        flow_user_data->last_flow_dst_l4_payload_len = total_bytes_ull[1];
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "new") != 0)
    {
        flow_user_data->new_seen = 1;
        influxd_statistics.gauges.flow_active_count++;

        struct nDPIsrvd_json_token const * const l3_proto = TOKEN_GET_SZ(sock, "l3_proto");
        if (TOKEN_VALUE_EQUALS_SZ(sock, l3_proto, "ip4") != 0)
        {
            flow_user_data->is_ip4 = 1;
            influxd_statistics.gauges.flow_l3_ip4_count++;
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l3_proto, "ip6") != 0)
        {
            flow_user_data->is_ip6 = 1;
            influxd_statistics.gauges.flow_l3_ip6_count++;
        }
        else if (l3_proto != NULL)
        {
            flow_user_data->is_other_l3 = 1;
            influxd_statistics.gauges.flow_l3_other_count++;
        }

        struct nDPIsrvd_json_token const * const l4_proto = TOKEN_GET_SZ(sock, "l4_proto");
        if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "tcp") != 0)
        {
            flow_user_data->is_tcp = 1;
            influxd_statistics.gauges.flow_l4_tcp_count++;
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "udp") != 0)
        {
            flow_user_data->is_udp = 1;
            influxd_statistics.gauges.flow_l4_udp_count++;
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "icmp") != 0)
        {
            flow_user_data->is_icmp = 1;
            influxd_statistics.gauges.flow_l4_icmp_count++;
        }
        else if (l4_proto != NULL)
        {
            flow_user_data->is_other_l4 = 1;
            influxd_statistics.gauges.flow_l4_other_count++;
        }
    }
    else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "not-detected") != 0)
    {
        flow_user_data->is_not_detected = 1;
        influxd_statistics.gauges.flow_not_detected_count++;
    }
    else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "guessed") != 0)
    {
        flow_user_data->is_guessed = 1;
        influxd_statistics.gauges.flow_guessed_count++;
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
            influxd_statistics.gauges.flow_detected_count++;
        }

        if (flow_risk != NULL)
        {
            if (flow_user_data->risks[0] == 0)
            {
                influxd_statistics.counters.flow_risky_count++;
            }

            while ((current = nDPIsrvd_get_next_token(sock, flow_risk, &next_child_index)) != NULL)
            {
                size_t numeric_risk_len = 0;
                char const * const numeric_risk_str = TOKEN_GET_KEY(sock, current, &numeric_risk_len);
                nDPIsrvd_ull numeric_risk_value = (nDPIsrvd_ull)-1;
                char numeric_risk_buf[numeric_risk_len + 1];

                if (numeric_risk_len > 0 && numeric_risk_str != NULL)
                {
                    strncpy(numeric_risk_buf, numeric_risk_str, numeric_risk_len);
                    numeric_risk_buf[numeric_risk_len] = '\0';

                    if (flow_user_data->severity == 0 && flow_user_data->severity_ndpid_invalid == 0)
                    {
                        struct nDPIsrvd_json_token const * const severity =
                            TOKEN_GET_SZ(sock, "ndpi", "flow_risk", numeric_risk_buf, "severity");
                        if (influxd_map_flow_u8(sock,
                                                severity,
                                                severity_map,
                                                nDPIsrvd_ARRAY_LENGTH(severity_map),
                                                &flow_user_data->severity) != 0 ||
                            influxd_map_value_to_stat(
                                sock, severity, severity_map, nDPIsrvd_ARRAY_LENGTH(severity_map)) != 0)
                        {
                            size_t value_len = 0;
                            char const * const value_str = TOKEN_GET_VALUE(sock, severity, &value_len);

                            flow_user_data->severity = 0;
                            flow_user_data->severity_ndpid_invalid = 1;
                            if (value_len > 0 && value_str != NULL)
                            {
                                logger(1,
                                       "Unknown/Invalid JSON value for key 'ndpi','breed': %.*s",
                                       (int)value_len,
                                       value_str);
                            }
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

                                influxd_statistics.gauges.flow_risk_count[numeric_risk_value]++;
                                flow_user_data->risks[i] = numeric_risk_value;
                            }
                        }
                        else if (flow_user_data->risk_ndpid_invalid == 0)
                        {
                            flow_user_data->risk_ndpid_invalid = 1;
                            influxd_statistics.gauges.flow_risk_unknown_count++;
                        }
                    }
                    else
                    {
                        logger(1, "Invalid numeric risk value: %s", numeric_risk_buf);
                    }
                }
                else
                {
                    logger(1, "%s", "Missing numeric risk value");
                }
            }
        }

        if (flow_user_data->breed == 0 && flow_user_data->breed_ndpid_invalid == 0)
        {
            struct nDPIsrvd_json_token const * const breed = TOKEN_GET_SZ(sock, "ndpi", "breed");
            if (influxd_map_flow_u8(
                    sock, breed, breeds_map, nDPIsrvd_ARRAY_LENGTH(breeds_map), &flow_user_data->breed) != 0 ||
                influxd_map_value_to_stat(sock, breed, breeds_map, nDPIsrvd_ARRAY_LENGTH(breeds_map)) != 0)
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
            if (influxd_map_flow_u8(
                    sock, category, categories_map, nDPIsrvd_ARRAY_LENGTH(categories_map), &flow_user_data->category) !=
                    0 ||
                influxd_map_value_to_stat(sock, category, categories_map, nDPIsrvd_ARRAY_LENGTH(categories_map)) != 0)
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
            struct nDPIsrvd_json_token const * current = NULL;
            int next_child_index = -1;

            if ((current = nDPIsrvd_get_next_token(sock, token, &next_child_index)) == NULL)
            {
                flow_user_data->confidence_ndpid_invalid = 1;
            }
            else if (nDPIsrvd_get_next_token(sock, token, &next_child_index) == NULL)
            {
                if (influxd_map_flow_u8(sock,
                                        current,
                                        confidence_map,
                                        nDPIsrvd_ARRAY_LENGTH(confidence_map),
                                        &flow_user_data->confidence) != 0 ||
                    influxd_map_value_to_stat(sock, current, confidence_map, nDPIsrvd_ARRAY_LENGTH(confidence_map)) !=
                        0)
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
                char const * const value_str = TOKEN_GET_VALUE(sock, current, &value_len);

                logger(1, "Unknown/Invalid JSON value for key 'ndpi','confidence': %.*s", (int)value_len, value_str);
            }
        }
    }
    else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "end") != 0 ||
             TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "idle") != 0)
    {
        influxd_unmap_flow_from_stat(flow_user_data);
    }
}

static enum nDPIsrvd_callback_return influxd_json_callback(struct nDPIsrvd_socket * const sock,
                                                           struct nDPIsrvd_instance * const instance,
                                                           struct nDPIsrvd_thread_data * const thread_data,
                                                           struct nDPIsrvd_flow * const flow)
{
    (void)instance;
    (void)thread_data;

    pthread_mutex_lock(&influxd_statistics.rw_lock);

    influxd_statistics.counters.json_lines++;
    influxd_statistics.counters.json_bytes += sock->buffer.json_message_length + NETWORK_BUFFER_LENGTH_DIGITS;

    process_flow_stats(sock, flow);

    influxd_map_value_to_stat(sock,
                              TOKEN_GET_SZ(sock, "flow_event_name"),
                              flow_event_map,
                              nDPIsrvd_ARRAY_LENGTH(flow_event_map));
    influxd_map_value_to_stat(sock,
                              TOKEN_GET_SZ(sock, "packet_event_name"),
                              packet_event_map,
                              nDPIsrvd_ARRAY_LENGTH(packet_event_map));
    influxd_map_value_to_stat(sock,
                              TOKEN_GET_SZ(sock, "daemon_event_name"),
                              daemon_event_map,
                              nDPIsrvd_ARRAY_LENGTH(daemon_event_map));
    influxd_map_value_to_stat(sock,
                              TOKEN_GET_SZ(sock, "error_event_name"),
                              error_event_map,
                              nDPIsrvd_ARRAY_LENGTH(error_event_map));

    pthread_mutex_unlock(&influxd_statistics.rw_lock);
    return CALLBACK_OK;
}

static int set_influxd_timer(void)
{
    const time_t interval = influxdb_interval_ull * 1000;
    struct itimerspec its;
    its.it_value.tv_sec = interval / 1000;
    its.it_value.tv_nsec = (interval % 1000) * 1000000;
    its.it_interval.tv_nsec = 0;
    its.it_interval.tv_sec = 0;

    errno = 0;
    return timerfd_settime(influxd_timerfd, 0, &its, NULL);
}

static int create_influxd_timer(void)
{
    influxd_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (influxd_timerfd < 0)
    {
        return 1;
    }

    return set_influxd_timer();
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

            if (events[i].data.fd == influxd_timerfd)
            {
                uint64_t expirations;

                errno = 0;
                if (read(influxd_timerfd, &expirations, sizeof(expirations)) != sizeof(expirations))
                {
                    logger(1, "Could not read timer expirations: %s", strerror(errno));
                    return 1;
                }
                if (set_influxd_timer() != 0)
                {
                    logger(1, "Could not set timer: %s", strerror(errno));
                    return 1;
                }

                start_influxdb_thread();
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

static int parse_options(int argc, char ** argv, struct nDPIsrvd_socket * const sock)
{
    int opt;

    static char const usage[] =
        "Usage: %s "
        "[-c] [-d] [-p pidfile] [-s host] [-u user] [-g group]\n"
        "\t  \t[-i interval] [-U URL] [-T token]\n\n"
        "\t-c\tLog to console instead of syslog.\n"
        "\t-d\tForking into background after initialization.\n"
        "\t-p\tWrite the daemon PID to the given file path.\n"
        "\t-s\tDestination where nDPIsrvd is listening on.\n"
        "\t-u\tChange user.\n"
        "\t-g\tChange group.\n"
        "\t-i\tInterval between pushing statistics to an influxdb endpoint.\n"
        "\t-U\tInfluxDB URL.\n"
        "\t  \tExample: http://127.0.0.1:8086/write?db=ndpi-daemon\n"
        "\t-T\tInfluxDB access token.\n"
        "\t  \tNot recommended, use environment variable INFLUXDB_AUTH_TOKEN instead.\n";

    while ((opt = getopt(argc, argv, "hcdp:s:u:g:i:U:T:")) != -1)
    {
        switch (opt)
        {
            case 'c':
                enable_console_logger();
                break;
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
            case 'i':
                free(influxdb_interval);
                influxdb_interval = strdup(optarg);
                break;
            case 'U':
                free(influxdb_url);
                influxdb_url = strdup(optarg);
                break;
            case 'T':
                free(influxdb_token);
                influxdb_token = strdup(optarg);
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

    if (influxdb_interval == NULL)
    {
        influxdb_interval = strdup("60");
    }

    if (str_value_to_ull(influxdb_interval, &influxdb_interval_ull) != CONVERSION_OK)
    {
        logger_early(1, "InfluxDB push interval `%s' is not a valid number", influxdb_interval);
        return 1;
    }

    if (influxdb_url == NULL)
    {
        logger_early(1, "%s", "Missing InfluxDB URL.");
        return 1;
    }

    if (influxdb_token == NULL && getenv("INFLUXDB_AUTH_TOKEN") != NULL)
    {
        influxdb_token = strdup(getenv("INFLUXDB_AUTH_TOKEN"));
    }
    if (influxdb_token == NULL)
    {
        logger_early(1, "%s", "Missing InfluxDB authentication token.");
        return 1;
    }

    if (nDPIsrvd_setup_address(&sock->address, serv_optarg) != 0)
    {
        logger_early(1, "Could not parse address `%s'", serv_optarg);
        return 1;
    }

    if (optind < argc)
    {
        logger_early(1, "%s", "Unexpected argument after options");
        logger_early(1, "%s", "");
        logger_early(1, usage, argv[0]);
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
    enum nDPIsrvd_connect_return connect_ret;
    int retval = 1, epollfd = -1;

    init_logging("nDPIsrvd-influxd");

    struct nDPIsrvd_socket * sock =
        nDPIsrvd_socket_init(0, 0, 0, sizeof(struct flow_user_data), influxd_json_callback, NULL, NULL);
    if (sock == NULL)
    {
        logger_early(1, "%s", "nDPIsrvd socket memory allocation failed!");
        goto failure;
    }

    if (parse_options(argc, argv, sock) != 0)
    {
        goto failure;
    }

    logger_early(0, "Recv buffer size: %u", NETWORK_BUFFER_MAX_SIZE);
    logger_early(0, "Connecting to `%s'..", serv_optarg);
    logger_early(0, "InfluxDB push URL: %s", influxdb_url);

    if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
    {
        logger_early(1,
                     "Could not set stdout unbuffered: %s. Collectd may receive too old PUTVALs and complain.",
                     strerror(errno));
    }

    connect_ret = nDPIsrvd_connect(sock);
    if (connect_ret != CONNECT_OK)
    {
        logger_early(1, "nDPIsrvd socket connect to %s failed!", serv_optarg);
        goto failure;
    }

    if (nDPIsrvd_set_nonblock(sock) != 0)
    {
        logger_early(1, "nDPIsrvd set nonblock failed: %s", strerror(errno));
        goto failure;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    if (daemonize_with_pidfile(pidfile) != 0)
    {
        goto failure;
    }

    errno = 0;
    if (user != NULL && change_user_group(user, group, pidfile, NULL, NULL) != 0)
    {
        if (errno != 0)
        {
            logger_early(1, "Change user/group failed: %s", strerror(errno));
        }
        else
        {
            logger_early(1, "%s", "Change user/group failed.");
        }
        goto failure;
    }

    epollfd = epoll_create1(0);
    if (epollfd < 0)
    {
        logger_early(1, "Error creating epoll: %s", strerror(errno));
        goto failure;
    }

    if (create_influxd_timer() != 0)
    {
        logger_early(1, "Error creating timer: %s", strerror(errno));
        goto failure;
    }

    {
        struct epoll_event timer_event = {.data.fd = influxd_timerfd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, influxd_timerfd, &timer_event) < 0)
        {
            logger_early(1, "Error adding JSON fd to epoll: %s", strerror(errno));
            goto failure;
        }
    }

    {
        struct epoll_event socket_event = {.data.fd = sock->fd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock->fd, &socket_event) < 0)
        {
            logger_early(1, "Error adding nDPIsrvd socket fd to epoll: %s", strerror(errno));
            goto failure;
        }
    }

    curl_global_init(CURL_GLOBAL_ALL);

    logger_early(0, "%s", "Initialization succeeded.");
    retval = mainloop(epollfd, sock);
    logger_early(0, "%s", "Bye.");

    curl_global_cleanup();
failure:
    nDPIsrvd_socket_free(&sock);
    close(influxd_timerfd);
    close(epollfd);
    daemonize_shutdown(pidfile);
    shutdown_logging();

    return retval;
}
