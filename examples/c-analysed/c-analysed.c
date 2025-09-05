#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <ndpi_typedefs.h>

#include "nDPIsrvd.h"
#include "utils.h"

#define BUFFER_MAX (NETWORK_BUFFER_MAX_SIZE / 3)
#define BUFFER_REMAINING(siz) (BUFFER_MAX - siz)
#define MAX_RISKS_PER_FLOW 8
#define MAX_SEVERITIES_PER_FLOW 4

typedef char csv_buf_t[(NETWORK_BUFFER_MAX_SIZE / 3) + 1];

static int main_thread_shutdown = 0;
static int analysed_timerfd = -1;
static struct nDPIsrvd_socket * distributor = NULL;

static char * pidfile = NULL;
static char * serv_optarg = NULL;
static char * user = NULL;
static char * group = NULL;
static char * analysed_interval = NULL;
static nDPIsrvd_ull analysed_interval_ull = 0uL;
static char * csv_outfile = NULL;
static FILE * csv_fp = NULL;
static char * stats_csv_outfile = NULL;
static FILE * stats_csv_fp = NULL;

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
        uint64_t flow_category_health_count;
        uint64_t flow_category_ai_count;
        uint64_t flow_category_finance_count;
        uint64_t flow_category_news_count;
        uint64_t flow_category_sport_count;
        uint64_t flow_category_business_count;
        uint64_t flow_category_internet_count;
        uint64_t flow_category_blockchain_count;
        uint64_t flow_category_blog_count;
        uint64_t flow_category_gov_count;
        uint64_t flow_category_edu_count;
        uint64_t flow_category_cdn_count;
        uint64_t flow_category_hwsw_count;
        uint64_t flow_category_dating_count;
        uint64_t flow_category_travel_count;
        uint64_t flow_category_food_count;
        uint64_t flow_category_bots_count;
        uint64_t flow_category_scanners_count;
        uint64_t flow_category_hosting_count;
        uint64_t flow_category_art_count;
        uint64_t flow_category_fashion_count;
        uint64_t flow_category_books_count;
        uint64_t flow_category_science_count;
        uint64_t flow_category_maps_count;
        uint64_t flow_category_login_count;
        uint64_t flow_category_legal_count;
        uint64_t flow_category_envsrv_count;
        uint64_t flow_category_culture_count;
        uint64_t flow_category_housing_count;
        uint64_t flow_category_telecom_count;
        uint64_t flow_category_transport_count;
        uint64_t flow_category_design_count;
        uint64_t flow_category_employ_count;
        uint64_t flow_category_events_count;
        uint64_t flow_category_weather_count;
        uint64_t flow_category_lifestyle_count;
        uint64_t flow_category_real_count;
        uint64_t flow_category_security_count;
        uint64_t flow_category_env_count;
        uint64_t flow_category_hobby_count;
        uint64_t flow_category_comp_count;
        uint64_t flow_category_const_count;
        uint64_t flow_category_eng_count;
        uint64_t flow_category_reli_count;
        uint64_t flow_category_enter_count;
        uint64_t flow_category_agri_count;
        uint64_t flow_category_tech_count;
        uint64_t flow_category_beauty_count;
        uint64_t flow_category_history_count;
        uint64_t flow_category_polit_count;
        uint64_t flow_category_vehi_count;
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
    } gauges[2]; /* values after CSV write: gauges[0] -= gauges[1], gauges[1] is zero'd afterwards */
} analysed_statistics = {};

struct global_map
{
    char const * const json_key;
    struct
    {
        uint64_t * const global_stat_inc;
        uint64_t * const global_stat_dec;
    };
};

#define ANALYSED_STATS_COUNTER_PTR(member)                                                                             \
    {                                                                                                                  \
        .global_stat_inc = &(analysed_statistics.counters.member), NULL                                                \
    }
#define ANALYSED_STATS_GAUGE_PTR(member)                                                                               \
    {                                                                                                                  \
        .global_stat_inc = &(analysed_statistics.gauges[0].member),                                                    \
        .global_stat_dec = &(analysed_statistics.gauges[1].member)                                                     \
    }
#define ANALYSED_STATS_COUNTER_INC(member) (analysed_statistics.counters.member++)
#define ANALYSED_STATS_GAUGE_RES(member) (analysed_statistics.gauges[0].member--)
#define ANALYSED_STATS_GAUGE_INC(member) (analysed_statistics.gauges[0].member++)
#define ANALYSED_STATS_GAUGE_DEC(member) (analysed_statistics.gauges[1].member++)
#define ANALYSED_STATS_GAUGE_SUB(member) (analysed_statistics.gauges[0].member -= analysed_statistics.gauges[1].member)
#define ANALYSED_STATS_MAP_NOTNULL(map, index) (map[index - 1].global_stat_dec != NULL)
#define ANALYSED_STATS_MAP_DEC(map, index) ((*map[index - 1].global_stat_dec)++)

static struct global_map const flow_event_map[] = {{"new", ANALYSED_STATS_COUNTER_PTR(flow_new_count)},
                                                   {"end", ANALYSED_STATS_COUNTER_PTR(flow_end_count)},
                                                   {"idle", ANALYSED_STATS_COUNTER_PTR(flow_idle_count)},
                                                   {"update", ANALYSED_STATS_COUNTER_PTR(flow_update_count)},
                                                   {"analyse", ANALYSED_STATS_COUNTER_PTR(flow_analyse_count)},
                                                   {"guessed", ANALYSED_STATS_COUNTER_PTR(flow_guessed_count)},
                                                   {"detected", ANALYSED_STATS_COUNTER_PTR(flow_detected_count)},
                                                   {"detection-update",
                                                    ANALYSED_STATS_COUNTER_PTR(flow_detection_update_count)},
                                                   {"not-detected",
                                                    ANALYSED_STATS_COUNTER_PTR(flow_not_detected_count)}};

static struct global_map const packet_event_map[] = {{"packet", ANALYSED_STATS_COUNTER_PTR(packet_count)},
                                                     {"packet-flow", ANALYSED_STATS_COUNTER_PTR(packet_flow_count)}};

static struct global_map const daemon_event_map[] = {{"init", ANALYSED_STATS_COUNTER_PTR(init_count)},
                                                     {"reconnect", ANALYSED_STATS_COUNTER_PTR(reconnect_count)},
                                                     {"shutdown", ANALYSED_STATS_COUNTER_PTR(shutdown_count)},
                                                     {"status", ANALYSED_STATS_COUNTER_PTR(status_count)}};

static struct global_map const error_event_map[] = {
    {"Unknown datalink layer packet", ANALYSED_STATS_COUNTER_PTR(error_unknown_datalink)},
    {"Unknown L3 protocol", ANALYSED_STATS_COUNTER_PTR(error_unknown_l3_protocol)},
    {"Unsupported datalink layer", ANALYSED_STATS_COUNTER_PTR(error_unsupported_datalink)},
    {"Packet too short", ANALYSED_STATS_COUNTER_PTR(error_packet_too_short)},
    {"Unknown packet type", ANALYSED_STATS_COUNTER_PTR(error_packet_type_unknown)},
    {"Packet header invalid", ANALYSED_STATS_COUNTER_PTR(error_packet_header_invalid)},
    {"IP4 packet too short", ANALYSED_STATS_COUNTER_PTR(error_ip4_packet_too_short)},
    {"Packet smaller than IP4 header", ANALYSED_STATS_COUNTER_PTR(error_ip4_size_smaller_than_header)},
    {"nDPI IPv4\\/L4 payload detection failed", ANALYSED_STATS_COUNTER_PTR(error_ip4_l4_payload_detection)},
    {"IP6 packet too short", ANALYSED_STATS_COUNTER_PTR(error_ip6_packet_too_short)},
    {"Packet smaller than IP6 header", ANALYSED_STATS_COUNTER_PTR(error_ip6_size_smaller_than_header)},
    {"nDPI IPv6\\/L4 payload detection failed", ANALYSED_STATS_COUNTER_PTR(error_ip6_l4_payload_detection)},
    {"TCP packet smaller than expected", ANALYSED_STATS_COUNTER_PTR(error_tcp_packet_too_short)},
    {"UDP packet smaller than expected", ANALYSED_STATS_COUNTER_PTR(error_udp_packet_too_short)},
    {"Captured packet size is smaller than expected packet size",
     ANALYSED_STATS_COUNTER_PTR(error_capture_size_smaller_than_packet)},
    {"Max flows to track reached", ANALYSED_STATS_COUNTER_PTR(error_max_flows_to_track)},
    {"Flow memory allocation failed", ANALYSED_STATS_COUNTER_PTR(error_flow_memory_alloc)}};

static struct global_map const breeds_map[] = {{"Safe", ANALYSED_STATS_GAUGE_PTR(flow_breed_safe_count)},
                                               {"Acceptable", ANALYSED_STATS_GAUGE_PTR(flow_breed_acceptable_count)},
                                               {"Fun", ANALYSED_STATS_GAUGE_PTR(flow_breed_fun_count)},
                                               {"Unsafe", ANALYSED_STATS_GAUGE_PTR(flow_breed_unsafe_count)},
                                               {"Potentially_Dangerous",
                                                ANALYSED_STATS_GAUGE_PTR(flow_breed_potentially_dangerous_count)},
                                               {"Tracker_Ads", ANALYSED_STATS_GAUGE_PTR(flow_breed_tracker_ads_count)},
                                               {"Dangerous", ANALYSED_STATS_GAUGE_PTR(flow_breed_dangerous_count)},
                                               {"Unrated", ANALYSED_STATS_GAUGE_PTR(flow_breed_unrated_count)},
                                               {NULL, ANALYSED_STATS_GAUGE_PTR(flow_breed_unknown_count)}};

static struct global_map const categories_map[] = {
    {"Unspecified", ANALYSED_STATS_GAUGE_PTR(flow_category_unspecified_count)},
    {"Media", ANALYSED_STATS_GAUGE_PTR(flow_category_media_count)},
    {"VPN", ANALYSED_STATS_GAUGE_PTR(flow_category_vpn_count)},
    {"Email", ANALYSED_STATS_GAUGE_PTR(flow_category_email_count)},
    {"DataTransfer", ANALYSED_STATS_GAUGE_PTR(flow_category_data_transfer_count)},
    {"Web", ANALYSED_STATS_GAUGE_PTR(flow_category_web_count)},
    {"SocialNetwork", ANALYSED_STATS_GAUGE_PTR(flow_category_social_network_count)},
    {"Download", ANALYSED_STATS_GAUGE_PTR(flow_category_download_count)},
    {"Game", ANALYSED_STATS_GAUGE_PTR(flow_category_game_count)},
    {"Chat", ANALYSED_STATS_GAUGE_PTR(flow_category_chat_count)},
    {"VoIP", ANALYSED_STATS_GAUGE_PTR(flow_category_voip_count)},
    {"Database", ANALYSED_STATS_GAUGE_PTR(flow_category_database_count)},
    {"RemoteAccess", ANALYSED_STATS_GAUGE_PTR(flow_category_remote_access_count)},
    {"Cloud", ANALYSED_STATS_GAUGE_PTR(flow_category_cloud_count)},
    {"Network", ANALYSED_STATS_GAUGE_PTR(flow_category_network_count)},
    {"Collaborative", ANALYSED_STATS_GAUGE_PTR(flow_category_collaborative_count)},
    {"RPC", ANALYSED_STATS_GAUGE_PTR(flow_category_rpc_count)},
    {"Streaming", ANALYSED_STATS_GAUGE_PTR(flow_category_streaming_count)},
    {"System", ANALYSED_STATS_GAUGE_PTR(flow_category_system_count)},
    {"SoftwareUpdate", ANALYSED_STATS_GAUGE_PTR(flow_category_software_update_count)},
    {"Music", ANALYSED_STATS_GAUGE_PTR(flow_category_music_count)},
    {"Video", ANALYSED_STATS_GAUGE_PTR(flow_category_video_count)},
    {"Shopping", ANALYSED_STATS_GAUGE_PTR(flow_category_shopping_count)},
    {"Productivity", ANALYSED_STATS_GAUGE_PTR(flow_category_productivity_count)},
    {"FileSharing", ANALYSED_STATS_GAUGE_PTR(flow_category_file_sharing_count)},
    {"ConnCheck", ANALYSED_STATS_GAUGE_PTR(flow_category_conn_check_count)},
    {"IoT-Scada", ANALYSED_STATS_GAUGE_PTR(flow_category_iot_scada_count)},
    {"VirtAssistant", ANALYSED_STATS_GAUGE_PTR(flow_category_virt_assistant_count)},
    {"Cybersecurity", ANALYSED_STATS_GAUGE_PTR(flow_category_cybersecurity_count)},
    {"AdultContent", ANALYSED_STATS_GAUGE_PTR(flow_category_adult_content_count)},
    {"Mining", ANALYSED_STATS_GAUGE_PTR(flow_category_mining_count)},
    {"Malware", ANALYSED_STATS_GAUGE_PTR(flow_category_malware_count)},
    {"Advertisement", ANALYSED_STATS_GAUGE_PTR(flow_category_advertisment_count)},
    {"Banned_Site", ANALYSED_STATS_GAUGE_PTR(flow_category_banned_site_count)},
    {"Site_Unavailable", ANALYSED_STATS_GAUGE_PTR(flow_category_site_unavail_count)},
    {"Allowed_Site", ANALYSED_STATS_GAUGE_PTR(flow_category_allowed_site_count)},
    {"Antimalware", ANALYSED_STATS_GAUGE_PTR(flow_category_antimalware_count)},
    {"Crypto_Currency", ANALYSED_STATS_GAUGE_PTR(flow_category_crypto_currency_count)},
    {"Gambling", ANALYSED_STATS_GAUGE_PTR(flow_category_gambling_count)},
    {"Health", ANALYSED_STATS_GAUGE_PTR(flow_category_health_count)},
    {"ArtifIntelligence", ANALYSED_STATS_GAUGE_PTR(flow_category_ai_count)},
    {"Finance", ANALYSED_STATS_GAUGE_PTR(flow_category_finance_count)},
    {"News", ANALYSED_STATS_GAUGE_PTR(flow_category_news_count)},
    {"Sport", ANALYSED_STATS_GAUGE_PTR(flow_category_sport_count)},
    {"Business", ANALYSED_STATS_GAUGE_PTR(flow_category_business_count)},
    {"Internet", ANALYSED_STATS_GAUGE_PTR(flow_category_internet_count)},
    {"Blockchain_Crypto", ANALYSED_STATS_GAUGE_PTR(flow_category_blockchain_count)},
    {"Blog_Forum", ANALYSED_STATS_GAUGE_PTR(flow_category_blog_count)},
    {"Government", ANALYSED_STATS_GAUGE_PTR(flow_category_gov_count)},
    {"Education", ANALYSED_STATS_GAUGE_PTR(flow_category_edu_count)},
    {"CDN_Proxy", ANALYSED_STATS_GAUGE_PTR(flow_category_cdn_count)},
    {"Hw_Sw", ANALYSED_STATS_GAUGE_PTR(flow_category_hwsw_count)},
    {"Dating", ANALYSED_STATS_GAUGE_PTR(flow_category_dating_count)},
    {"Travel", ANALYSED_STATS_GAUGE_PTR(flow_category_travel_count)},
    {"Food", ANALYSED_STATS_GAUGE_PTR(flow_category_food_count)},
    {"Bots", ANALYSED_STATS_GAUGE_PTR(flow_category_bots_count)},
    {"Scanners", ANALYSED_STATS_GAUGE_PTR(flow_category_scanners_count)},
    {"Hosting", ANALYSED_STATS_GAUGE_PTR(flow_category_hosting_count)},
    {"Art", ANALYSED_STATS_GAUGE_PTR(flow_category_art_count)},
    {"Fashion", ANALYSED_STATS_GAUGE_PTR(flow_category_fashion_count)},
    {"Books", ANALYSED_STATS_GAUGE_PTR(flow_category_books_count)},
    {"Science", ANALYSED_STATS_GAUGE_PTR(flow_category_science_count)},
    {"Maps_Navigation", ANALYSED_STATS_GAUGE_PTR(flow_category_maps_count)},
    {"Login_Portal", ANALYSED_STATS_GAUGE_PTR(flow_category_login_count)},
    {"Legal", ANALYSED_STATS_GAUGE_PTR(flow_category_legal_count)},
    {"Environmental_Services", ANALYSED_STATS_GAUGE_PTR(flow_category_envsrv_count)},
    {"Culture", ANALYSED_STATS_GAUGE_PTR(flow_category_culture_count)},
    {"Housing", ANALYSED_STATS_GAUGE_PTR(flow_category_housing_count)},
    {"Telecommunication", ANALYSED_STATS_GAUGE_PTR(flow_category_telecom_count)},
    {"Transportation", ANALYSED_STATS_GAUGE_PTR(flow_category_transport_count)},
    {"Design", ANALYSED_STATS_GAUGE_PTR(flow_category_design_count)},
    {"Employment", ANALYSED_STATS_GAUGE_PTR(flow_category_employ_count)},
    {"Events", ANALYSED_STATS_GAUGE_PTR(flow_category_events_count)},
    {"Weather", ANALYSED_STATS_GAUGE_PTR(flow_category_weather_count)},
    {"Lifestyle", ANALYSED_STATS_GAUGE_PTR(flow_category_lifestyle_count)},
    {"Real_Estate", ANALYSED_STATS_GAUGE_PTR(flow_category_real_count)},
    {"Security", ANALYSED_STATS_GAUGE_PTR(flow_category_security_count)},
    {"Environment", ANALYSED_STATS_GAUGE_PTR(flow_category_env_count)},
    {"Hobby", ANALYSED_STATS_GAUGE_PTR(flow_category_hobby_count)},
    {"Computer_Science", ANALYSED_STATS_GAUGE_PTR(flow_category_comp_count)},
    {"Construction", ANALYSED_STATS_GAUGE_PTR(flow_category_const_count)},
    {"Engineering", ANALYSED_STATS_GAUGE_PTR(flow_category_eng_count)},
    {"Religion", ANALYSED_STATS_GAUGE_PTR(flow_category_reli_count)},
    {"Entertainment", ANALYSED_STATS_GAUGE_PTR(flow_category_enter_count)},
    {"Agriculture", ANALYSED_STATS_GAUGE_PTR(flow_category_agri_count)},
    {"Technology", ANALYSED_STATS_GAUGE_PTR(flow_category_tech_count)},
    {"Beauty", ANALYSED_STATS_GAUGE_PTR(flow_category_beauty_count)},
    {"History", ANALYSED_STATS_GAUGE_PTR(flow_category_history_count)},
    {"Politics", ANALYSED_STATS_GAUGE_PTR(flow_category_polit_count)},
    {"Vehicles", ANALYSED_STATS_GAUGE_PTR(flow_category_vehi_count)},
    {NULL, ANALYSED_STATS_GAUGE_PTR(flow_category_unknown_count)}};

static struct global_map const confidence_map[] = {
    {"Match by port", ANALYSED_STATS_GAUGE_PTR(flow_confidence_by_port)},
    {"DPI (partial)", ANALYSED_STATS_GAUGE_PTR(flow_confidence_dpi_partial)},
    {"DPI (partial cache)", ANALYSED_STATS_GAUGE_PTR(flow_confidence_dpi_partial_cache)},
    {"DPI (cache)", ANALYSED_STATS_GAUGE_PTR(flow_confidence_dpi_cache)},
    {"DPI", ANALYSED_STATS_GAUGE_PTR(flow_confidence_dpi)},
    {"nBPF", ANALYSED_STATS_GAUGE_PTR(flow_confidence_nbpf)},
    {"Match by IP", ANALYSED_STATS_GAUGE_PTR(flow_confidence_by_ip)},
    {"DPI (aggressive)", ANALYSED_STATS_GAUGE_PTR(flow_confidence_dpi_aggressive)},
    {"Match by custom rule", ANALYSED_STATS_GAUGE_PTR(flow_confidence_custom_rule)},
    {NULL, ANALYSED_STATS_GAUGE_PTR(flow_confidence_unknown)}};

static struct global_map const severity_map[] = {{"Low", ANALYSED_STATS_GAUGE_PTR(flow_severity_low)},
                                                 {"Medium", ANALYSED_STATS_GAUGE_PTR(flow_severity_medium)},
                                                 {"High", ANALYSED_STATS_GAUGE_PTR(flow_severity_high)},
                                                 {"Severe", ANALYSED_STATS_GAUGE_PTR(flow_severity_severe)},
                                                 {"Critical", ANALYSED_STATS_GAUGE_PTR(flow_severity_critical)},
                                                 {"Emergency", ANALYSED_STATS_GAUGE_PTR(flow_severity_emergency)},
                                                 {NULL, ANALYSED_STATS_GAUGE_PTR(flow_severity_unknown)}};

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
    logger(0, "%s", "nDPIsrvd MemoryProfiler: ");
    vlogger(0, format, ap);
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

    if (flow == NULL || thread_data == NULL)
    {
        logger(0, "%s", "[WriteFlowInfoCallback] BUG: Internal error.");
        return;
    }

    logger(0,
           "[Thread %2d][Flow %5llu][ptr: "
#ifdef __LP64__
           "0x%016llx"
#else
           "0x%08lx"
#endif
           "][last-seen: %13llu][idle-time: %7llu][time-until-timeout: %7llu]",
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
            logger(1,
                   "Thread %d / %d, Flow %llu verification failed",
                   thread_data->thread_key,
                   flow->thread_id,
                   flow->id_as_ull);
        }
        else
        {
            logger(1,
                   "Thread %d / %d, Flow %llu verification failed, diff: %llu",
                   thread_data->thread_key,
                   flow->thread_id,
                   flow->id_as_ull,
                   thread_data->most_recent_flow_time - flow->last_seen + flow->idle_time);
        }
    }
    else
    {
        logger(1, "Thread [UNKNOWN], Flow %llu verification failed", flow->id_as_ull);
    }
}

static void sighandler(int signum)
{
    struct nDPIsrvd_instance * current_instance;
    struct nDPIsrvd_instance * itmp;
    int verification_failed = 0;

    if (signum == SIGUSR1)
    {
        nDPIsrvd_flow_info(distributor, nDPIsrvd_write_flow_info_cb, NULL);

        HASH_ITER(hh, distributor->instance_table, current_instance, itmp)
        {
            if (nDPIsrvd_verify_flows(current_instance, nDPIsrvd_verify_flows_cb, NULL) != 0)
            {
                logger(1, "Flow verification failed for instance %d", current_instance->alias_source_key);
                verification_failed = 1;
            }
        }
        if (verification_failed == 0)
        {
            logger(1, "%s", "Flow verification succeeded.");
        }
        else
        {
            /* FATAL! */
            exit(EXIT_FAILURE);
        }
    }
    else if (signum == SIGUSR2)
    {
        if (csv_fp != NULL)
        {
            fflush(csv_fp);
        }
        if (stats_csv_fp != NULL)
        {
            fflush(stats_csv_fp);
        }
    }
    else if (main_thread_shutdown == 0)
    {
        main_thread_shutdown = 1;
    }
}

static void csv_buf_add(csv_buf_t buf, size_t * const csv_buf_used, char const * const str, size_t siz_len)
{
    size_t len;

    if (siz_len > 0 && str != NULL)
    {
        len = MIN(BUFFER_REMAINING(*csv_buf_used), siz_len);
        if (len == 0)
        {
            return;
        }
        snprintf(buf + *csv_buf_used, BUFFER_MAX - len, "%.*s", (int)len, str);
    }
    else
    {
        len = 0;
    }

    *csv_buf_used += len;
    if (BUFFER_REMAINING(*csv_buf_used) > 0)
    {
        buf[*csv_buf_used] = ',';
        (*csv_buf_used)++;
    }
    buf[*csv_buf_used] = '\0';
}

static int json_value_to_csv(
    struct nDPIsrvd_socket * const sock, csv_buf_t buf, size_t * const csv_buf_used, char const * const json_key, ...)
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

    csv_buf_add(buf, csv_buf_used, val, val_length);

    return ret;
}

static int json_array_to_csv(
    struct nDPIsrvd_socket * const sock, csv_buf_t buf, size_t * const csv_buf_used, char const * const json_key, ...)
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
        csv_buf_add(buf, csv_buf_used, NULL, 0);
    }

    {
        size_t token_count = 0;
        struct nDPIsrvd_json_token next = {};

        csv_buf_add(buf, csv_buf_used, "\"", 1);
        buf[--(*csv_buf_used)] = '\0';
        while (nDPIsrvd_token_iterate(sock, token, &next) == 0)
        {
            size_t val_length = 0;
            char const * const val = TOKEN_GET_VALUE(sock, &next, &val_length);

            csv_buf_add(buf, csv_buf_used, val, val_length);
            token_count++;
        }
        if (token_count > 0)
        {
            buf[--(*csv_buf_used)] = '\0';
        }
        csv_buf_add(buf, csv_buf_used, "\"", 1);
    }

    return ret;
}

static int analysed_map_to_stat(char const * const token_str,
                                size_t token_length,
                                struct global_map const * const map,
                                size_t map_length)
{
    size_t i;
    size_t null_i = map_length;

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

static int analysed_map_value_to_stat(struct nDPIsrvd_socket const * const sock,
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

    return analysed_map_to_stat(value_str, value_length, map, map_length);
}

static void analysed_unmap_flow_from_stat(struct flow_user_data const * const flow_user_data)
{
    if (flow_user_data->is_ip4 != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_l3_ip4_count);
    }

    if (flow_user_data->is_ip6 != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_l3_ip6_count);
    }

    if (flow_user_data->is_other_l3 != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_l3_other_count);
    }

    if (flow_user_data->is_tcp != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_l4_tcp_count);
    }

    if (flow_user_data->is_udp != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_l4_udp_count);
    }

    if (flow_user_data->is_icmp != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_l4_icmp_count);
    }

    if (flow_user_data->is_other_l4 != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_l4_other_count);
    }

    if (flow_user_data->new_seen != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_active_count);
    }

    if (flow_user_data->is_detected != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_detected_count);
    }

    if (flow_user_data->is_guessed != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_guessed_count);
    }

    if (flow_user_data->is_not_detected != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_not_detected_count);
    }

    if (flow_user_data->is_info != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_state_info);
    }

    if (flow_user_data->is_finished != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_state_finished);
    }

    if (flow_user_data->breed > 0 && flow_user_data->breed_ndpid_invalid == 0 &&
        ANALYSED_STATS_MAP_NOTNULL(breeds_map, flow_user_data->breed) != 0)
    {
        ANALYSED_STATS_MAP_DEC(breeds_map, flow_user_data->breed);
    }

    if (flow_user_data->category > 0 && flow_user_data->category_ndpid_invalid == 0 &&
        ANALYSED_STATS_MAP_NOTNULL(categories_map, flow_user_data->category) != 0)
    {
        ANALYSED_STATS_MAP_DEC(categories_map, flow_user_data->category);
    }

    if (flow_user_data->confidence > 0 && flow_user_data->confidence_ndpid_invalid == 0 &&
        ANALYSED_STATS_MAP_NOTNULL(confidence_map, flow_user_data->confidence) != 0)
    {
        ANALYSED_STATS_MAP_DEC(confidence_map, flow_user_data->confidence);
    }

    for (uint8_t i = 0; i < MAX_SEVERITIES_PER_FLOW; ++i)
    {
        if (flow_user_data->severities[i] > 0)
        {
            ANALYSED_STATS_MAP_DEC(severity_map, flow_user_data->severities[i]);
        }
    }

    for (uint8_t i = 0; i < MAX_RISKS_PER_FLOW; ++i)
    {
        if (flow_user_data->risks[i] > 0)
        {
            ANALYSED_STATS_GAUGE_DEC(flow_risk_count[flow_user_data->risks[i]]);
        }
    }

    if (flow_user_data->risk_ndpid_invalid != 0)
    {
        ANALYSED_STATS_GAUGE_DEC(flow_risk_unknown_count);
    }
}

static ssize_t analysed_map_index(char const * const json_key,
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

static int analysed_map_flow_u8(struct nDPIsrvd_socket const * const sock,
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

    ssize_t const map_index = analysed_map_index(str, len, map, map_length);
    if (map_index < 0 || map_index >= UCHAR_MAX)
    {
        return 1;
    }

    *dest = map_index + 1;
    return 0;
}

static void process_flow_stats(struct nDPIsrvd_socket const * const sock, struct nDPIsrvd_flow * const flow)
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
        ANALYSED_STATS_GAUGE_INC(flow_active_count);

        struct nDPIsrvd_json_token const * const l3_proto = TOKEN_GET_SZ(sock, "l3_proto");
        if (TOKEN_VALUE_EQUALS_SZ(sock, l3_proto, "ip4") != 0)
        {
            flow_user_data->is_ip4 = 1;
            ANALYSED_STATS_GAUGE_INC(flow_l3_ip4_count);
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l3_proto, "ip6") != 0)
        {
            flow_user_data->is_ip6 = 1;
            ANALYSED_STATS_GAUGE_INC(flow_l3_ip6_count);
        }
        else if (l3_proto != NULL)
        {
            flow_user_data->is_other_l3 = 1;
            ANALYSED_STATS_GAUGE_INC(flow_l3_other_count);
        }

        struct nDPIsrvd_json_token const * const l4_proto = TOKEN_GET_SZ(sock, "l4_proto");
        if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "tcp") != 0)
        {
            flow_user_data->is_tcp = 1;
            ANALYSED_STATS_GAUGE_INC(flow_l4_tcp_count);
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "udp") != 0)
        {
            flow_user_data->is_udp = 1;
            ANALYSED_STATS_GAUGE_INC(flow_l4_udp_count);
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "icmp") != 0)
        {
            flow_user_data->is_icmp = 1;
            ANALYSED_STATS_GAUGE_INC(flow_l4_icmp_count);
        }
        else if (l4_proto != NULL)
        {
            flow_user_data->is_other_l4 = 1;
            ANALYSED_STATS_GAUGE_INC(flow_l4_other_count);
        }
    }
    else if (flow_user_data->new_seen == 0)
    {
        return;
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "not-detected") != 0)
    {
        flow_user_data->is_not_detected = 1;
        ANALYSED_STATS_GAUGE_INC(flow_not_detected_count);
    }
    else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "guessed") != 0)
    {
        flow_user_data->is_guessed = 1;
        ANALYSED_STATS_GAUGE_INC(flow_guessed_count);
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
            ANALYSED_STATS_GAUGE_INC(flow_detected_count);
        }

        if (flow_risk != NULL)
        {
            if (flow_user_data->risks[0] == 0)
            {
                ANALYSED_STATS_COUNTER_INC(flow_risky_count);
            }

            while ((current = nDPIsrvd_get_next_token(sock, flow_risk, &next_child_index)) != NULL)
            {
                size_t numeric_risk_len = 0;
                char const * const numeric_risk_str = TOKEN_GET_KEY(sock, current, &numeric_risk_len);
                nDPIsrvd_ull numeric_risk_value = 0;
                char numeric_risk_buf[numeric_risk_len + 1];

                if (numeric_risk_len > 0 && numeric_risk_str != NULL)
                {
                    strncpy(numeric_risk_buf, numeric_risk_str, numeric_risk_len);
                    numeric_risk_buf[numeric_risk_len] = '\0';

                    struct nDPIsrvd_json_token const * const severity =
                        TOKEN_GET_SZ(sock, "ndpi", "flow_risk", numeric_risk_buf, "severity");
                    uint8_t severity_index;

                    if (analysed_map_flow_u8(
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

                            if (analysed_map_value_to_stat(
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
                            logger(1,
                                   "Unknown/Invalid JSON value for key 'ndpi','breed': %.*s",
                                   (int)value_len,
                                   value_str);
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
                                if (numeric_risk_value > UCHAR_MAX)
                                {
                                    logger(1, "BUG: Numeric risk value > 255");
                                }

                                ANALYSED_STATS_GAUGE_INC(flow_risk_count[numeric_risk_value - 1]);
                                flow_user_data->risks[i] = numeric_risk_value - 1;
                                break;
                            }
                        }
                        else if (flow_user_data->risk_ndpid_invalid == 0)
                        {
                            flow_user_data->risk_ndpid_invalid = 1;
                            ANALYSED_STATS_GAUGE_INC(flow_risk_unknown_count);
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
            if (analysed_map_flow_u8(
                    sock, breed, breeds_map, nDPIsrvd_ARRAY_LENGTH(breeds_map), &flow_user_data->breed) != 0 ||
                analysed_map_value_to_stat(sock, breed, breeds_map, nDPIsrvd_ARRAY_LENGTH(breeds_map)) != 0)
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
            if (analysed_map_flow_u8(
                    sock, category, categories_map, nDPIsrvd_ARRAY_LENGTH(categories_map), &flow_user_data->category) !=
                    0 ||
                analysed_map_value_to_stat(sock, category, categories_map, nDPIsrvd_ARRAY_LENGTH(categories_map)) != 0)
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
                if (analysed_map_flow_u8(sock,
                                         current,
                                         confidence_map,
                                         nDPIsrvd_ARRAY_LENGTH(confidence_map),
                                         &flow_user_data->confidence) != 0 ||
                    analysed_map_value_to_stat(sock, current, confidence_map, nDPIsrvd_ARRAY_LENGTH(confidence_map)) !=
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

    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_state, "info") != 0)
    {
        if (flow_user_data->is_info == 0)
        {
            flow_user_data->is_info = 1;
            ANALYSED_STATS_GAUGE_INC(flow_state_info);
        }
    }
    else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_state, "finished") != 0)
    {
        if (flow_user_data->is_finished == 0)
        {
            if (flow_user_data->is_info != 0)
            {
                flow_user_data->is_info = 0;
                ANALYSED_STATS_GAUGE_RES(flow_state_info);
            }
            flow_user_data->is_finished = 1;
            ANALYSED_STATS_GAUGE_INC(flow_state_finished);
        }
    }

    if (TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_src_tot_l4_payload_len"), &total_bytes_ull[0]) ==
            CONVERSION_OK &&
        TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_dst_tot_l4_payload_len"), &total_bytes_ull[1]) ==
            CONVERSION_OK)
    {
        analysed_statistics.counters.flow_src_total_bytes +=
            total_bytes_ull[0] - flow_user_data->last_flow_src_l4_payload_len;
        analysed_statistics.counters.flow_dst_total_bytes +=
            total_bytes_ull[1] - flow_user_data->last_flow_dst_l4_payload_len;

        flow_user_data->last_flow_src_l4_payload_len = total_bytes_ull[0];
        flow_user_data->last_flow_dst_l4_payload_len = total_bytes_ull[1];
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "end") != 0 ||
        TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "idle") != 0)
    {
        analysed_unmap_flow_from_stat(flow_user_data);
    }
}

static void process_global_stats(struct nDPIsrvd_socket const * const sock)
{
    struct nDPIsrvd_json_token const * const flow_event = TOKEN_GET_SZ(sock, "flow_event_name");
    struct nDPIsrvd_json_token const * const packet_event = TOKEN_GET_SZ(sock, "packet_event_name");
    struct nDPIsrvd_json_token const * const daemon_event = TOKEN_GET_SZ(sock, "daemon_event_name");
    struct nDPIsrvd_json_token const * const error_event = TOKEN_GET_SZ(sock, "error_event_name");

    ANALYSED_STATS_COUNTER_INC(json_lines);
    analysed_statistics.counters.json_bytes += sock->buffer.json_message_length + NETWORK_BUFFER_LENGTH_DIGITS;

    if (flow_event != NULL &&
        analysed_map_value_to_stat(sock, flow_event, flow_event_map, nDPIsrvd_ARRAY_LENGTH(flow_event_map)) != 0)
    {
        logger(1, "%s", "Unknown flow_event_name");
    }

    if (packet_event != NULL &&
        analysed_map_value_to_stat(sock, packet_event, packet_event_map, nDPIsrvd_ARRAY_LENGTH(packet_event_map)) != 0)
    {
        logger(1, "%s", "Unknown packet_event_name");
    }

    if (daemon_event != NULL &&
        analysed_map_value_to_stat(sock, daemon_event, daemon_event_map, nDPIsrvd_ARRAY_LENGTH(daemon_event_map)) != 0)
    {
        logger(1, "%s", "Unknown daemon_event_name");
    }

    if (error_event != NULL &&
        analysed_map_value_to_stat(sock, error_event, error_event_map, nDPIsrvd_ARRAY_LENGTH(error_event_map)) != 0)
    {
        logger(1, "%s", "Unknown error_event_name");
    }
}

static enum nDPIsrvd_callback_return process_analyse_events(struct nDPIsrvd_socket * const sock)
{
    csv_buf_t buf;
    size_t csv_buf_used = 0;

    struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");
    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "analyse") == 0)
    {
        return CALLBACK_OK;
    }

    if (TOKEN_GET_SZ(sock, "data_analysis") == NULL)
    {
        return CALLBACK_ERROR;
    }

    buf[0] = '\0';

    json_value_to_csv(sock, buf, &csv_buf_used, "flow_datalink", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "l3_proto", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "src_ip", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "dst_ip", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "l4_proto", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "src_port", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "dst_port", NULL);

    if (json_value_to_csv(sock, buf, &csv_buf_used, "flow_state", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_src_packets_processed", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_dst_packets_processed", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_first_seen", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_src_last_pkt_time", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_dst_last_pkt_time", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_src_min_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_dst_min_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_src_max_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_dst_max_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_src_tot_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "flow_dst_tot_l4_payload_len", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "midstream", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "iat", "min", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "iat", "avg", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "iat", "max", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "iat", "stddev", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "iat", "var", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "iat", "ent", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, buf, &csv_buf_used, "data_analysis", "iat", "data", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "pktlen", "min", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "pktlen", "avg", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "pktlen", "max", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "pktlen", "stddev", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "pktlen", "var", NULL) != 0 ||
        json_value_to_csv(sock, buf, &csv_buf_used, "data_analysis", "pktlen", "ent", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, buf, &csv_buf_used, "data_analysis", "pktlen", "data", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, buf, &csv_buf_used, "data_analysis", "bins", "c_to_s", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, buf, &csv_buf_used, "data_analysis", "bins", "s_to_c", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, buf, &csv_buf_used, "data_analysis", "directions", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    if (json_array_to_csv(sock, buf, &csv_buf_used, "data_analysis", "entropies", NULL) != 0)
    {
        return CALLBACK_ERROR;
    }

    json_value_to_csv(sock, buf, &csv_buf_used, "ndpi", "proto", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "ndpi", "proto_id", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "ndpi", "encrypted", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "ndpi", "breed", NULL);
    json_value_to_csv(sock, buf, &csv_buf_used, "ndpi", "category", NULL);
    {
        struct nDPIsrvd_json_token const * const token = TOKEN_GET_SZ(sock, "ndpi", "confidence");
        struct nDPIsrvd_json_token const * current = NULL;
        int next_child_index = -1;

        if (token == NULL)
        {
            csv_buf_add(buf, &csv_buf_used, NULL, 0);
            csv_buf_add(buf, &csv_buf_used, NULL, 0);
        }
        else
        {
            while ((current = nDPIsrvd_get_next_token(sock, token, &next_child_index)) != NULL)
            {
                size_t key_length = 0, value_length = 0;
                char const * const key = TOKEN_GET_KEY(sock, current, &key_length);
                char const * const value = TOKEN_GET_VALUE(sock, current, &value_length);

                csv_buf_add(buf, &csv_buf_used, key, key_length);
                csv_buf_add(buf, &csv_buf_used, value, value_length);
            }
        }
    }
    {
        csv_buf_t risks;
        size_t csv_risks_used = 0;
        struct nDPIsrvd_json_token const * const flow_risk = TOKEN_GET_SZ(sock, "ndpi", "flow_risk");
        struct nDPIsrvd_json_token const * current = NULL;
        int next_child_index = -1;

        risks[csv_risks_used++] = '"';
        risks[csv_risks_used] = '\0';
        if (flow_risk != NULL)
        {
            while ((current = nDPIsrvd_get_next_token(sock, flow_risk, &next_child_index)) != NULL)
            {
                size_t key_length = 0;
                char const * const key = TOKEN_GET_KEY(sock, current, &key_length);

                csv_buf_add(risks, &csv_risks_used, key, key_length);
            }
        }
        if (csv_risks_used > 1)
        {
            risks[csv_risks_used - 1] = '"';
        }
        else if (BUFFER_REMAINING(csv_risks_used) > 0)
        {
            risks[csv_risks_used++] = '"';
        }
        if (BUFFER_REMAINING(csv_risks_used) > 0)
        {
            risks[csv_risks_used] = '\0';
        }
        else
        {
            risks[csv_risks_used - 1] = '\0';
        }
        csv_buf_add(buf, &csv_buf_used, risks, csv_risks_used);
    }

    if (csv_buf_used > 0 && buf[csv_buf_used - 1] == ',')
    {
        buf[--csv_buf_used] = '\0';
    }

    fprintf(csv_fp, "%.*s\n", (int)csv_buf_used, buf);
    return CALLBACK_OK;
}

static enum nDPIsrvd_callback_return analysed_json_callback(struct nDPIsrvd_socket * const sock,
                                                            struct nDPIsrvd_instance * const instance,
                                                            struct nDPIsrvd_thread_data * const thread_data,
                                                            struct nDPIsrvd_flow * const flow)
{
    (void)instance;
    (void)thread_data;

    if (stats_csv_fp != NULL)
    {
        process_global_stats(sock);
    }

    if (flow == NULL)
    {
        return CALLBACK_OK;
    }

    if (stats_csv_fp != NULL)
    {
        process_flow_stats(sock, flow);
    }

    if (csv_fp != NULL && process_analyse_events(sock) != CALLBACK_OK)
    {
        return CALLBACK_ERROR;
    }

    return CALLBACK_OK;
}

static void print_usage(char const * const arg0)
{
    static char const usage[] =
        "Usage: %s "
        "[-l] [-d] [-p pidfile] [-s host]\n"
        "\t  \t[-u user] [-g group] [-o csv-outfile] [-O csv-outfile]\n\n"
        "\t-l\tLog to console instead of syslog.\n"
        "\t-d\tForking into background after initialization.\n"
        "\t-p\tWrite the daemon PID to the given file path.\n"
        "\t-s\tDestination where nDPIsrvd is listening on.\n"
        "\t  \tCan be either a path to UNIX socket or an IPv4/TCP-Port IPv6/TCP-Port tuple.\n"
        "\t-u\tChange user.\n"
        "\t-g\tChange group.\n"
        "\t-o\tSpecify the CSV output file for analysis results.\n"
        "\t-O\tWrite some global statistics to a CSV every `-t' seconds.\n"
        "\t-t\tTime interval for `-O'.\n\n";

    fprintf(stderr, usage, arg0);
}

static int parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "hldp:s:u:g:o:O:t:")) != -1)
    {
        switch (opt)
        {
            case 'l':
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
            case 'o':
                free(csv_outfile);
                csv_outfile = strdup(optarg);
                break;
            case 'O':
                free(stats_csv_outfile);
                stats_csv_outfile = strdup(optarg);
                break;
            case 't':
                free(analysed_interval);
                analysed_interval = strdup(optarg);
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (csv_outfile == NULL && stats_csv_outfile == NULL)
    {
        logger_early(1,
                     "%s: Missing either analyse CSV output file (`-o') or global stats CSV output file (`-O')",
                     argv[0]);
        return 1;
    }

    if (csv_outfile != NULL)
    {
        opt = 0;
        if (access(csv_outfile, F_OK) != 0 && errno == ENOENT)
        {
            opt = 1;
        }
        else
        {
            if (chmod_chown(csv_outfile, S_IRUSR | S_IWUSR, "root", "root") != 0)
            {
                // skip "unused result" warning
            }
        }

        csv_fp = fopen(csv_outfile, "a+");
        if (csv_fp == NULL)
        {
            logger_early(1, "%s: Could not open file `%s' for appending: %s", argv[0], csv_outfile, strerror(errno));
            return 1;
        }

        if (opt != 0)
        {
            fprintf(csv_fp,
                    "flow_datalink,l3_proto,src_ip,dst_ip,l4_proto,src_port,dst_port,flow_state,flow_src_packets_"
                    "processed,"
                    "flow_dst_packets_processed,flow_first_seen,flow_src_last_pkt_time,flow_dst_last_pkt_time,flow_src_"
                    "min_"
                    "l4_payload_len,flow_dst_min_l4_payload_len,flow_src_max_l4_payload_len,flow_dst_max_l4_payload_"
                    "len,"
                    "flow_src_tot_l4_payload_len,flow_dst_tot_l4_payload_len,midstream,iat_min,iat_avg,iat_max,iat_"
                    "stddev,"
                    "iat_var,iat_ent,iat_data,pktlen_min,pktlen_avg,pktlen_max,pktlen_stddev,pktlen_var,pktlen_ent,"
                    "pktlen_"
                    "data,bins_c_to_s,bins_s_to_c,directions,entropies,proto,proto_id,encrypted,breed,category,"
                    "confidence_id,confidence,risks\n");
        }
    }

    if (serv_optarg == NULL)
    {
        serv_optarg = strdup(DISTRIBUTOR_UNIX_SOCKET);
    }

    if (stats_csv_outfile != NULL)
    {
        opt = 0;
        if (access(stats_csv_outfile, F_OK) != 0 && errno == ENOENT)
        {
            opt = 1;
        }
        else
        {
            if (chmod_chown(stats_csv_outfile, S_IRUSR | S_IWUSR, "root", "root") != 0)
            {
                // skip "unused result" warning
            }
        }

        stats_csv_fp = fopen(stats_csv_outfile, "a+");
        if (stats_csv_fp == NULL)
        {
            logger_early(
                1, "%s: Could not open file `%s' for appending: %s", argv[0], stats_csv_outfile, strerror(errno));
            return 1;
        }

        if (opt != 0)
        {
            fprintf(stats_csv_fp,
                    "%s",
                    "timestamp,"
                    "json_lines,json_bytes,flow_src_total_bytes,flow_dst_total_bytes,"
                    "flow_new_count,flow_end_count,flow_idle_count,flow_update_count,flow_analyse_count,flow_guessed_"
                    "count,flow_detected_count,flow_detection_update_count,flow_not_detected_count,flow_risky_count,"
                    "packet_count,packet_flow_count,init_count,reconnect_count,shutdown_count,status_count,error_"
                    "unknown_datalink,error_unknown_l3_protocol,error_unsupported_datalink,error_packet_too_short,"
                    "error_packet_type_unknown,error_packet_header_invalid,error_ip4_packet_too_short,error_ip4_size_"
                    "smaller_than_header,error_ip4_l4_payload_detection,error_ip6_packet_too_short,error_ip6_size_"
                    "smaller_than_header,error_ip6_l4_payload_detection,error_tcp_packet_too_short,error_udp_packet_"
                    "too_short,error_capture_size_smaller_than_packet,error_max_flows_to_track,error_flow_memory_"
                    "alloc,"
                    "flow_state_info,flow_state_finished,"
                    "flow_breed_safe_count,flow_breed_acceptable_count,flow_breed_fun_count,flow_breed_unsafe_count,"
                    "flow_breed_potentially_dangerous_count,flow_breed_tracker_ads_count,flow_breed_dangerous_count,"
                    "flow_breed_unrated_count,flow_breed_unknown_count,"
                    "flow_category_unspecified_count,flow_category_media_count,flow_category_vpn_count,flow_category_"
                    "email_count,flow_category_data_transfer_count,flow_category_web_count,flow_category_social_"
                    "network_count,flow_category_download_count,flow_category_game_count,flow_category_chat_count,flow_"
                    "category_voip_count,flow_category_database_count,flow_category_remote_access_count,flow_category_"
                    "cloud_count,flow_category_network_count,flow_category_collaborative_count,flow_category_rpc_count,"
                    "flow_category_streaming_count,flow_category_system_count,flow_category_software_update_count,flow_"
                    "category_music_count,flow_category_video_count,flow_category_shopping_count,flow_category_"
                    "productivity_count,flow_category_file_sharing_count,flow_category_conn_check_count,flow_category_"
                    "iot_scada_count,flow_category_virt_assistant_count,flow_category_cybersecurity_count,flow_"
                    "category_adult_content_count,flow_category_mining_count,flow_category_malware_count,flow_category_"
                    "advertisment_count,flow_category_banned_site_count,flow_category_site_unavail_count,flow_category_"
                    "allowed_site_count,flow_category_antimalware_count,flow_category_crypto_currency_count,flow_"
                    "category_gambling_count,flow_category_unknown_count,"
                    "flow_confidence_by_port,flow_confidence_dpi_partial,flow_confidence_dpi_partial_cache,flow_"
                    "confidence_dpi_cache,flow_confidence_dpi,flow_confidence_nbpf,flow_confidence_by_ip,flow_"
                    "confidence_dpi_aggressive,flow_confidence_custom_rule,flow_confidence_unknown,"
                    "flow_severity_low,flow_severity_medium,flow_severity_high,flow_severity_severe,flow_severity_"
                    "critical,flow_severity_emergency,flow_severity_unknown,"
                    "flow_l3_ip4_count,flow_l3_ip6_count,flow_l3_other_count,"
                    "flow_l4_tcp_count,flow_l4_udp_count,flow_l4_icmp_count,flow_l4_other_count,"
                    "flow_active_count,flow_detected_count,flow_guessed_count,flow_not_detected_count,");
            for (size_t i = 0; i < NDPI_MAX_RISK - 1 /* NDPI_NO_RISK */; ++i)
            {
                fprintf(stats_csv_fp, "flow_risk_%zu_count,", i + 1);
            }
            fprintf(stats_csv_fp, "%s\n", "flow_risk_unknown_count");
        }

        if (analysed_interval == NULL)
        {
            analysed_interval = strdup("30");
        }

        if (str_value_to_ull(analysed_interval, &analysed_interval_ull) != CONVERSION_OK)
        {
            logger_early(1, "Global Stats CSV write interval `%s' is not a valid number", analysed_interval);
            return 1;
        }
        if (analysed_interval_ull == 0)
        {
            logger_early(0, "%s", "Global Stats CSV write interval is zero, summarizing stats during termination");
        }
    }

    if (optind < argc)
    {
        logger_early(1, "%s", "Unexpected argument after options");
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}

static int set_analysed_timer(void)
{
    if (analysed_interval_ull == 0)
    {
        return 0;
    }

    const time_t interval = analysed_interval_ull * 1000;
    struct itimerspec its;
    its.it_value.tv_sec = interval / 1000;
    its.it_value.tv_nsec = (interval % 1000) * 1000000;
    its.it_interval.tv_nsec = 0;
    its.it_interval.tv_sec = 0;

    errno = 0;
    return timerfd_settime(analysed_timerfd, 0, &its, NULL);
}

static int create_analysed_timer(void)
{
    analysed_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (analysed_timerfd < 0)
    {
        return 1;
    }

    return set_analysed_timer();
}

#define ANALYSEDB_FORMAT() "%llu,"
#define ANALYSEDB_VALUE_COUNTER(value) (unsigned long long int)analysed_statistics.counters.value
#define ANALYSEDB_VALUE_GAUGE(value) (unsigned long long int)analysed_statistics.gauges[0].value
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
static int write_global_flow_stats(void)
{
    int rc = 1;
    char output_buffer[BUFSIZ];
    char * buf = &output_buffer[0];
    size_t siz = sizeof(output_buffer);
    int bytes;

    bytes = snprintf(buf,
                     siz,
                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT(),
                     ANALYSEDB_VALUE_COUNTER(json_lines),
                     ANALYSEDB_VALUE_COUNTER(json_bytes),
                     ANALYSEDB_VALUE_COUNTER(flow_src_total_bytes),
                     ANALYSEDB_VALUE_COUNTER(flow_dst_total_bytes));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                         ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                             ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                 ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                         ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                             ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                 ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT(),
                     ANALYSEDB_VALUE_COUNTER(flow_new_count),
                     ANALYSEDB_VALUE_COUNTER(flow_end_count),
                     ANALYSEDB_VALUE_COUNTER(flow_idle_count),
                     ANALYSEDB_VALUE_COUNTER(flow_update_count),
                     ANALYSEDB_VALUE_COUNTER(flow_analyse_count),
                     ANALYSEDB_VALUE_COUNTER(flow_guessed_count),
                     ANALYSEDB_VALUE_COUNTER(flow_detected_count),
                     ANALYSEDB_VALUE_COUNTER(flow_detection_update_count),
                     ANALYSEDB_VALUE_COUNTER(flow_not_detected_count),
                     ANALYSEDB_VALUE_COUNTER(flow_risky_count),
                     ANALYSEDB_VALUE_COUNTER(packet_count),
                     ANALYSEDB_VALUE_COUNTER(packet_flow_count),
                     ANALYSEDB_VALUE_COUNTER(init_count),
                     ANALYSEDB_VALUE_COUNTER(reconnect_count),
                     ANALYSEDB_VALUE_COUNTER(shutdown_count),
                     ANALYSEDB_VALUE_COUNTER(status_count),
                     ANALYSEDB_VALUE_COUNTER(error_unknown_datalink),
                     ANALYSEDB_VALUE_COUNTER(error_unknown_l3_protocol),
                     ANALYSEDB_VALUE_COUNTER(error_unsupported_datalink),
                     ANALYSEDB_VALUE_COUNTER(error_packet_too_short),
                     ANALYSEDB_VALUE_COUNTER(error_packet_type_unknown),
                     ANALYSEDB_VALUE_COUNTER(error_packet_header_invalid),
                     ANALYSEDB_VALUE_COUNTER(error_ip4_packet_too_short),
                     ANALYSEDB_VALUE_COUNTER(error_ip4_size_smaller_than_header),
                     ANALYSEDB_VALUE_COUNTER(error_ip4_l4_payload_detection),
                     ANALYSEDB_VALUE_COUNTER(error_ip6_packet_too_short),
                     ANALYSEDB_VALUE_COUNTER(error_ip6_size_smaller_than_header),
                     ANALYSEDB_VALUE_COUNTER(error_ip6_l4_payload_detection),
                     ANALYSEDB_VALUE_COUNTER(error_tcp_packet_too_short),
                     ANALYSEDB_VALUE_COUNTER(error_udp_packet_too_short),
                     ANALYSEDB_VALUE_COUNTER(error_capture_size_smaller_than_packet),
                     ANALYSEDB_VALUE_COUNTER(error_max_flows_to_track),
                     ANALYSEDB_VALUE_COUNTER(error_flow_memory_alloc));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT(),
                     ANALYSEDB_VALUE_GAUGE(flow_state_info),
                     ANALYSEDB_VALUE_GAUGE(flow_state_finished));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                         ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT(),
                     ANALYSEDB_VALUE_GAUGE(flow_breed_safe_count),
                     ANALYSEDB_VALUE_GAUGE(flow_breed_acceptable_count),
                     ANALYSEDB_VALUE_GAUGE(flow_breed_fun_count),
                     ANALYSEDB_VALUE_GAUGE(flow_breed_unsafe_count),
                     ANALYSEDB_VALUE_GAUGE(flow_breed_potentially_dangerous_count),
                     ANALYSEDB_VALUE_GAUGE(flow_breed_tracker_ads_count),
                     ANALYSEDB_VALUE_GAUGE(flow_breed_dangerous_count),
                     ANALYSEDB_VALUE_GAUGE(flow_breed_unrated_count),
                     ANALYSEDB_VALUE_GAUGE(flow_breed_unknown_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(
        buf,
        siz,
        ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
            ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                    ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                        ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                            ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                    ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                        ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                            ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                    ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                        ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                            ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                    ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                        ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                            ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                                ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                                    ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                                        ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                                            ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                                                ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                                                                                                    ANALYSEDB_FORMAT()
                                                                                                        ANALYSEDB_FORMAT()
                                                                                                            ANALYSEDB_FORMAT()
                                                                                                                ANALYSEDB_FORMAT()
                                                                                                                    ANALYSEDB_FORMAT(),

        ANALYSEDB_VALUE_GAUGE(flow_category_unspecified_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_media_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_vpn_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_email_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_data_transfer_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_web_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_social_network_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_download_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_game_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_chat_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_voip_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_database_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_remote_access_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_cloud_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_network_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_collaborative_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_rpc_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_streaming_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_system_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_software_update_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_music_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_video_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_shopping_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_productivity_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_file_sharing_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_conn_check_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_iot_scada_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_virt_assistant_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_cybersecurity_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_adult_content_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_mining_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_malware_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_advertisment_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_banned_site_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_site_unavail_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_allowed_site_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_antimalware_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_crypto_currency_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_gambling_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_health_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_ai_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_finance_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_news_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_sport_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_business_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_internet_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_blockchain_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_blog_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_gov_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_edu_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_cdn_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_hwsw_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_dating_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_travel_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_food_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_bots_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_scanners_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_hosting_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_art_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_fashion_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_books_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_science_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_maps_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_login_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_legal_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_envsrv_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_culture_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_housing_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_telecom_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_transport_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_design_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_employ_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_events_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_weather_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_lifestyle_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_real_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_security_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_env_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_hobby_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_comp_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_const_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_eng_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_reli_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_enter_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_agri_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_tech_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_beauty_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_history_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_polit_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_vehi_count),
        ANALYSEDB_VALUE_GAUGE(flow_category_unknown_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                         ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT(),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_by_port),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_dpi_partial),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_dpi_partial_cache),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_dpi_cache),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_dpi),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_nbpf),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_by_ip),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_dpi_aggressive),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_custom_rule),
                     ANALYSEDB_VALUE_GAUGE(flow_confidence_unknown));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT()
                         ANALYSEDB_FORMAT() ANALYSEDB_FORMAT(),
                     ANALYSEDB_VALUE_GAUGE(flow_severity_low),
                     ANALYSEDB_VALUE_GAUGE(flow_severity_medium),
                     ANALYSEDB_VALUE_GAUGE(flow_severity_high),
                     ANALYSEDB_VALUE_GAUGE(flow_severity_severe),
                     ANALYSEDB_VALUE_GAUGE(flow_severity_critical),
                     ANALYSEDB_VALUE_GAUGE(flow_severity_emergency),
                     ANALYSEDB_VALUE_GAUGE(flow_severity_unknown));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT(),
                     ANALYSEDB_VALUE_GAUGE(flow_l3_ip4_count),
                     ANALYSEDB_VALUE_GAUGE(flow_l3_ip6_count),
                     ANALYSEDB_VALUE_GAUGE(flow_l3_other_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT(),
                     ANALYSEDB_VALUE_GAUGE(flow_l4_tcp_count),
                     ANALYSEDB_VALUE_GAUGE(flow_l4_udp_count),
                     ANALYSEDB_VALUE_GAUGE(flow_l4_icmp_count),
                     ANALYSEDB_VALUE_GAUGE(flow_l4_other_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf,
                     siz,
                     ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT() ANALYSEDB_FORMAT(),
                     ANALYSEDB_VALUE_GAUGE(flow_active_count),
                     ANALYSEDB_VALUE_GAUGE(flow_detected_count),
                     ANALYSEDB_VALUE_GAUGE(flow_guessed_count),
                     ANALYSEDB_VALUE_GAUGE(flow_not_detected_count));
    CHECK_SNPRINTF_RET(bytes);

    bytes = snprintf(buf, siz, ANALYSEDB_FORMAT(), ANALYSEDB_VALUE_GAUGE(flow_risk_unknown_count));
    CHECK_SNPRINTF_RET(bytes);

    for (size_t i = 0; i < NDPI_MAX_RISK - 1 /* NDPI_NO_RISK */; ++i)
    {
        bytes = snprintf(buf, siz, "%llu,", (unsigned long long int)analysed_statistics.gauges[0].flow_risk_count[i]);
        CHECK_SNPRINTF_RET(bytes);
    }
    buf[-1] = '\n';

    struct timeval tval;
    if (analysed_interval_ull != 0 && gettimeofday(&tval, NULL) == 0)
    {
        unsigned long long int sec = tval.tv_sec;
        unsigned long long int usec = tval.tv_usec;
        unsigned long long int timestamp = usec + sec * 1000 * 1000;
        fprintf(stats_csv_fp, "%llu,%s", timestamp, output_buffer);
        rc = 0;
    }
    else
    {
        fprintf(stats_csv_fp, "0,%s", output_buffer);
    }
failure:
    // reset all counters until the analysed timer is ready again
    memset(&analysed_statistics.counters, 0, sizeof(analysed_statistics.counters));

    ANALYSED_STATS_GAUGE_SUB(flow_state_info);
    ANALYSED_STATS_GAUGE_SUB(flow_state_finished);

    ANALYSED_STATS_GAUGE_SUB(flow_breed_safe_count);
    ANALYSED_STATS_GAUGE_SUB(flow_breed_acceptable_count);
    ANALYSED_STATS_GAUGE_SUB(flow_breed_fun_count);
    ANALYSED_STATS_GAUGE_SUB(flow_breed_unsafe_count);
    ANALYSED_STATS_GAUGE_SUB(flow_breed_potentially_dangerous_count);
    ANALYSED_STATS_GAUGE_SUB(flow_breed_tracker_ads_count);
    ANALYSED_STATS_GAUGE_SUB(flow_breed_dangerous_count);
    ANALYSED_STATS_GAUGE_SUB(flow_breed_unrated_count);
    ANALYSED_STATS_GAUGE_SUB(flow_breed_unknown_count);

    ANALYSED_STATS_GAUGE_SUB(flow_category_unspecified_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_media_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_vpn_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_email_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_data_transfer_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_web_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_social_network_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_download_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_game_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_chat_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_voip_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_database_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_remote_access_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_cloud_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_network_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_collaborative_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_rpc_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_streaming_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_system_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_software_update_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_music_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_video_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_shopping_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_productivity_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_file_sharing_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_conn_check_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_iot_scada_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_virt_assistant_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_cybersecurity_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_adult_content_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_mining_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_malware_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_advertisment_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_banned_site_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_site_unavail_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_allowed_site_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_antimalware_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_crypto_currency_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_gambling_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_health_count);
    ANALYSED_STATS_GAUGE_SUB(flow_category_unknown_count);

    ANALYSED_STATS_GAUGE_SUB(flow_confidence_by_port);
    ANALYSED_STATS_GAUGE_SUB(flow_confidence_dpi_partial);
    ANALYSED_STATS_GAUGE_SUB(flow_confidence_dpi_partial_cache);
    ANALYSED_STATS_GAUGE_SUB(flow_confidence_dpi_cache);
    ANALYSED_STATS_GAUGE_SUB(flow_confidence_dpi);
    ANALYSED_STATS_GAUGE_SUB(flow_confidence_nbpf);
    ANALYSED_STATS_GAUGE_SUB(flow_confidence_by_ip);
    ANALYSED_STATS_GAUGE_SUB(flow_confidence_dpi_aggressive);
    ANALYSED_STATS_GAUGE_SUB(flow_confidence_custom_rule);
    ANALYSED_STATS_GAUGE_SUB(flow_confidence_unknown);

    ANALYSED_STATS_GAUGE_SUB(flow_severity_low);
    ANALYSED_STATS_GAUGE_SUB(flow_severity_medium);
    ANALYSED_STATS_GAUGE_SUB(flow_severity_high);
    ANALYSED_STATS_GAUGE_SUB(flow_severity_severe);
    ANALYSED_STATS_GAUGE_SUB(flow_severity_critical);
    ANALYSED_STATS_GAUGE_SUB(flow_severity_emergency);
    ANALYSED_STATS_GAUGE_SUB(flow_severity_unknown);

    ANALYSED_STATS_GAUGE_SUB(flow_l3_ip4_count);
    ANALYSED_STATS_GAUGE_SUB(flow_l3_ip6_count);
    ANALYSED_STATS_GAUGE_SUB(flow_l3_other_count);

    ANALYSED_STATS_GAUGE_SUB(flow_l4_tcp_count);
    ANALYSED_STATS_GAUGE_SUB(flow_l4_udp_count);
    ANALYSED_STATS_GAUGE_SUB(flow_l4_icmp_count);
    ANALYSED_STATS_GAUGE_SUB(flow_l4_other_count);

    ANALYSED_STATS_GAUGE_SUB(flow_active_count);
    ANALYSED_STATS_GAUGE_SUB(flow_detected_count);
    ANALYSED_STATS_GAUGE_SUB(flow_guessed_count);
    ANALYSED_STATS_GAUGE_SUB(flow_not_detected_count);

    for (size_t i = 0; i < NDPI_MAX_RISK - 1 /* NDPI_NO_RISK */; ++i)
    {
        ANALYSED_STATS_GAUGE_SUB(flow_risk_count[i]);
    }
    ANALYSED_STATS_GAUGE_SUB(flow_risk_unknown_count);

    memset(&analysed_statistics.gauges[1], 0, sizeof(analysed_statistics.gauges[1]));

    return rc;
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

            if (events[i].data.fd == analysed_timerfd)
            {
                uint64_t expirations;

                errno = 0;
                if (read(analysed_timerfd, &expirations, sizeof(expirations)) != sizeof(expirations))
                {
                    logger(1, "Could not read timer expirations: %s", strerror(errno));
                    return 1;
                }
                if (set_analysed_timer() != 0)
                {
                    logger(1, "Could not set timer: %s", strerror(errno));
                    return 1;
                }

                if (write_global_flow_stats() != 0)
                {
                    logger(1, "%s", "Could not write global/flow stats.");
                    return 1;
                }
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

int main(int argc, char ** argv)
{
    int retval = 1;
    int epollfd = -1;

    init_logging("nDPIsrvd-analysed");

    if (parse_options(argc, argv) != 0)
    {
        goto failure;
    }

    distributor = nDPIsrvd_socket_init(
        0, 0, 0, (stats_csv_outfile != NULL ? sizeof(struct flow_user_data) : 0), analysed_json_callback, NULL, NULL);
    if (distributor == NULL)
    {
        logger_early(1, "%s", "nDPIsrvd socket memory allocation failed!");
        goto failure;
    }

    if (nDPIsrvd_setup_address(&distributor->address, serv_optarg) != 0)
    {
        logger_early(1, "%s: Could not parse address `%s'\n", argv[0], serv_optarg);
        goto failure;
    }

    logger(0, "Recv buffer size: %u", NETWORK_BUFFER_MAX_SIZE);
    logger(0, "Connecting to `%s'..", serv_optarg);

    if (nDPIsrvd_connect(distributor) != CONNECT_OK)
    {
        logger_early(1, "nDPIsrvd socket connect to %s failed!", serv_optarg);
        goto failure;
    }

    if (nDPIsrvd_set_nonblock(distributor) != 0)
    {
        logger_early(1, "nDPIsrvd set nonblock failed: %s", strerror(errno));
        goto failure;
    }

    signal(SIGUSR1, sighandler);
    signal(SIGUSR2, sighandler);
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, sighandler);

    if (daemonize_with_pidfile(pidfile) != 0)
    {
        goto failure;
    }

    if (csv_outfile != NULL)
    {
        int ret = chmod_chown(csv_outfile, S_IRUSR | S_IWUSR | S_IRGRP, user, group);
        if (ret != 0)
        {
            logger_early(1, "Could not chmod/chown `%s': %s", csv_outfile, strerror(ret));
            return 1;
        }
    }
    if (stats_csv_outfile != NULL)
    {
        int ret = chmod_chown(stats_csv_outfile, S_IRUSR | S_IWUSR | S_IRGRP, user, group);
        if (ret != 0)
        {
            logger_early(1, "Could not chmod/chown `%s': %s", stats_csv_outfile, strerror(ret));
            return 1;
        }
    }

    errno = 0;
    if (user != NULL && change_user_group(user, group, pidfile) != 0)
    {
        if (errno != 0)
        {
            logger_early(1, "Change user/group failed: %s", strerror(errno));
        }
        else
        {
            logger_early(1, "Change user/group failed.");
        }

        goto failure;
    }

    epollfd = epoll_create1(0);
    if (epollfd < 0)
    {
        logger_early(1, "Error creating epoll: %s", strerror(errno));
        goto failure;
    }

    if (stats_csv_fp != NULL)
    {
        if (create_analysed_timer() != 0)
        {
            logger_early(1, "Error creating timer: %s", strerror(errno));
            goto failure;
        }

        {
            struct epoll_event timer_event = {.data.fd = analysed_timerfd, .events = EPOLLIN};
            if (epoll_ctl(epollfd, EPOLL_CTL_ADD, analysed_timerfd, &timer_event) < 0)
            {
                logger_early(1, "Error adding JSON fd to epoll: %s", strerror(errno));
                goto failure;
            }
        }
    }

    {
        struct epoll_event socket_event = {.data.fd = distributor->fd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, distributor->fd, &socket_event) < 0)
        {
            logger_early(1, "Error adding nDPIsrvd socket fd to epoll: %s", strerror(errno));
            goto failure;
        }
    }

    logger(0, "%s", "Initialization succeeded.");
    retval = mainloop(epollfd, distributor);
    if (analysed_interval_ull == 0)
    {
        if (write_global_flow_stats() != 0)
        {
            logger(1, "%s", "Could not write global/flow stats on termination.");
        }
    }
failure:
    nDPIsrvd_socket_free(&distributor);
    daemonize_shutdown(pidfile);
    shutdown_logging();

    if (csv_fp != NULL)
    {
        fflush(csv_fp);
        fclose(csv_fp);
    }

    if (stats_csv_fp != NULL)
    {
        fflush(stats_csv_fp);
        fclose(stats_csv_fp);
    }

    return retval;
}
