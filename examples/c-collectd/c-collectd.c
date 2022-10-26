#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <ndpi_typedefs.h>

#include "nDPIsrvd.h"

#define DEFAULT_COLLECTD_EXEC_INST "nDPIsrvd"
#define ERROR_EVENT_ID_MAX 17
//#define GENERATE_TIMESTAMP 1

#define LOG(flags, format, ...)                                                                                        \
    if (quiet == 0)                                                                                                    \
    {                                                                                                                  \
        fprintf(stderr, format, __VA_ARGS__);                                                                          \
        fprintf(stderr, "%s", "\n");                                                                                   \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        syslog(flags, format, __VA_ARGS__);                                                                            \
    }

struct flow_user_data
{
    nDPIsrvd_ull last_flow_src_l4_payload_len;
    nDPIsrvd_ull last_flow_dst_l4_payload_len;
    nDPIsrvd_ull detected_risks;
};

static int main_thread_shutdown = 0;
static int collectd_timerfd = -1;
static pid_t collectd_pid;

static char * serv_optarg = NULL;
static char * collectd_hostname = NULL;
static char * collectd_interval = NULL;
static char * instance_name = NULL;
static nDPIsrvd_ull collectd_interval_ull = 0uL;
static int quiet = 0;

static struct
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

    uint64_t error_count_sum;
    uint64_t error_count[ERROR_EVENT_ID_MAX];
    uint64_t error_unknown_count;

    uint64_t flow_src_total_bytes;
    uint64_t flow_dst_total_bytes;
    uint64_t flow_risky_count;

    uint64_t flow_breed_safe_count;
    uint64_t flow_breed_acceptable_count;
    uint64_t flow_breed_fun_count;
    uint64_t flow_breed_unsafe_count;
    uint64_t flow_breed_potentially_dangerous_count;
    uint64_t flow_breed_tracker_ads_count;
    uint64_t flow_breed_dangerous_count;
    uint64_t flow_breed_unrated_count;
    uint64_t flow_breed_unknown_count;

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
    uint64_t flow_category_mining_count;
    uint64_t flow_category_malware_count;
    uint64_t flow_category_advertisment_count;
    uint64_t flow_category_unknown_count;

    uint64_t flow_l3_ip4_count;
    uint64_t flow_l3_ip6_count;
    uint64_t flow_l3_other_count;

    uint64_t flow_l4_tcp_count;
    uint64_t flow_l4_udp_count;
    uint64_t flow_l4_icmp_count;
    uint64_t flow_l4_other_count;

    nDPIsrvd_ull flow_risk_count[NDPI_MAX_RISK];
    nDPIsrvd_ull flow_risk_unknown_count;
} collectd_statistics = {};

struct json_stat_map
{
    char const * const json_key;
    uint64_t * const collectd_stat;
};

static struct json_stat_map const flow_event_map[] = {{"new", &collectd_statistics.flow_new_count},
                                                      {"end", &collectd_statistics.flow_end_count},
                                                      {"idle", &collectd_statistics.flow_idle_count},
                                                      {"update", &collectd_statistics.flow_update_count},
                                                      {"analyse", &collectd_statistics.flow_analyse_count},
                                                      {"guessed", &collectd_statistics.flow_guessed_count},
                                                      {"detected", &collectd_statistics.flow_detected_count},
                                                      {"detection-update",
                                                       &collectd_statistics.flow_detection_update_count},
                                                      {"not-detected", &collectd_statistics.flow_not_detected_count}};

static struct json_stat_map const packet_event_map[] = {{"packet", &collectd_statistics.packet_count},
                                                        {"packet-flow", &collectd_statistics.packet_flow_count}};

static struct json_stat_map const daemon_event_map[] = {{"init", &collectd_statistics.init_count},
                                                        {"reconnect", &collectd_statistics.reconnect_count},
                                                        {"shutdown", &collectd_statistics.shutdown_count},
                                                        {"status", &collectd_statistics.status_count}};

static struct json_stat_map const breeds_map[] = {{"Safe", &collectd_statistics.flow_breed_safe_count},
                                                  {"Acceptable", &collectd_statistics.flow_breed_acceptable_count},
                                                  {"Fun", &collectd_statistics.flow_breed_fun_count},
                                                  {"Unsafe", &collectd_statistics.flow_breed_unsafe_count},
                                                  {"Potentially Dangerous",
                                                   &collectd_statistics.flow_breed_potentially_dangerous_count},
                                                  {"Tracker/Ads", &collectd_statistics.flow_breed_tracker_ads_count},
                                                  {"Dangerous", &collectd_statistics.flow_breed_dangerous_count},
                                                  {"Unrated", &collectd_statistics.flow_breed_unrated_count},
                                                  {NULL, &collectd_statistics.flow_breed_unknown_count}};

static struct json_stat_map const categories_map[] = {
    {"Media", &collectd_statistics.flow_category_media_count},
    {"VPN", &collectd_statistics.flow_category_vpn_count},
    {"Email", &collectd_statistics.flow_category_email_count},
    {"DataTransfer", &collectd_statistics.flow_category_data_transfer_count},
    {"Web", &collectd_statistics.flow_category_web_count},
    {"SocialNetwork", &collectd_statistics.flow_category_social_network_count},
    {"Download-FileTransfer-FileSharing", &collectd_statistics.flow_category_download_count},
    {"Game", &collectd_statistics.flow_category_game_count},
    {"Chat", &collectd_statistics.flow_category_chat_count},
    {"VoIP", &collectd_statistics.flow_category_voip_count},
    {"Database", &collectd_statistics.flow_category_database_count},
    {"RemoteAccess", &collectd_statistics.flow_category_remote_access_count},
    {"Cloud", &collectd_statistics.flow_category_cloud_count},
    {"Network", &collectd_statistics.flow_category_network_count},
    {"Collaborative", &collectd_statistics.flow_category_collaborative_count},
    {"RPC", &collectd_statistics.flow_category_rpc_count},
    {"Streaming", &collectd_statistics.flow_category_streaming_count},
    {"System", &collectd_statistics.flow_category_system_count},
    {"SoftwareUpdate", &collectd_statistics.flow_category_software_update_count},
    {"Music", &collectd_statistics.flow_category_music_count},
    {"Video", &collectd_statistics.flow_category_video_count},
    {"Shopping", &collectd_statistics.flow_category_shopping_count},
    {"Productivity", &collectd_statistics.flow_category_productivity_count},
    {"FileSharing", &collectd_statistics.flow_category_file_sharing_count},
    {"Mining", &collectd_statistics.flow_category_mining_count},
    {"Malware", &collectd_statistics.flow_category_malware_count},
    {"Advertisement", &collectd_statistics.flow_category_advertisment_count},
    {NULL, &collectd_statistics.flow_category_unknown_count}};

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
    LOG(LOG_DAEMON | LOG_NOTICE, "Received SIGNAL %d", signum);

    if (main_thread_shutdown == 0)
    {
        LOG(LOG_DAEMON | LOG_NOTICE, "%s", "Shutting down ..");
        main_thread_shutdown = 1;
    }
}

static int parse_options(int argc, char ** argv, struct nDPIsrvd_socket * const sock)
{
    int opt;

    static char const usage[] =
        "Usage: %s "
        "[-s host] [-c hostname] [-n collectd-instance-name] [-i interval] [-q]\n\n"
        "\t-s\tDestination where nDPIsrvd is listening on.\n"
        "\t-c\tCollectd hostname.\n"
        "\t  \tThis value defaults to the environment variable COLLECTD_HOSTNAME.\n"
        "\t-n\tName of the collectd(-exec) instance.\n"
        "\t  \tDefaults to: " DEFAULT_COLLECTD_EXEC_INST
        "\n"
        "\t-i\tInterval between print statistics to stdout.\n"
        "\t  \tThis value defaults to the environment variable COLLECTD_INTERVAL.\n"
        "\t-q\tDo not print anything except collectd statistics.\n"
        "\t  \tAutomatically enabled if environment variables mentioned above are set.\n";

    while ((opt = getopt(argc, argv, "hs:c:n:i:q")) != -1)
    {
        switch (opt)
        {
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
            case 'q':
                quiet = 1;
                break;
            default:
                LOG(LOG_DAEMON | LOG_ERR, usage, argv[0]);
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
    }

    if (str_value_to_ull(collectd_interval, &collectd_interval_ull) != CONVERSION_OK)
    {
        LOG(LOG_DAEMON | LOG_ERR, "Collectd interval `%s' is not a valid number", collectd_interval);
        return 1;
    }

    if (nDPIsrvd_setup_address(&sock->address, serv_optarg) != 0)
    {
        LOG(LOG_DAEMON | LOG_ERR, "Could not parse address `%s'", serv_optarg);
        return 1;
    }

    if (optind < argc)
    {
        LOG(LOG_DAEMON | LOG_ERR, "%s", "Unexpected argument after options");
        if (quiet == 0)
        {
            LOG(0, "%s", "");
            LOG(0, usage, argv[0]);
        }
        return 1;
    }

    return 0;
}

#ifdef GENERATE_TIMESTAMP
#define COLLECTD_PUTVAL_PREFIX "PUTVAL \"%s/exec-%s/gauge-"
#define COLLECTD_PUTVAL_SUFFIX "\" interval=%llu %llu:%llu\n"
#define COLLECTD_PUTVAL_N(value)                                                                                       \
    collectd_hostname, instance_name, #value, collectd_interval_ull, (unsigned long long int)now,                      \
        (unsigned long long int)collectd_statistics.value
#define COLLECTD_PUTVAL_N2(name, value)                                                                                \
    collectd_hostname, instance_name, name, collectd_interval_ull, (unsigned long long int)now,                        \
        (unsigned long long int)collectd_statistics.value
#else
#define COLLECTD_PUTVAL_PREFIX "PUTVAL \"%s/exec-%s/gauge-"
#define COLLECTD_PUTVAL_SUFFIX "\" interval=%llu N:%llu\n"
#define COLLECTD_PUTVAL_N(value)                                                                                       \
    collectd_hostname, instance_name, #value, collectd_interval_ull, (unsigned long long int)collectd_statistics.value
#define COLLECTD_PUTVAL_N2(name, value)                                                                                \
    collectd_hostname, instance_name, name, collectd_interval_ull, (unsigned long long int)collectd_statistics.value
#endif
#define COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_PREFIX "%s" COLLECTD_PUTVAL_SUFFIX
static void print_collectd_exec_output(void)
{
    size_t i;
#ifdef GENERATE_TIMESTAMP
    time_t now = time(NULL);
#endif

    printf(COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
               COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                   COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                       COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                           COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                               COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                                   COLLECTD_PUTVAL_N_FORMAT(),

           COLLECTD_PUTVAL_N(json_lines),
           COLLECTD_PUTVAL_N(json_bytes),
           COLLECTD_PUTVAL_N(flow_new_count),
           COLLECTD_PUTVAL_N(flow_end_count),
           COLLECTD_PUTVAL_N(flow_idle_count),
           COLLECTD_PUTVAL_N(flow_update_count),
           COLLECTD_PUTVAL_N(flow_analyse_count),
           COLLECTD_PUTVAL_N(flow_guessed_count),
           COLLECTD_PUTVAL_N(flow_detected_count),
           COLLECTD_PUTVAL_N(flow_detection_update_count),
           COLLECTD_PUTVAL_N(flow_not_detected_count),
           COLLECTD_PUTVAL_N(flow_src_total_bytes),
           COLLECTD_PUTVAL_N(flow_dst_total_bytes),
           COLLECTD_PUTVAL_N(flow_risky_count),
           COLLECTD_PUTVAL_N(packet_count),
           COLLECTD_PUTVAL_N(packet_flow_count),
           COLLECTD_PUTVAL_N(init_count),
           COLLECTD_PUTVAL_N(reconnect_count),
           COLLECTD_PUTVAL_N(shutdown_count),
           COLLECTD_PUTVAL_N(status_count));

    printf(COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
               COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                   COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT(),

           COLLECTD_PUTVAL_N(flow_breed_safe_count),
           COLLECTD_PUTVAL_N(flow_breed_acceptable_count),
           COLLECTD_PUTVAL_N(flow_breed_fun_count),
           COLLECTD_PUTVAL_N(flow_breed_unsafe_count),
           COLLECTD_PUTVAL_N(flow_breed_potentially_dangerous_count),
           COLLECTD_PUTVAL_N(flow_breed_tracker_ads_count),
           COLLECTD_PUTVAL_N(flow_breed_dangerous_count),
           COLLECTD_PUTVAL_N(flow_breed_unrated_count),
           COLLECTD_PUTVAL_N(flow_breed_unknown_count));

    printf(COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
               COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                   COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                       COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                           COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                               COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                                   COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                                       COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                                           COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                                               COLLECTD_PUTVAL_N_FORMAT(),

           COLLECTD_PUTVAL_N(flow_category_media_count),
           COLLECTD_PUTVAL_N(flow_category_vpn_count),
           COLLECTD_PUTVAL_N(flow_category_email_count),
           COLLECTD_PUTVAL_N(flow_category_data_transfer_count),
           COLLECTD_PUTVAL_N(flow_category_web_count),
           COLLECTD_PUTVAL_N(flow_category_social_network_count),
           COLLECTD_PUTVAL_N(flow_category_download_count),
           COLLECTD_PUTVAL_N(flow_category_game_count),
           COLLECTD_PUTVAL_N(flow_category_chat_count),
           COLLECTD_PUTVAL_N(flow_category_voip_count),
           COLLECTD_PUTVAL_N(flow_category_database_count),
           COLLECTD_PUTVAL_N(flow_category_remote_access_count),
           COLLECTD_PUTVAL_N(flow_category_cloud_count),
           COLLECTD_PUTVAL_N(flow_category_network_count),
           COLLECTD_PUTVAL_N(flow_category_collaborative_count),
           COLLECTD_PUTVAL_N(flow_category_rpc_count),
           COLLECTD_PUTVAL_N(flow_category_streaming_count),
           COLLECTD_PUTVAL_N(flow_category_system_count),
           COLLECTD_PUTVAL_N(flow_category_software_update_count),
           COLLECTD_PUTVAL_N(flow_category_music_count),
           COLLECTD_PUTVAL_N(flow_category_video_count),
           COLLECTD_PUTVAL_N(flow_category_shopping_count),
           COLLECTD_PUTVAL_N(flow_category_productivity_count),
           COLLECTD_PUTVAL_N(flow_category_file_sharing_count),
           COLLECTD_PUTVAL_N(flow_category_mining_count),
           COLLECTD_PUTVAL_N(flow_category_malware_count),
           COLLECTD_PUTVAL_N(flow_category_advertisment_count),
           COLLECTD_PUTVAL_N(flow_category_unknown_count));

    printf(COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
               COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT()
                   COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT() COLLECTD_PUTVAL_N_FORMAT(),

           COLLECTD_PUTVAL_N(flow_l3_ip4_count),
           COLLECTD_PUTVAL_N(flow_l3_ip6_count),
           COLLECTD_PUTVAL_N(flow_l3_other_count),
           COLLECTD_PUTVAL_N(flow_l4_tcp_count),
           COLLECTD_PUTVAL_N(flow_l4_udp_count),
           COLLECTD_PUTVAL_N(flow_l4_icmp_count),
           COLLECTD_PUTVAL_N(flow_l4_other_count),
           COLLECTD_PUTVAL_N(flow_risk_unknown_count),
           COLLECTD_PUTVAL_N(error_unknown_count),
           COLLECTD_PUTVAL_N(error_count_sum));

    for (i = 0; i < ERROR_EVENT_ID_MAX; ++i)
    {
        char gauge_name[BUFSIZ];
        snprintf(gauge_name, sizeof(gauge_name), "error_%zu_count", i);
        printf(COLLECTD_PUTVAL_N_FORMAT(), COLLECTD_PUTVAL_N2(gauge_name, error_count[i]));
    }

    for (i = 0; i < NDPI_MAX_RISK; ++i)
    {
        char gauge_name[BUFSIZ];
        snprintf(gauge_name, sizeof(gauge_name), "flow_risk_%zu_count", i);
        printf(COLLECTD_PUTVAL_N_FORMAT(), COLLECTD_PUTVAL_N2(gauge_name, flow_risk_count[i]));
    }

    memset(&collectd_statistics, 0, sizeof(collectd_statistics));
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
                LOG(LOG_DAEMON | LOG_ERR, "Epoll event error: %s", (errno != 0 ? strerror(errno) : "EPOLLERR"));
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
                    LOG(LOG_DAEMON | LOG_ERR, "Parent process %d exited. Nothing left to do here, bye.", collectd_pid);
                    return 1;
                }

                errno = 0;
                if (read(collectd_timerfd, &expirations, sizeof(expirations)) != sizeof(expirations))
                {
                    LOG(LOG_DAEMON | LOG_ERR, "Could not read timer expirations: %s", strerror(errno));
                    return 1;
                }
                if (set_collectd_timer() != 0)
                {
                    LOG(LOG_DAEMON | LOG_ERR, "Could not set timer: %s", strerror(errno));
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
                    LOG(LOG_DAEMON | LOG_ERR, "nDPIsrvd read failed with: %s", nDPIsrvd_enum_to_string(read_ret));
                    return 1;
                }

                enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(sock);
                if (parse_ret != PARSE_NEED_MORE_DATA)
                {
                    LOG(LOG_DAEMON | LOG_ERR, "nDPIsrvd parse failed with: %s", nDPIsrvd_enum_to_string(parse_ret));
                    return 1;
                }
            }
        }
    }

    return 0;
}

static void collectd_map_token_to_stat(struct nDPIsrvd_socket * const sock,
                                       struct nDPIsrvd_json_token const * const token,
                                       struct json_stat_map const * const map,
                                       size_t map_length)
{
    size_t i, null_i = map_length;

    if (token == NULL)
    {
        return;
    }

    for (i = 0; i < map_length; ++i)
    {
        if (map[i].json_key == NULL)
        {
            null_i = i;
            continue;
        }

        if (TOKEN_VALUE_EQUALS(sock, token, map[i].json_key, strlen(map[i].json_key)) != 0)
        {
            (*map[i].collectd_stat)++;
            return;
        }
    }

    if (null_i < map_length)
    {
        (*map[null_i].collectd_stat)++;
    }
}

static enum nDPIsrvd_callback_return collectd_json_callback(struct nDPIsrvd_socket * const sock,
                                                            struct nDPIsrvd_instance * const instance,
                                                            struct nDPIsrvd_thread_data * const thread_data,
                                                            struct nDPIsrvd_flow * const flow)
{
    (void)instance;
    (void)thread_data;

    struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");
    struct flow_user_data * flow_user_data = NULL;

    collectd_statistics.json_lines++;
    collectd_statistics.json_bytes += sock->buffer.json_string_length + NETWORK_BUFFER_LENGTH_DIGITS;

    struct nDPIsrvd_json_token const * const packet_event_name = TOKEN_GET_SZ(sock, "packet_event_name");
    if (packet_event_name != NULL)
    {
        collectd_map_token_to_stat(sock, packet_event_name, packet_event_map, nDPIsrvd_ARRAY_LENGTH(packet_event_map));
    }

    struct nDPIsrvd_json_token const * const daemon_event_name = TOKEN_GET_SZ(sock, "daemon_event_name");
    if (daemon_event_name != NULL)
    {
        collectd_map_token_to_stat(sock, daemon_event_name, daemon_event_map, nDPIsrvd_ARRAY_LENGTH(daemon_event_map));
    }

    struct nDPIsrvd_json_token const * const error_event_id = TOKEN_GET_SZ(sock, "error_event_id");
    if (error_event_id != NULL)
    {
        nDPIsrvd_ull error_event_id_ull;
        if (TOKEN_VALUE_TO_ULL(sock, error_event_id, &error_event_id_ull) != CONVERSION_OK)
        {
            return CALLBACK_ERROR;
        }

        collectd_statistics.error_count_sum++;
        if (error_event_id_ull < ERROR_EVENT_ID_MAX)
        {
            collectd_statistics.error_count[error_event_id_ull]++;
        }
        else
        {
            collectd_statistics.error_unknown_count++;
        }
    }

    if (flow != NULL)
    {
        flow_user_data = (struct flow_user_data *)flow->flow_user_data;
    }

    if (flow_user_data != NULL)
    {
        nDPIsrvd_ull total_bytes_ull[2] = {0, 0};

        if (TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_src_tot_l4_payload_len"), &total_bytes_ull[0]) ==
                CONVERSION_OK &&
            TOKEN_VALUE_TO_ULL(sock, TOKEN_GET_SZ(sock, "flow_dst_tot_l4_payload_len"), &total_bytes_ull[1]) ==
                CONVERSION_OK)
        {
            collectd_statistics.flow_src_total_bytes +=
                total_bytes_ull[0] - flow_user_data->last_flow_src_l4_payload_len;
            collectd_statistics.flow_dst_total_bytes +=
                total_bytes_ull[1] - flow_user_data->last_flow_dst_l4_payload_len;

            flow_user_data->last_flow_src_l4_payload_len = total_bytes_ull[0];
            flow_user_data->last_flow_dst_l4_payload_len = total_bytes_ull[1];
        }
    }

    collectd_map_token_to_stat(sock, flow_event_name, flow_event_map, nDPIsrvd_ARRAY_LENGTH(flow_event_map));
    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "new") != 0)
    {
        struct nDPIsrvd_json_token const * const l3_proto = TOKEN_GET_SZ(sock, "l3_proto");
        if (TOKEN_VALUE_EQUALS_SZ(sock, l3_proto, "ip4") != 0)
        {
            collectd_statistics.flow_l3_ip4_count++;
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l3_proto, "ip6") != 0)
        {
            collectd_statistics.flow_l3_ip6_count++;
        }
        else if (l3_proto != NULL)
        {
            collectd_statistics.flow_l3_other_count++;
        }

        struct nDPIsrvd_json_token const * const l4_proto = TOKEN_GET_SZ(sock, "l4_proto");
        if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "tcp") != 0)
        {
            collectd_statistics.flow_l4_tcp_count++;
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "udp") != 0)
        {
            collectd_statistics.flow_l4_udp_count++;
        }
        else if (TOKEN_VALUE_EQUALS_SZ(sock, l4_proto, "icmp") != 0)
        {
            collectd_statistics.flow_l4_icmp_count++;
        }
        else if (l4_proto != NULL)
        {
            collectd_statistics.flow_l4_other_count++;
        }
    }
    else if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detected") != 0 ||
             TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detection-update") != 0 ||
             TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "update") != 0)
    {
        struct nDPIsrvd_json_token const * const flow_risk = TOKEN_GET_SZ(sock, "ndpi", "flow_risk");
        struct nDPIsrvd_json_token const * current = NULL;
        int next_child_index = -1;

        if (flow_risk != NULL)
        {
            if (flow_user_data->detected_risks == 0)
            {
                collectd_statistics.flow_risky_count++;
            }

            while ((current = nDPIsrvd_get_next_token(sock, flow_risk, &next_child_index)) != NULL)
            {
                nDPIsrvd_ull numeric_risk_value = (nDPIsrvd_ull)-1;

                if (str_value_to_ull(TOKEN_GET_KEY(sock, current, NULL), &numeric_risk_value) == CONVERSION_OK)
                {
                    if ((flow_user_data->detected_risks & (1 << numeric_risk_value)) == 0)
                    {
                        if (numeric_risk_value < NDPI_MAX_RISK)
                        {
                            collectd_statistics.flow_risk_count[numeric_risk_value]++;
                        }
                        else
                        {
                            collectd_statistics.flow_risk_unknown_count++;
                        }
                    }
                    flow_user_data->detected_risks |= (1 << numeric_risk_value);
                }
            }
        }

        struct nDPIsrvd_json_token const * const breed = TOKEN_GET_SZ(sock, "ndpi", "breed");
        collectd_map_token_to_stat(sock, breed, breeds_map, nDPIsrvd_ARRAY_LENGTH(breeds_map));

        struct nDPIsrvd_json_token const * const category = TOKEN_GET_SZ(sock, "ndpi", "category");
        collectd_map_token_to_stat(sock, category, categories_map, nDPIsrvd_ARRAY_LENGTH(categories_map));
    }

    return CALLBACK_OK;
}

int main(int argc, char ** argv)
{
    int retval = 1, epollfd = -1;

    openlog("nDPIsrvd-collectd", LOG_CONS, LOG_DAEMON);

    struct nDPIsrvd_socket * sock =
        nDPIsrvd_socket_init(0, 0, 0, sizeof(struct flow_user_data), collectd_json_callback, NULL, NULL);
    if (sock == NULL)
    {
        LOG(LOG_DAEMON | LOG_ERR, "%s", "nDPIsrvd socket memory allocation failed!");
        return 1;
    }

    if (parse_options(argc, argv, sock) != 0)
    {
        goto failure;
    }

    if (getenv("COLLECTD_HOSTNAME") == NULL && getenv("COLLECTD_INTERVAL") == NULL)
    {
        LOG(LOG_DAEMON | LOG_NOTICE, "Recv buffer size: %u", NETWORK_BUFFER_MAX_SIZE);
        LOG(LOG_DAEMON | LOG_NOTICE, "Connecting to `%s'..", serv_optarg);
    }
    else
    {
        quiet = 1;
        LOG(LOG_DAEMON | LOG_NOTICE, "Collectd hostname: %s", getenv("COLLECTD_HOSTNAME"));
        LOG(LOG_DAEMON | LOG_NOTICE, "Collectd interval: %llu", collectd_interval_ull);
    }

    if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
    {
        LOG(LOG_DAEMON | LOG_ERR,
            "Could not set stdout unbuffered: %s. Collectd may receive too old PUTVALs and complain.",
            strerror(errno));
    }

    enum nDPIsrvd_connect_return connect_ret = nDPIsrvd_connect(sock);
    if (connect_ret != CONNECT_OK)
    {
        LOG(LOG_DAEMON | LOG_ERR, "nDPIsrvd socket connect to %s failed!", serv_optarg);
        goto failure;
    }

    if (nDPIsrvd_set_nonblock(sock) != 0)
    {
        LOG(LOG_DAEMON | LOG_ERR, "nDPIsrvd set nonblock failed: %s", strerror(errno));
        goto failure;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    collectd_pid = getppid();

    epollfd = epoll_create1(0);
    if (epollfd < 0)
    {
        LOG(LOG_DAEMON | LOG_ERR, "Error creating epoll: %s", strerror(errno));
        goto failure;
    }

    if (create_collectd_timer() != 0)
    {
        LOG(LOG_DAEMON | LOG_ERR, "Error creating timer: %s", strerror(errno));
        goto failure;
    }

    {
        struct epoll_event timer_event = {.data.fd = collectd_timerfd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, collectd_timerfd, &timer_event) < 0)
        {
            LOG(LOG_DAEMON | LOG_ERR, "Error adding JSON fd to epoll: %s", strerror(errno));
            goto failure;
        }
    }

    {
        struct epoll_event socket_event = {.data.fd = sock->fd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock->fd, &socket_event) < 0)
        {
            LOG(LOG_DAEMON | LOG_ERR, "Error adding nDPIsrvd socket fd to epoll: %s", strerror(errno));
            goto failure;
        }
    }

    LOG(LOG_DAEMON | LOG_NOTICE, "%s", "Initialization succeeded.");
    retval = mainloop(epollfd, sock);

failure:
    nDPIsrvd_socket_free(&sock);
    close(collectd_timerfd);
    close(epollfd);
    closelog();

    return retval;
}
