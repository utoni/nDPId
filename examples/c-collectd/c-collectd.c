#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "nDPIsrvd.h"

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

static struct nDPIsrvd_socket * sock = NULL;
static int main_thread_shutdown = 0;
static int collectd_timerfd = -1;

static char * serv_optarg = NULL;
static char * collectd_hostname = NULL;
static char * collectd_interval = NULL;
static nDPIsrvd_ull collectd_interval_ull = 0uL;
static int quiet = 0;

static struct
{
    uint64_t flow_new_count;
    uint64_t flow_end_count;
    uint64_t flow_idle_count;
    uint64_t flow_guessed_count;
    uint64_t flow_detected_count;
    uint64_t flow_detection_update_count;
    uint64_t flow_not_detected_count;
} collectd_statistics = {};

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

static int parse_options(int argc, char ** argv)
{
    int opt;

    static char const usage[] =
        "Usage: %s "
        "[-s host] [-c hostname] [-i interval] [-q]\n\n"
        "\t-s\tDestination where nDPIsrvd is listening on.\n"
        "\t-c\tCollectd hostname.\n"
        "\t  \tThis value defaults to the environment variable COLLECTD_HOSTNAME.\n"
        "\t-i\tInterval between print statistics to stdout.\n"
        "\t  \tThis value defaults to the environment variable COLLECTD_INTERVAL.\n"
        "\t-q\tDo not print anything except collectd statistics.\n"
        "\t  \tAutomatically enabled if environment variables mentioned above are set.\n";

    while ((opt = getopt(argc, argv, "hs:c:i:q")) != -1)
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

#define COLLECTD_PUTVAL_N_FORMAT(name) "PUTVAL %s/nDPId/" #name " interval=%llu %llu:%llu\n"
#define COLLECTD_PUTVAL_N(value)                                                                                       \
    collectd_hostname, collectd_interval_ull, (unsigned long long int)now,                                             \
        (unsigned long long int)collectd_statistics.value
static void print_collectd_exec_output(void)
{
    time_t now = time(NULL);

    printf(COLLECTD_PUTVAL_N_FORMAT(flow_new_count) COLLECTD_PUTVAL_N_FORMAT(flow_end_count)
               COLLECTD_PUTVAL_N_FORMAT(flow_idle_count) COLLECTD_PUTVAL_N_FORMAT(flow_guessed_count)
                   COLLECTD_PUTVAL_N_FORMAT(flow_detected_count) COLLECTD_PUTVAL_N_FORMAT(flow_detection_update_count)
                       COLLECTD_PUTVAL_N_FORMAT(flow_not_detected_count),

           COLLECTD_PUTVAL_N(flow_new_count),
           COLLECTD_PUTVAL_N(flow_end_count),
           COLLECTD_PUTVAL_N(flow_idle_count),
           COLLECTD_PUTVAL_N(flow_guessed_count),
           COLLECTD_PUTVAL_N(flow_detected_count),
           COLLECTD_PUTVAL_N(flow_detection_update_count),
           COLLECTD_PUTVAL_N(flow_not_detected_count));

    memset(&collectd_statistics, 0, sizeof(collectd_statistics));
}

static int mainloop(int epollfd)
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

                enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse(sock);
                if (parse_ret != PARSE_OK)
                {
                    LOG(LOG_DAEMON | LOG_ERR, "nDPIsrvd parse failed with: %s", nDPIsrvd_enum_to_string(parse_ret));
                    return 1;
                }
            }
        }
    }

    return 0;
}

static enum nDPIsrvd_callback_return captured_json_callback(struct nDPIsrvd_socket * const sock,
                                                            struct nDPIsrvd_flow * const flow)
{
    (void)sock;
    (void)flow;

    struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");

    if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "new") != 0)
    {
        collectd_statistics.flow_new_count++;
    }
    else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "end") != 0)
    {
        collectd_statistics.flow_end_count++;
    }
    else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "idle") != 0)
    {
        collectd_statistics.flow_idle_count++;
    }
    else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "guessed") != 0)
    {
        collectd_statistics.flow_guessed_count++;
    }
    else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "detected") != 0)
    {
        collectd_statistics.flow_detected_count++;
    }
    else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "detection-update") != 0)
    {
        collectd_statistics.flow_detection_update_count++;
    }
    else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "not-detected") != 0)
    {
        collectd_statistics.flow_not_detected_count++;
    }

    return CALLBACK_OK;
}

int main(int argc, char ** argv)
{
    int retval = 1;

    openlog("nDPIsrvd-collectd", LOG_CONS, LOG_DAEMON);

    sock = nDPIsrvd_init(0, 0, captured_json_callback, NULL);
    if (sock == NULL)
    {
        LOG(LOG_DAEMON | LOG_ERR, "%s", "nDPIsrvd socket memory allocation failed!");
        return 1;
    }

    if (parse_options(argc, argv) != 0)
    {
        return 1;
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

    enum nDPIsrvd_connect_return connect_ret = nDPIsrvd_connect(sock);
    if (connect_ret != CONNECT_OK)
    {
        LOG(LOG_DAEMON | LOG_ERR, "nDPIsrvd socket connect to %s failed!", serv_optarg);
        nDPIsrvd_free(&sock);
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    int epollfd = epoll_create1(0);
    if (epollfd < 0)
    {
        LOG(LOG_DAEMON | LOG_ERR, "Error creating epoll: %s", strerror(errno));
        return 1;
    }

    if (create_collectd_timer() != 0)
    {
        LOG(LOG_DAEMON | LOG_ERR, "Error creating timer: %s", strerror(errno));
        return 1;
    }

    {
        struct epoll_event timer_event = {.data.fd = collectd_timerfd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, collectd_timerfd, &timer_event) < 0)
        {
            LOG(LOG_DAEMON | LOG_ERR, "Error adding JSON fd to epoll: %s", strerror(errno));
            return 1;
        }
    }

    {
        struct epoll_event socket_event = {.data.fd = sock->fd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock->fd, &socket_event) < 0)
        {
            LOG(LOG_DAEMON | LOG_ERR, "Error adding nDPIsrvd socket fd to epoll: %s", strerror(errno));
            return 1;
        }
    }

    LOG(LOG_DAEMON | LOG_NOTICE, "%s", "Initialization succeeded.");
    retval = mainloop(epollfd);

    nDPIsrvd_free(&sock);
    close(collectd_timerfd);
    close(epollfd);
    closelog();

    return retval;
}
