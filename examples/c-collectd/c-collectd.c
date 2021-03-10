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

static struct nDPIsrvd_socket * sock = NULL;
static int main_thread_shutdown = 0;
static int collectd_timerfd = -1;

static char * serv_optarg = NULL;
static char * collectd_hostname = NULL;
static char * collectd_interval = NULL;
static nDPIsrvd_ull collectd_interval_ull = 0uL;

static struct {
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
    syslog(LOG_DAEMON | LOG_NOTICE, "Received SIGNAL %d", signum);

    if (main_thread_shutdown == 0)
    {
        syslog(LOG_DAEMON | LOG_NOTICE, "Shutting down ..");
        main_thread_shutdown = 1;
    }
    else
    {
        syslog(LOG_DAEMON | LOG_NOTICE, "Reader threads are already shutting down, please be patient.");
    }
}

static int parse_options(int argc, char ** argv)
{
    int opt;

    static char const usage[] =
        "Usage: %s "
        "[-s host] [-i interval]\n\n"
        "\t-s\tDestination where nDPIsrvd is listening on.\n"
        "\t-c\tCollectd hostname.\n"
        "\t  \tThis value defaults to the environment variable COLLECTD_HOSTNAME.\n"
        "\t-i\tInterval between print statistics to stdout.\n"
        "\t  \tThis value defaults to the environment variable COLLECTD_INTERVAL.\n";

    while ((opt = getopt(argc, argv, "hs:c:i:")) != -1)
    {
        switch (opt)
        {
            case 's':
                free(serv_optarg);
                serv_optarg = strdup(optarg);
                break;
            case 'c':
                free(collectd_hostname);
                collectd_hostname =  strdup(optarg);
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
        fprintf(stderr, "%s: Collectd interval `%s' is not a valid number\n", argv[0], collectd_interval);
        return 1;
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

#define COLLECTD_PUTVAL_N_FORMAT(name) "PUTVAL %s/nDPId/" #name " interval=%llu N:%llu\n"
#define COLLECTD_PUTVAL_N(value) collectd_hostname, collectd_interval_ull, (unsigned long long int)collectd_statistics.value
static void print_collectd_exec_output(void)
{
    printf(COLLECTD_PUTVAL_N_FORMAT(flow_new_count)
           COLLECTD_PUTVAL_N_FORMAT(flow_end_count)
           COLLECTD_PUTVAL_N_FORMAT(flow_idle_count)
           COLLECTD_PUTVAL_N_FORMAT(flow_guessed_count)
           COLLECTD_PUTVAL_N_FORMAT(flow_detected_count)
           COLLECTD_PUTVAL_N_FORMAT(flow_detection_update_count)
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
                syslog(LOG_DAEMON | LOG_ERR, "Epoll event error: %s", (errno != 0 ? strerror(errno) : "EPOLLERR"));
                break;
            }

            if (events[i].data.fd == collectd_timerfd)
            {
                uint64_t expirations;

                errno = 0;
                if (read(collectd_timerfd, &expirations, sizeof(expirations)) != sizeof(expirations))
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Could not read timer expirations: %s", strerror(errno));
                    return 1;
                }
                if (set_collectd_timer() != 0)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Could not set timer: %s", strerror(errno));
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
                    syslog(LOG_DAEMON | LOG_ERR, "nDPIsrvd read failed with: %s", nDPIsrvd_enum_to_string(read_ret));
                    return 1;
                }

                enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse(sock);
                if (parse_ret != PARSE_OK)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "nDPIsrvd parse failed with: %s", nDPIsrvd_enum_to_string(parse_ret));
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
    } else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "end") != 0)
    {
        collectd_statistics.flow_end_count++;
    } else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "idle") != 0)
    {
        collectd_statistics.flow_idle_count++;
    } else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "guessed") != 0)
    {
        collectd_statistics.flow_guessed_count++;
    } else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "detected") != 0)
    {
        collectd_statistics.flow_detected_count++;
    } else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "detection-update") != 0)
    {
        collectd_statistics.flow_detection_update_count++;
    } else if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "not-detected") != 0)
    {
        collectd_statistics.flow_not_detected_count++;
    }

    return CALLBACK_OK;
}

int main(int argc, char ** argv)
{
    int retval = 1;

    sock = nDPIsrvd_init(0, 0, captured_json_callback, NULL);
    if (sock == NULL)
    {
        fprintf(stderr, "%s: nDPIsrvd socket memory allocation failed!\n", argv[0]);
        return 1;
    }

    if (parse_options(argc, argv) != 0)
    {
        return 1;
    }

    printf("Recv buffer size: %u\n", NETWORK_BUFFER_MAX_SIZE);
    printf("Connecting to `%s'..\n", serv_optarg);

    enum nDPIsrvd_connect_return connect_ret = nDPIsrvd_connect(sock);
    if (connect_ret != CONNECT_OK)
    {
        fprintf(stderr, "%s: nDPIsrvd socket connect to %s failed!\n", argv[0], serv_optarg);
        nDPIsrvd_free(&sock);
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    openlog("nDPIsrvd-collectd", LOG_CONS, LOG_DAEMON);

    int epollfd = epoll_create1(0);
    if (epollfd < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error creating epoll: %s", strerror(errno));
        return 1;
    }

    if (create_collectd_timer() != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error creating timer: %s", strerror(errno));
        return 1;
    }

    {
        struct epoll_event timer_event = {.data.fd = collectd_timerfd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, collectd_timerfd, &timer_event) < 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Error adding JSON fd to epoll: %s", strerror(errno));
            return 1;
        }
    }

    {
        struct epoll_event socket_event = {.data.fd = sock->fd, .events = EPOLLIN};
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock->fd, &socket_event) < 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Error adding nDPIsrvd socket fd to epoll: %s", strerror(errno));
            return 1;
        }
    }

    syslog(LOG_DAEMON | LOG_NOTICE, "%s", "Initialization succeeded.");
    retval = mainloop(epollfd);

    nDPIsrvd_free(&sock);
    close(collectd_timerfd);
    close(epollfd);
    closelog();

    return retval;
}
