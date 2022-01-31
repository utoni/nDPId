#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>

/*
 * Mock some syslog variables and functions.
 * This way, we do not spam any syslog daemon on the host.
 */
#define LOG_DAEMON 0x1
#define LOG_ERR 0x2
#define LOG_CONS 0x4
#define LOG_PERROR 0x8

static void openlog(char const * const ident, int option, int facility);
static void syslog(int p, char const * const format, ...);
static void closelog(void);
static void nDPIsrvd_memprof_log(char const * const format, ...);

#define NO_MAIN 1
#include "nDPIsrvd.c"
#include "nDPId.c"

enum
{
    PIPE_nDPId = 1,    /* nDPId mock pipefd array index */
    PIPE_nDPIsrvd = 0, /* nDPIsrvd mock pipefd array index */

    PIPE_TEST_WRITE = 1, /* Distributor (data from nDPIsrvd) write */
    PIPE_TEST_READ = 0,  /* Distributor (do some validation tests) read */

    PIPE_NULL_WRITE = 1, /* Distributor (data from nDPIsrvd) write */
    PIPE_NULL_READ = 0,  /* Distributor (print to stdout) read */

    PIPE_FDS = 2,
    MAX_REMOTE_DESCRIPTORS = 3 /* mock pipefd's + 2 * distributor pipefd's */
};

struct thread_return_value
{
    int val;
};

struct nDPId_return_value
{
    struct thread_return_value thread_return_value;

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_skipped_flows;
    unsigned long long int total_l4_data_len;

    unsigned long long int not_detected_flow_protocols;
    unsigned long long int guessed_flow_protocols;
    unsigned long long int detected_flow_protocols;
    unsigned long long int flow_detection_updates;
    unsigned long long int flow_updates;

    unsigned long long int total_active_flows;
    unsigned long long int total_idle_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int cur_idle_flows;

    unsigned long long int total_events_serialized;
};

struct distributor_global_user_data
{
    unsigned long long int total_packets_processed;
    unsigned long long int total_l4_data_len;
    unsigned long long int total_events_deserialized;
    unsigned long long int total_events_serialized;
    unsigned long long int total_flow_timeouts;

    unsigned long long int flow_new_count;
    unsigned long long int flow_end_count;
    unsigned long long int flow_idle_count;
    unsigned long long int flow_detected_count;
    unsigned long long int flow_guessed_count;
    unsigned long long int flow_not_detected_count;
    unsigned long long int flow_detection_update_count;
    unsigned long long int flow_update_count;

    unsigned long long int json_string_len_min;
    unsigned long long int json_string_len_max;
    double json_string_len_avg;

    unsigned long long int cur_active_flows;
    unsigned long long int cur_idle_flows;

    int flow_cleanup_error;
};

struct distributor_flow_user_data
{
    unsigned long long int total_packets_processed;
    unsigned long long int flow_total_l4_data_len;
    uint8_t is_flow_timedout;
};

struct distributor_return_value
{
    struct thread_return_value thread_return_value;

    struct distributor_global_user_data stats;
};

static int mock_pipefds[PIPE_FDS] = {};
static int mock_testfds[PIPE_FDS] = {};
static int mock_nullfds[PIPE_FDS] = {};
static pthread_mutex_t nDPId_start_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nDPIsrvd_start_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t distributor_start_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

#define THREAD_ERROR(thread_arg)                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        ((struct thread_return_value *)thread_arg)->val = 1;                                                           \
    } while (0);
#define THREAD_ERROR_GOTO(thread_arg)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        THREAD_ERROR(thread_arg);                                                                                      \
        goto error;                                                                                                    \
    } while (0);

static void openlog(char const * const ident, int option, int facility)
{
    (void)ident;
    (void)option;
    (void)facility;
}

static void syslog(int p, char const * const format, ...)
{
    va_list ap;

    (void)p;
    va_start(ap, format);
    pthread_mutex_lock(&log_mutex);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "%s\n", "");
    pthread_mutex_unlock(&log_mutex);
    va_end(ap);
}

static void closelog(void)
{
}

static void nDPIsrvd_memprof_log(char const * const format, ...)
{
    va_list ap;

    va_start(ap, format);
    pthread_mutex_lock(&log_mutex);
    fprintf(stderr, "%s", "nDPIsrvd MemoryProfiler: ");
    vfprintf(stderr, format, ap);
    fprintf(stderr, "%s\n", "");
    pthread_mutex_unlock(&log_mutex);
    va_end(ap);
}

static int setup_pipe(int pipefd[PIPE_FDS])
{
    if (pipe(pipefd) != 0)
    {
        return -1;
    }

    return 0;
}

static void * nDPIsrvd_mainloop_thread(void * const arg)
{
    (void)arg;
    int epollfd = create_evq();
    struct remote_desc * mock_json_desc = NULL;
    struct remote_desc * mock_test_desc = NULL;
    struct remote_desc * mock_null_desc = NULL;
    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);

    if (epollfd < 0)
    {
        syslog(0, "nDPIsrvd epollfd invalid: %d", epollfd);
        THREAD_ERROR_GOTO(arg);
    }

    mock_json_desc = get_unused_remote_descriptor(JSON_SOCK, mock_pipefds[PIPE_nDPIsrvd], NETWORK_BUFFER_MAX_SIZE);
    if (mock_json_desc == NULL)
    {
        syslog(0, "%s", "nDPIsrvd could not acquire remote descriptor (Collector)");
        THREAD_ERROR_GOTO(arg);
    }

    mock_test_desc =
        get_unused_remote_descriptor(SERV_SOCK, mock_testfds[PIPE_TEST_WRITE], NETWORK_BUFFER_MAX_SIZE / 4);
    if (mock_test_desc == NULL)
    {
        syslog(0, "%s", "nDPIsrvd could not acquire remote descriptor (TEST Distributor)");
        THREAD_ERROR_GOTO(arg);
    }

    mock_null_desc = get_unused_remote_descriptor(SERV_SOCK, mock_nullfds[PIPE_NULL_WRITE], NETWORK_BUFFER_MAX_SIZE);
    if (mock_null_desc == NULL)
    {
        syslog(0, "%s", "nDPIsrvd could not acquire remote descriptor (NULL Distributor)");
        THREAD_ERROR_GOTO(arg);
    }

    strncpy(mock_test_desc->event_serv.peer_addr, "0.0.0.0", sizeof(mock_test_desc->event_serv.peer_addr));
    mock_test_desc->event_serv.peer.sin_port = 0;
    strncpy(mock_null_desc->event_serv.peer_addr, "0.0.0.0", sizeof(mock_null_desc->event_serv.peer_addr));
    mock_null_desc->event_serv.peer.sin_port = 0;

    if (add_in_event(epollfd, mock_pipefds[PIPE_nDPIsrvd], mock_json_desc) != 0 ||
        add_in_event(epollfd, mock_testfds[PIPE_TEST_WRITE], mock_test_desc) != 0 ||
        add_in_event(epollfd, mock_nullfds[PIPE_NULL_WRITE], mock_null_desc) != 0)
    {
        syslog(0, "%s", "nDPIsrvd add input event failed");
        THREAD_ERROR_GOTO(arg);
    }

    pthread_mutex_lock(&nDPIsrvd_start_mutex);

    while (1)
    {
        int nready = epoll_wait(epollfd, events, events_size, -1);

        if (nready < 0)
        {
            THREAD_ERROR_GOTO(arg);
        }

        for (int i = 0; i < nready; i++)
        {
            if (events[i].data.ptr == mock_json_desc)
            {
                if (handle_data_event(epollfd, &events[i]) != 0)
                {
                    goto error;
                }
            }
            else
            {
                syslog(0,
                       "nDPIsrvd epoll returned unexpected event data: %d (%p)",
                       events[i].data.fd,
                       events[i].data.ptr);
                THREAD_ERROR_GOTO(arg);
            }
        }
    }

error:
    if (mock_test_desc != NULL)
    {
        drain_cache_blocking(mock_test_desc);
    }
    if (mock_null_desc != NULL)
    {
        drain_cache_blocking(mock_null_desc);
    }

    del_event(epollfd, mock_pipefds[PIPE_nDPIsrvd]);
    del_event(epollfd, mock_testfds[PIPE_TEST_WRITE]);
    del_event(epollfd, mock_nullfds[PIPE_NULL_WRITE]);
    close(mock_pipefds[PIPE_nDPIsrvd]);
    close(mock_testfds[PIPE_TEST_WRITE]);
    close(mock_nullfds[PIPE_NULL_WRITE]);
    close(epollfd);

    return NULL;
}

static enum nDPIsrvd_callback_return distributor_json_callback(struct nDPIsrvd_socket * const sock,
                                                               struct nDPIsrvd_instance * const instance,
                                                               struct nDPIsrvd_flow * const flow)
{
    struct distributor_global_user_data * const global_stats =
        (struct distributor_global_user_data *)sock->global_user_data;
    struct distributor_flow_user_data * flow_stats = NULL;

#if 0
    printf("Distributor: %.*s\n", (int)sock->buffer.json_string_length, sock->buffer.json_string);
#endif

    if (flow != NULL)
    {
        flow_stats = (struct distributor_flow_user_data *)flow->flow_user_data;
    }

    if (sock->buffer.json_string_length < global_stats->json_string_len_min)
    {
        global_stats->json_string_len_min = sock->buffer.json_string_length;
    }
    if (sock->buffer.json_string_length > global_stats->json_string_len_max)
    {
        global_stats->json_string_len_max = sock->buffer.json_string_length;
    }
    global_stats->json_string_len_avg = (global_stats->json_string_len_avg +
                                         (global_stats->json_string_len_max + global_stats->json_string_len_min) / 2) /
                                        2;

    global_stats->total_events_deserialized++;

    {
        struct nDPIsrvd_json_token const * const daemon_event_name = TOKEN_GET_SZ(sock, "daemon_event_name");

        if (daemon_event_name != NULL)
        {
            if (TOKEN_VALUE_EQUALS_SZ(daemon_event_name, "shutdown") != 0)
            {
                struct nDPIsrvd_json_token const * const total_events_serialized =
                    TOKEN_GET_SZ(sock, "total-events-serialized");

                if (total_events_serialized != NULL)
                {
                    nDPIsrvd_ull nmb = 0;
                    if (TOKEN_VALUE_TO_ULL(total_events_serialized, &nmb) != CONVERSION_OK)
                    {
                        return CALLBACK_ERROR;
                    }

                    global_stats->total_events_serialized = nmb;
                }
            }
        }
    }

    {
        struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");

        if (flow_event_name != NULL)
        {
            if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "new") != 0)
            {
                global_stats->cur_active_flows++;
                global_stats->flow_new_count++;

                unsigned hash_count = HASH_COUNT(instance->flow_table);
                if (hash_count != global_stats->cur_active_flows)
                {
                    syslog(0,
                           "Amount of flows in the flow table not equal to current active flows counter: %u != %llu",
                           hash_count,
                           global_stats->cur_active_flows);
                    return CALLBACK_ERROR;
                }
            }
            if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "end") != 0)
            {
                global_stats->cur_active_flows--;
                global_stats->cur_idle_flows++;
                global_stats->flow_end_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "idle") != 0)
            {
                global_stats->cur_active_flows--;
                global_stats->cur_idle_flows++;
                global_stats->flow_idle_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "detected") != 0)
            {
                global_stats->flow_detected_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "guessed") != 0)
            {
                global_stats->flow_guessed_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "not-detected") != 0)
            {
                global_stats->flow_not_detected_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "detection-update") != 0)
            {
                global_stats->flow_detection_update_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "update") != 0)
            {
                global_stats->flow_update_count++;
            }

            struct nDPIsrvd_flow * current_flow;
            struct nDPIsrvd_flow * ftmp;
            size_t flow_count = 0;
            HASH_ITER(hh, instance->flow_table, current_flow, ftmp)
            {
                flow_count++;
            }
            if (flow_count != global_stats->cur_active_flows + global_stats->cur_idle_flows)
            {
                syslog(0,
                       "Amount of flows in flow table not equal current active flows plus current idle flows: %llu != "
                       "%llu + %llu",
                       flow_count,
                       global_stats->cur_active_flows,
                       global_stats->cur_idle_flows);
                return CALLBACK_ERROR;
            }

            struct nDPIsrvd_json_token const * const flow_total_packets_processed =
                TOKEN_GET_SZ(sock, "flow_packets_processed");

            if (flow_total_packets_processed != NULL)
            {
                nDPIsrvd_ull nmb = 0;
                if (TOKEN_VALUE_TO_ULL(flow_total_packets_processed, &nmb) != CONVERSION_OK)
                {
                    return CALLBACK_ERROR;
                }

                if (flow_stats != NULL)
                {
                    flow_stats->total_packets_processed = nmb;
                }
            }

            struct nDPIsrvd_json_token const * const flow_total_l4_payload_len =
                TOKEN_GET_SZ(sock, "flow_tot_l4_payload_len");

            if (flow_total_l4_payload_len == NULL)
            {
                syslog(0, "%s", "Flow total l4 payload length not found in flow event");
                return CALLBACK_ERROR;
            }

            nDPIsrvd_ull nmb = 0;
            if (TOKEN_VALUE_TO_ULL(flow_total_l4_payload_len, &nmb) != CONVERSION_OK)
            {
                return CALLBACK_ERROR;
            }

            if (flow_stats != NULL)
            {
                flow_stats->flow_total_l4_data_len = nmb;
            }
        }
    }

    return CALLBACK_OK;
}

static void distributor_flow_cleanup_callback(struct nDPIsrvd_socket * const sock,
                                              struct nDPIsrvd_instance * const instance,
                                              struct nDPIsrvd_flow * const flow,
                                              enum nDPIsrvd_cleanup_reason reason)
{
    struct distributor_global_user_data * const global_stats =
        (struct distributor_global_user_data *)sock->global_user_data;
    struct distributor_flow_user_data * const flow_stats = (struct distributor_flow_user_data *)flow->flow_user_data;

    (void)instance;

    switch (reason)
    {
        case CLEANUP_REASON_DAEMON_INIT:
        case CLEANUP_REASON_DAEMON_SHUTDOWN:
            /* If that happens, it is either a BUG or caused by other applications. */
            syslog(0, "Invalid flow cleanup reason: %s", nDPIsrvd_enum_to_string(reason));
            global_stats->flow_cleanup_error = 1;
            break;

        case CLEANUP_REASON_FLOW_TIMEOUT:
            /*
             * Flow timeouts may happen. The cause is libpcap itself.
             * Unfortunately, libpcap does not provide retrieving the file descriptor if reading packets from a file.
             * Without a file descriptor select(), poll() or epoll() can not work.
             * As result all timestamps may have huge gaps depending on the recorded pcap file.
             * But those timestamps are necessary to make flow-updates work.
             */
            global_stats->total_flow_timeouts++;
            flow_stats->is_flow_timedout = 1;
            break;

        case CLEANUP_REASON_APP_SHUTDOWN:
        case CLEANUP_REASON_FLOW_END:
        case CLEANUP_REASON_FLOW_IDLE:
            break;

        case CLEANUP_REASON_LAST_ENUM_VALUE:
            break;
    }

    unsigned hash_count = HASH_COUNT(instance->flow_table);
    if (hash_count != global_stats->cur_active_flows + global_stats->cur_idle_flows)
    {
        syslog(0,
               "Flow count is not equal to current active flows plus current idle flows plus current timedout flows: "
               "%llu != %llu + %llu",
               hash_count,
               global_stats->cur_active_flows,
               global_stats->cur_idle_flows);
        global_stats->flow_cleanup_error = 1;
    }

    if (flow_stats->is_flow_timedout == 0)
    {
        global_stats->total_packets_processed += flow_stats->total_packets_processed;
        global_stats->total_l4_data_len += flow_stats->flow_total_l4_data_len;
        global_stats->cur_idle_flows--;
    }
}

static void * distributor_client_mainloop_thread(void * const arg)
{
    int dis_epollfd = create_evq();
    int signalfd = setup_signalfd(dis_epollfd);
    int pipe_read_finished = 0, null_read_finished = 0;
    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);
    struct distributor_return_value * const drv = (struct distributor_return_value *)arg;
    struct thread_return_value * const trv = &drv->thread_return_value;
    struct nDPIsrvd_socket * mock_sock = nDPIsrvd_socket_init(sizeof(struct distributor_global_user_data),
                                                              sizeof(struct distributor_flow_user_data),
                                                              distributor_json_callback,
                                                              distributor_flow_cleanup_callback);
    struct distributor_global_user_data * stats;

    if (mock_sock == NULL)
    {
        THREAD_ERROR_GOTO(trv);
    }

    mock_sock->fd = mock_testfds[PIPE_TEST_READ];

    if (dis_epollfd < 0 || signalfd < 0)
    {
        THREAD_ERROR_GOTO(trv);
    }

    if (add_in_event(dis_epollfd, mock_testfds[PIPE_TEST_READ], NULL) != 0)
    {
        THREAD_ERROR_GOTO(trv);
    }

    if (add_in_event(dis_epollfd, mock_nullfds[PIPE_NULL_READ], NULL) != 0)
    {
        THREAD_ERROR_GOTO(trv);
    }

    stats = (struct distributor_global_user_data *)mock_sock->global_user_data;
    stats->json_string_len_min = (unsigned long long int)-1;

    pthread_mutex_lock(&distributor_start_mutex);

    while (pipe_read_finished == 0 || null_read_finished == 0)
    {
        int nready = epoll_wait(dis_epollfd, events, events_size, -1);
        if (nready < 0 && errno != EINTR)
        {
            syslog(0, "%s", "Distributor epoll wait failed.");
            THREAD_ERROR_GOTO(trv);
        }

        for (int i = 0; i < nready; i++)
        {
            if ((events[i].events & EPOLLIN) == 0 && (events[i].events & EPOLLHUP) == 0)
            {
                syslog(0, "Invalid epoll event received: %d", events[i].events & (~EPOLLIN & ~EPOLLHUP));
                THREAD_ERROR_GOTO(trv);
            }

            if (events[i].data.fd == mock_testfds[PIPE_TEST_READ])
            {
                switch (nDPIsrvd_read(mock_sock))
                {
                    case READ_OK:
                        break;
                    case READ_LAST_ENUM_VALUE:
                    case READ_ERROR:
                        syslog(0, "Read and verify fd returned an error: %s", strerror(errno));
                        THREAD_ERROR_GOTO(trv);
                    case READ_PEER_DISCONNECT:
                        del_event(dis_epollfd, mock_testfds[PIPE_TEST_READ]);
                        pipe_read_finished = 1;
                        continue;
                }

                enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(mock_sock);
                if (parse_ret != PARSE_NEED_MORE_DATA)
                {
                    syslog(0, "JSON parsing failed: %s", nDPIsrvd_enum_to_string(parse_ret));
                    THREAD_ERROR_GOTO(trv);
                }

                if (stats->flow_cleanup_error != 0)
                {
                    syslog(0, "%s", "Flow cleanup callback error'd");
                    THREAD_ERROR_GOTO(trv);
                }
            }
            else if (events[i].data.fd == mock_nullfds[PIPE_NULL_READ])
            {
                /* Read all data from the pipe, but do nothing else. */
                char buf[NETWORK_BUFFER_MAX_SIZE];
                ssize_t bytes_read = read(mock_nullfds[PIPE_NULL_READ], buf, sizeof(buf));
                if (bytes_read < 0)
                {
                    syslog(0, "Read and print to stdout fd returned an error: %s", strerror(errno));
                    THREAD_ERROR_GOTO(trv);
                }
                if (bytes_read == 0)
                {
                    del_event(dis_epollfd, mock_nullfds[PIPE_NULL_READ]);
                    null_read_finished = 1;
                    continue;
                }

                printf("%.*s", (int)bytes_read, buf);
            }
            else if (events[i].data.fd == signalfd)
            {
                struct signalfd_siginfo fdsi;
                ssize_t s;

                s = read(signalfd, &fdsi, sizeof(struct signalfd_siginfo));
                if (s != sizeof(struct signalfd_siginfo))
                {
                    THREAD_ERROR(trv);
                }

                if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGQUIT)
                {
                    syslog(0, "Got signal %d, abort.", fdsi.ssi_signo);
                    THREAD_ERROR_GOTO(trv);
                }
            }
            else
            {
                syslog(0,
                       "Distributor epoll returned unexpected event data: %d (%p)",
                       events[i].data.fd,
                       events[i].data.ptr);
                THREAD_ERROR_GOTO(trv);
            }
        }
    }

    drv->stats = *stats;

    struct nDPIsrvd_instance * current_instance;
    struct nDPIsrvd_instance * itmp;
    struct nDPIsrvd_flow * current_flow;
    struct nDPIsrvd_flow * ftmp;
    HASH_ITER(hh, mock_sock->instance_table, current_instance, itmp)
    {
        HASH_ITER(hh, current_instance->flow_table, current_flow, ftmp)
        {
            syslog(0, "Active flow found during client distributor shutdown: %llu", current_flow->id_as_ull);
            THREAD_ERROR(trv);
            break;
        }
    }

error:
    del_event(dis_epollfd, signalfd);
    del_event(dis_epollfd, mock_testfds[PIPE_TEST_READ]);
    del_event(dis_epollfd, mock_nullfds[PIPE_NULL_READ]);
    close(dis_epollfd);
    close(signalfd);
    nDPIsrvd_socket_free(&mock_sock);

    return NULL;
}

static void * nDPId_mainloop_thread(void * const arg)
{
    struct nDPId_return_value * const nrv = (struct nDPId_return_value *)arg;
    struct thread_return_value * const trr = &nrv->thread_return_value;

    if (setup_reader_threads() != 0)
    {
        THREAD_ERROR(trr);
        goto error;
    }

    /* Replace nDPId JSON socket fd with the one in our pipe and hope that no socket specific code-path triggered. */
    reader_threads[0].json_sockfd = mock_pipefds[PIPE_nDPId];
    reader_threads[0].json_sock_reconnect = 0;

    pthread_mutex_lock(&nDPId_start_mutex);

    jsonize_daemon(&reader_threads[0], DAEMON_EVENT_INIT);
    /* restore SIGPIPE to the default handler (Termination) */
    if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
    {
        goto error;
    }
    run_pcap_loop(&reader_threads[0]);
    process_remaining_flows();
    for (size_t i = 0; i < nDPId_options.reader_thread_count; ++i)
    {
        nrv->packets_captured += reader_threads[i].workflow->packets_captured;
        nrv->packets_processed += reader_threads[i].workflow->packets_processed;
        nrv->total_skipped_flows += reader_threads[i].workflow->total_skipped_flows;
        nrv->total_l4_data_len += reader_threads[i].workflow->total_l4_data_len;

        nrv->not_detected_flow_protocols += reader_threads[i].workflow->total_not_detected_flows;
        nrv->guessed_flow_protocols += reader_threads[i].workflow->total_guessed_flows;
        nrv->detected_flow_protocols += reader_threads[i].workflow->total_detected_flows;
        nrv->flow_detection_updates += reader_threads[i].workflow->total_flow_detection_updates;
        nrv->flow_updates += reader_threads[i].workflow->total_flow_updates;

        nrv->total_active_flows += reader_threads[i].workflow->total_active_flows;
        nrv->total_idle_flows += reader_threads[i].workflow->total_idle_flows;
        nrv->cur_active_flows += reader_threads[i].workflow->cur_active_flows;
        nrv->cur_idle_flows += reader_threads[i].workflow->cur_idle_flows;

        nrv->total_events_serialized += reader_threads[i].workflow->total_events_serialized;
    }

error:
    free_reader_threads();
    close(mock_pipefds[PIPE_nDPId]);

    return NULL;
}

static void usage(char const * const arg0)
{
    syslog(0, "usage: %s [path-to-pcap-file]", arg0);
}

static int thread_wait_for_termination(pthread_t thread, time_t wait_time_secs, struct thread_return_value * const trv)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
    {
        return -1;
    }

    ts.tv_sec += wait_time_secs;
    int err = pthread_timedjoin_np(thread, (void **)&trv, &ts);

    switch (err)
    {
        case EBUSY:
            return 0;
        case ETIMEDOUT:
            return 0;
    }

    return 1;
}

#define THREADS_RETURNED_ERROR()                                                                                       \
    (nDPId_return.thread_return_value.val != 0 || nDPIsrvd_return.val != 0 ||                                          \
     distributor_return.thread_return_value.val != 0)
int main(int argc, char ** argv)
{
    if (argc != 2)
    {
        usage(argv[0]);
        return 1;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        return 1;
    }

    nDPId_options.max_packets_per_flow_to_send = 3;
#ifdef ENABLE_ZLIB
    /*
     * zLib compression is forced disabled for testing at the moment.
     * That may change in the future.
     */
    nDPId_options.enable_zlib_compression = 1;
#endif
    nDPId_options.memory_profiling_log_interval = (unsigned long long int)-1;
    nDPId_options.reader_thread_count = 1; /* Please do not change this! Generating meaningful pcap diff's relies on a
                                              single reader thread! */
    nDPId_options.instance_alias = strdup("nDPId-test");
    if (access(argv[1], R_OK) != 0)
    {
        syslog(0, "%s: pcap file `%s' does not exist or is not readable", argv[0], argv[1]);
        return 1;
    }
    nDPId_options.pcap_file_or_interface = strdup(argv[1]);
    if (validate_options(argv[0]) != 0)
    {
        return 1;
    }

    if (setup_pipe(mock_pipefds) != 0 || setup_pipe(mock_testfds) != 0 || setup_pipe(mock_nullfds) != 0)
    {
        return 1;
    }

    /* We do not have any sockets, any socket operation must fail! */
    json_sockfd = -1;
    serv_sockfd = -1;

    if (setup_remote_descriptors(MAX_REMOTE_DESCRIPTORS) != 0)
    {
        return 1;
    }

    /* Start processing after all threads started and initialized. */
    pthread_mutex_lock(&nDPId_start_mutex);
    pthread_mutex_lock(&nDPIsrvd_start_mutex);
    pthread_mutex_lock(&distributor_start_mutex);

    pthread_t nDPId_thread;
    struct nDPId_return_value nDPId_return = {};
    if (pthread_create(&nDPId_thread, NULL, nDPId_mainloop_thread, &nDPId_return) != 0)
    {
        return 1;
    }

    pthread_t nDPIsrvd_thread;
    struct thread_return_value nDPIsrvd_return = {};
    if (pthread_create(&nDPIsrvd_thread, NULL, nDPIsrvd_mainloop_thread, &nDPIsrvd_return) != 0)
    {
        return 1;
    }

    pthread_t distributor_thread;
    struct distributor_return_value distributor_return = {};
    if (pthread_create(&distributor_thread, NULL, distributor_client_mainloop_thread, &distributor_return) != 0)
    {
        return 1;
    }

    pthread_mutex_unlock(&nDPIsrvd_start_mutex);
    pthread_mutex_unlock(&distributor_start_mutex);
    pthread_mutex_unlock(&nDPId_start_mutex);

    /* Try to gracefully shutdown all threads. */
    while (thread_wait_for_termination(distributor_thread, 1, &distributor_return.thread_return_value) == 0)
    {
        if (THREADS_RETURNED_ERROR() != 0)
        {
            break;
        }
    }

    while (thread_wait_for_termination(nDPId_thread, 1, &nDPId_return.thread_return_value) == 0)
    {
        if (THREADS_RETURNED_ERROR() != 0)
        {
            break;
        }
    }

    while (thread_wait_for_termination(nDPIsrvd_thread, 1, &nDPIsrvd_return) == 0)
    {
        if (THREADS_RETURNED_ERROR() != 0)
        {
            break;
        }
    }

    if (THREADS_RETURNED_ERROR() != 0)
    {
        char const * which_thread = "Unknown";
        if (nDPId_return.thread_return_value.val != 0)
        {
            which_thread = "nDPId";
        }
        else if (nDPIsrvd_return.val != 0)
        {
            which_thread = "nDPIsrvd";
        }
        else if (distributor_return.thread_return_value.val != 0)
        {
            which_thread = "Distributor";
        }

        syslog(0, "%s Thread returned a non zero value", which_thread);
        return 1;
    }

    {
        printf(
            "~~~~~~~~~~~~~~~~~~~~ SUMMARY ~~~~~~~~~~~~~~~~~~~~\n"
            "~~ packets captured/processed: %llu/%llu\n"
            "~~ skipped flows.............: %llu\n"
            "~~ total layer4 data length..: %llu bytes\n"
            "~~ total detected protocols..: %llu\n"
            "~~ total active/idle flows...: %llu/%llu\n"
            "~~ total timeout flows.......: %llu\n"
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
            nDPId_return.packets_captured,
            nDPId_return.packets_processed,
            nDPId_return.total_skipped_flows,
            nDPId_return.total_l4_data_len,
            nDPId_return.detected_flow_protocols,
            nDPId_return.total_active_flows,
            nDPId_return.total_idle_flows,
            distributor_return.stats.total_flow_timeouts);

        printf(
            "~~ total memory allocated....: %llu bytes\n"
            "~~ total memory freed........: %llu bytes\n"
            "~~ total allocations/frees...: %llu/%llu\n"
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
            (unsigned long long int)ndpi_memory_alloc_bytes,
            (unsigned long long int)ndpi_memory_free_bytes,
            (unsigned long long int)ndpi_memory_alloc_count,
            (unsigned long long int)ndpi_memory_free_count);

        printf(
            "~~ json string min len.......: %llu chars\n"
            "~~ json string max len.......: %llu chars\n"
            "~~ json string avg len.......: %llu chars\n",
            distributor_return.stats.json_string_len_min,
            distributor_return.stats.json_string_len_max,
            (unsigned long long int)distributor_return.stats.json_string_len_avg);
    }

    if (ndpi_memory_alloc_bytes != ndpi_memory_free_bytes || ndpi_memory_alloc_count != ndpi_memory_free_count ||
        nDPId_return.total_active_flows != nDPId_return.total_idle_flows)
    {
        syslog(0, "%s: %s", argv[0], "Memory / Flow leak detected.");
        return 1;
    }

    if (nDPId_return.cur_active_flows != 0 || nDPId_return.cur_idle_flows != 0)
    {
        syslog(0, "%s: %s", argv[0], "Active / Idle inconsistency detected.");
        return 1;
    }

    if (nDPId_return.total_skipped_flows != 0)
    {
        syslog(0, "%s: %s", argv[0], "Skipped flow detected, that should not happen.");
        return 1;
    }

    if (nDPId_return.total_events_serialized != distributor_return.stats.total_events_deserialized ||
        nDPId_return.total_events_serialized != distributor_return.stats.total_events_serialized)
    {
        syslog(0,
               "%s: Event count of nDPId and distributor not equal: %llu != %llu",
               argv[0],
               nDPId_return.total_events_serialized,
               distributor_return.stats.total_events_deserialized);
        return 1;
    }

    if (nDPId_return.packets_processed != distributor_return.stats.total_packets_processed)
    {
        syslog(0,
               "%s: Total nDPId and distributor packets processed not equal: %llu != %llu",
               argv[0],
               nDPId_return.packets_processed,
               distributor_return.stats.total_packets_processed);
        return 1;
    }

    if (nDPId_return.total_l4_data_len != distributor_return.stats.total_l4_data_len)
    {
        syslog(0,
               "%s: Total processed layer4 payload length of nDPId and distributor not equal: %llu != %llu",
               argv[0],
               nDPId_return.total_l4_data_len,
               distributor_return.stats.total_l4_data_len);
        return 1;
    }

    if (distributor_return.stats.flow_new_count !=
        distributor_return.stats.flow_end_count + distributor_return.stats.flow_idle_count)
    {
        syslog(0,
               "%s: Amount of flow 'new' events received is not equal to the amount of 'end' plus 'idle': %llu != "
               "%llu + %llu",
               argv[0],
               distributor_return.stats.flow_new_count,
               distributor_return.stats.flow_end_count,
               distributor_return.stats.flow_idle_count);
        return 1;
    }

    if (nDPId_return.total_active_flows !=
        distributor_return.stats.flow_end_count + distributor_return.stats.flow_idle_count)
    {
        syslog(0,
               "%s: Amount of total active flows is not equal to the amount of received 'end' plus 'idle' events: "
               "%llu != %llu + %llu",
               argv[0],
               nDPId_return.total_active_flows,
               distributor_return.stats.flow_end_count,
               distributor_return.stats.flow_idle_count);
        return 1;
    }

    if (nDPId_return.total_idle_flows !=
        distributor_return.stats.flow_idle_count + distributor_return.stats.flow_end_count)
    {
        syslog(0,
               "%s: Amount of total idle flows is not equal to the amount of received 'idle' events: %llu != %llu",
               argv[0],
               nDPId_return.total_idle_flows,
               distributor_return.stats.flow_idle_count);
        return 1;
    }

    if (nDPId_return.not_detected_flow_protocols != distributor_return.stats.flow_not_detected_count)
    {
        syslog(0,
               "%s: Amount of total undetected flows is not equal to the amount of received 'not-detected' events: "
               "%llu != %llu",
               argv[0],
               nDPId_return.not_detected_flow_protocols,
               distributor_return.stats.flow_not_detected_count);
        return 1;
    }

    if (nDPId_return.guessed_flow_protocols != distributor_return.stats.flow_guessed_count)
    {
        syslog(0,
               "%s: Amount of total guessed flows is not equal to the amount of received 'guessed' events: %llu != "
               "%llu",
               argv[0],
               nDPId_return.guessed_flow_protocols,
               distributor_return.stats.flow_guessed_count);
        return 1;
    }

    if (nDPId_return.detected_flow_protocols != distributor_return.stats.flow_detected_count)
    {
        syslog(0,
               "%s: Amount of total detected flows not equal to the amount of received 'detected' events: %llu != "
               "%llu",
               argv[0],
               nDPId_return.detected_flow_protocols,
               distributor_return.stats.flow_detected_count);
        return 1;
    }

    if (nDPId_return.flow_detection_updates != distributor_return.stats.flow_detection_update_count)
    {
        syslog(0,
               "%s: Amount of total detection updates is not equal to the amount of received 'detection-update' "
               "events: %llu != %llu",
               argv[0],
               nDPId_return.flow_detection_updates,
               distributor_return.stats.flow_detection_update_count);
        return 1;
    }

    if (nDPId_return.flow_updates != distributor_return.stats.flow_update_count)
    {
        syslog(0,
               "%s: Amount of total flow updates is not equal to the amount of received 'update' events: %llu != "
               "%llu",
               argv[0],
               nDPId_return.flow_updates,
               distributor_return.stats.flow_update_count);
        return 1;
    }

    if (nDPId_return.total_active_flows > distributor_return.stats.flow_detected_count +
                                              distributor_return.stats.flow_guessed_count +
                                              distributor_return.stats.flow_not_detected_count)
    {
        syslog(0,
               "%s: Amount of total active flows not equal to the amount of received 'detected', 'guessed and "
               "'not-detected' events: %llu != "
               "%llu + %llu + %llu",
               argv[0],
               nDPId_return.total_active_flows,
               distributor_return.stats.flow_detected_count,
               distributor_return.stats.flow_guessed_count,
               distributor_return.stats.flow_not_detected_count);
        return 1;
    }

#ifdef ENABLE_ZLIB
    if (zlib_compressions != zlib_decompressions)
    {
        syslog(0,
               "%s: %s (%llu != %llu)",
               argv[0],
               "ZLib compression / decompression inconsistency detected.",
               zlib_compressions,
               zlib_decompressions);
        return 1;
    }
#endif

    return 0;
}
