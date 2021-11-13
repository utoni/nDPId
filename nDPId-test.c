#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>

/*
 * Mock some syslog variables and functions.
 * This way, we do not spam any syslog daemon on the host.
 */
#define LOG_DAEMON 0x1
#define LOG_ERR    0x2
#define LOG_CONS   0x4
#define LOG_PERROR 0x8

static void openlog(const char *ident, int option, int facility);
static void syslog(int p, const char * format, ...);
static void closelog(void);

#define NO_MAIN 1
#include "nDPIsrvd.c"
#include "nDPId.c"

enum
{
    PIPE_nDPId = 1,    /* nDPId mock pipefd array index */
    PIPE_nDPIsrvd = 0, /* nDPIsrvd mock pipefd array index */
    PIPE_WRITE = 1,
    PIPE_READ = 0,
    PIPE_COUNT = 2
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
    unsigned long long int detected_flow_protocols;
    unsigned long long int total_active_flows;
    unsigned long long int total_idle_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int cur_idle_flows;
};

struct distributor_return_value
{
    struct thread_return_value thread_return_value;

    unsigned long long int json_string_len_min;
    unsigned long long int json_string_len_max;
    double json_string_len_avg;
};

static int mock_pipefds[PIPE_COUNT] = {};
static int mock_servfds[PIPE_COUNT] = {};
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MAX_REMOTE_DESCRIPTORS 2

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

static void openlog(const char *ident, int option, int facility)
{
    (void)ident;
    (void)option;
    (void)facility;
}

static void syslog(int p, const char * format, ...)
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

static int setup_pipe(int pipefd[PIPE_COUNT])
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
    struct remote_desc * mock_serv_desc = NULL;
    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);

    if (epollfd < 0)
    {
        THREAD_ERROR_GOTO(arg);
    }

    mock_json_desc = get_unused_remote_descriptor(JSON_SOCK, mock_pipefds[PIPE_nDPIsrvd], NETWORK_BUFFER_MAX_SIZE);
    if (mock_json_desc == NULL)
    {
        THREAD_ERROR_GOTO(arg);
    }

    mock_serv_desc = get_unused_remote_descriptor(SERV_SOCK, mock_servfds[PIPE_WRITE], NETWORK_BUFFER_MAX_SIZE / 4);
    if (mock_serv_desc == NULL)
    {
        THREAD_ERROR_GOTO(arg);
    }
    strncpy(mock_serv_desc->event_serv.peer_addr, "0.0.0.0", sizeof(mock_serv_desc->event_serv.peer_addr));
    mock_serv_desc->event_serv.peer.sin_port = 0;

    if (add_in_event(epollfd, mock_pipefds[PIPE_nDPIsrvd], mock_json_desc) != 0)
    {
        THREAD_ERROR_GOTO(arg);
    }

    if (add_in_event(epollfd, mock_servfds[PIPE_WRITE], mock_serv_desc) != 0)
    {
        THREAD_ERROR_GOTO(arg);
    }

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
                THREAD_ERROR_GOTO(arg);
            }
        }
    }

error:
    drain_cache_blocking(mock_serv_desc);

    del_event(epollfd, mock_pipefds[PIPE_nDPIsrvd]);
    del_event(epollfd, mock_servfds[PIPE_WRITE]);
    close(mock_pipefds[PIPE_nDPIsrvd]);
    close(mock_servfds[PIPE_WRITE]);
    close(epollfd);

    return NULL;
}

static enum nDPIsrvd_parse_return parse_json_lines(struct nDPIsrvd_buffer * const buffer,
                                                   struct distributor_return_value * const drv)
{
    struct nDPIsrvd_jsmn jsmn = {};
    size_t const n = (buffer->used > buffer->max ? buffer->max : buffer->used);

    if (n > NETWORK_BUFFER_MAX_SIZE)
    {
        return PARSE_STRING_TOO_BIG;
    }

    enum nDPIsrvd_parse_return ret;
    while ((ret = nDPIsrvd_parse_line(buffer, &jsmn)) == PARSE_OK)
    {
        if (jsmn.tokens_found == 0)
        {
            return PARSE_JSMN_ERROR;
        }

        if (buffer->json_string_length < drv->json_string_len_min)
        {
            drv->json_string_len_min = buffer->json_string_length;
        }
        if (buffer->json_string_length > drv->json_string_len_max)
        {
            drv->json_string_len_max = buffer->json_string_length;
        }
        drv->json_string_len_avg =
            (drv->json_string_len_avg + (drv->json_string_len_max + drv->json_string_len_min) / 2) / 2;

        nDPIsrvd_drain_buffer(buffer);
    }

    return ret;
}

static void * distributor_client_mainloop_thread(void * const arg)
{
    struct nDPIsrvd_buffer client_buffer = {};
    int dis_epollfd = create_evq();
    int signalfd = setup_signalfd(dis_epollfd);
    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);
    struct distributor_return_value * const drv = (struct distributor_return_value *)arg;
    struct thread_return_value * const trv = &drv->thread_return_value;

    if (nDPIsrvd_buffer_init(&client_buffer, NETWORK_BUFFER_MAX_SIZE) != 0 || dis_epollfd < 0 || signalfd < 0)
    {
        THREAD_ERROR_GOTO(trv);
    }
    if (add_in_event(dis_epollfd, mock_servfds[PIPE_READ], NULL) != 0)
    {
        THREAD_ERROR_GOTO(trv);
    }

    drv->json_string_len_min = (unsigned long long int)-1;
    drv->json_string_len_max = 0;
    drv->json_string_len_avg = 0.;

    while (1)
    {
        int nready = epoll_wait(dis_epollfd, events, events_size, -1);

        for (int i = 0; i < nready; i++)
        {
            if ((events[i].events & EPOLLIN) == 0 && (events[i].events & EPOLLHUP) == 0)
            {
                THREAD_ERROR_GOTO(trv);
            }

            if (events[i].data.fd == mock_servfds[PIPE_READ])
            {
                ssize_t bytes_read = read(mock_servfds[PIPE_READ],
                                          client_buffer.ptr.raw + client_buffer.used,
                                          client_buffer.max - client_buffer.used);
                if (bytes_read == 0)
                {
                    goto error;
                }
                else if (bytes_read < 0)
                {
                    THREAD_ERROR_GOTO(trv);
                }
                printf("%.*s", (int)bytes_read, client_buffer.ptr.text + client_buffer.used);
                client_buffer.used += bytes_read;

                enum nDPIsrvd_parse_return parse_ret = parse_json_lines(&client_buffer, drv);
                if (parse_ret != PARSE_NEED_MORE_DATA)
                {
                    fprintf(stderr, "JSON parsing failed: %s\n", nDPIsrvd_enum_to_string(parse_ret));
                    THREAD_ERROR(trv);
                }
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
                    fprintf(stderr, "Got signal %d, abort.\n", fdsi.ssi_signo);
                    THREAD_ERROR(trv);
                }
            }
            else
            {
                THREAD_ERROR(trv);
            }
        }
    }

error:
    del_event(dis_epollfd, signalfd);
    del_event(dis_epollfd, mock_servfds[PIPE_READ]);
    close(dis_epollfd);
    close(signalfd);
    nDPIsrvd_buffer_free(&client_buffer);

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
        nrv->packets_captured = reader_threads[i].workflow->packets_captured;
        nrv->packets_processed = reader_threads[i].workflow->packets_processed;
        nrv->total_skipped_flows = reader_threads[i].workflow->total_skipped_flows;
        nrv->total_l4_data_len = reader_threads[i].workflow->total_l4_data_len;
        nrv->detected_flow_protocols = reader_threads[i].workflow->detected_flow_protocols;
        nrv->total_active_flows = reader_threads[i].workflow->total_active_flows;
        nrv->total_idle_flows = reader_threads[i].workflow->total_idle_flows;
        nrv->cur_active_flows = reader_threads[i].workflow->cur_active_flows;
        nrv->cur_idle_flows = reader_threads[i].workflow->cur_idle_flows;
    }

error:
    free_reader_threads();
    close(mock_pipefds[PIPE_nDPId]);

    return NULL;
}

static void usage(char const * const arg0)
{
    fprintf(stderr,
            "usage: %s [path-to-pcap-file]\n"
            "\tinfluencial environment variable:\n"
            "\t\tPRINT_SUMMARY - if set, print a summary after processing finished\n",
            arg0);
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

#ifdef ENABLE_ZLIB
    /*
     * zLib compression is forced disabled for testing at the moment.
     * That may change in the future.
     */
    nDPId_options.enable_zlib_compression = 1;
#endif
    nDPId_options.memory_profiling_print_every = (unsigned long long int)-1;
    nDPId_options.reader_thread_count = 1; /* Please do not change this! Generating meaningful pcap diff's relies on a
                                              single reader thread! */
    nDPId_options.instance_alias = strdup("nDPId-test");
    if (access(argv[1], R_OK) != 0)
    {
        fprintf(stderr, "%s: pcap file `%s' does not exist or is not readable\n", argv[0], argv[1]);
        return 1;
    }
    nDPId_options.pcap_file_or_interface = strdup(argv[1]);
    if (validate_options(argv[0]) != 0)
    {
        return 1;
    }

    if (setup_pipe(mock_pipefds) != 0 || setup_pipe(mock_servfds) != 0)
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

    if (getenv("PRINT_SUMMARY") != NULL)
    {
        printf(
            "~~~~~~~~~~~~~~~~~~~~ SUMMARY ~~~~~~~~~~~~~~~~~~~~\n"
            "~~ packets captured/processed: %llu/%llu\n"
            "~~ skipped flows.............: %llu\n"
            "~~ total layer4 data length..: %llu bytes\n"
            "~~ total detected protocols..: %llu\n"
            "~~ total active/idle flows...: %llu/%llu\n"
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
            nDPId_return.packets_captured,
            nDPId_return.packets_processed,
            nDPId_return.total_skipped_flows,
            nDPId_return.total_l4_data_len,
            nDPId_return.detected_flow_protocols,
            nDPId_return.total_active_flows,
            nDPId_return.total_idle_flows);

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
            distributor_return.json_string_len_min,
            distributor_return.json_string_len_max,
            (unsigned long long int)distributor_return.json_string_len_avg);
    }

    if (ndpi_memory_alloc_bytes != ndpi_memory_free_bytes || ndpi_memory_alloc_count != ndpi_memory_free_count ||
        nDPId_return.total_active_flows != nDPId_return.total_idle_flows)
    {
        fprintf(stderr, "%s: %s\n", argv[0], "Memory / Flow leak detected.");
        return 1;
    }

    if (nDPId_return.cur_active_flows != 0 || nDPId_return.cur_idle_flows != 0)
    {
        fprintf(stderr, "%s: %s\n", argv[0], "Active / Idle inconsistency detected.");
        return 1;
    }

    if (nDPId_return.total_skipped_flows != 0)
    {
        fprintf(stderr, "%s: %s\n", argv[0], "Skipped flow detected, that should not happen.");
        return 1;
    }

#ifdef ENABLE_ZLIB
    if (zlib_compressions != zlib_decompressions)
    {
        fprintf(stderr,
                "%s: %s (%llu != %llu)\n",
                argv[0],
                "ZLib compression / decompression inconsistency detected.",
                zlib_compressions,
                zlib_decompressions);
        return 1;
    }
#endif

    return THREADS_RETURNED_ERROR();
}
