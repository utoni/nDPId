#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>

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

void mock_syslog_stderr(int p, const char * format, ...)
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

    mock_json_desc = get_unused_remote_descriptor(JSON_SOCK, mock_pipefds[PIPE_nDPIsrvd]);
    if (mock_json_desc == NULL)
    {
        THREAD_ERROR_GOTO(arg);
    }

    mock_serv_desc = get_unused_remote_descriptor(SERV_SOCK, mock_servfds[PIPE_WRITE]);
    if (mock_serv_desc == NULL)
    {
        THREAD_ERROR_GOTO(arg);
    }
    strncpy(mock_serv_desc->event_serv.peer_addr, "0.0.0.0", sizeof(mock_serv_desc->event_serv.peer_addr));
    mock_serv_desc->event_serv.peer.sin_port = 0;

    if (add_event(epollfd, mock_pipefds[PIPE_nDPIsrvd], mock_json_desc) != 0)
    {
        THREAD_ERROR_GOTO(arg);
    }

    if (add_event(epollfd, mock_servfds[PIPE_WRITE], mock_serv_desc) != 0)
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
                if (handle_incoming_data_event(epollfd, &events[i]) != 0)
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
    del_event(epollfd, mock_pipefds[PIPE_nDPIsrvd]);
    del_event(epollfd, mock_servfds[PIPE_WRITE]);
    close(mock_pipefds[PIPE_nDPIsrvd]);
    close(mock_servfds[PIPE_WRITE]);
    close(epollfd);

    return NULL;
}

static enum nDPIsrvd_parse_return parse_json_lines(struct io_buffer * const buffer)
{
    struct nDPIsrvd_buffer buf = {};
    struct nDPIsrvd_jsmn jsmn = {};
    size_t const n = (buffer->used > sizeof(buf.raw) ? sizeof(buf.raw) : buffer->used);

    if (n > NETWORK_BUFFER_MAX_SIZE)
    {
        return PARSE_STRING_TOO_BIG;
    }

    memcpy(buf.raw, buffer->ptr, n);
    buf.used = buffer->used;

    enum nDPIsrvd_parse_return ret;
    while ((ret = nDPIsrvd_parse_line(&buf, &jsmn)) == PARSE_OK)
    {
        if (jsmn.tokens_found == 0)
        {
            return PARSE_JSMN_ERROR;
        }
        nDPIsrvd_drain_buffer(&buf);
    }

    memcpy(buffer->ptr, buf.raw, buf.used);
    buffer->used = buf.used;

    return ret;
}

static void * distributor_client_mainloop_thread(void * const arg)
{
    struct io_buffer client_buffer = {.ptr = (uint8_t *)malloc(NETWORK_BUFFER_MAX_SIZE),
                                      .max = NETWORK_BUFFER_MAX_SIZE,
                                      .used = 0};
    int dis_epollfd = create_evq();
    int signalfd = setup_signalfd(dis_epollfd);
    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);

    if (client_buffer.ptr == NULL || dis_epollfd < 0 || signalfd < 0)
    {
        THREAD_ERROR_GOTO(arg);
    }
    if (add_event(dis_epollfd, mock_servfds[PIPE_READ], NULL) != 0)
    {
        THREAD_ERROR_GOTO(arg);
    }

    while (1)
    {
        int nready = epoll_wait(dis_epollfd, events, events_size, -1);

        for (int i = 0; i < nready; i++)
        {
            if ((events[i].events & EPOLLIN) == 0 && (events[i].events & EPOLLHUP) == 0)
            {
                THREAD_ERROR_GOTO(arg);
            }

            if (events[i].data.fd == mock_servfds[PIPE_READ])
            {
                ssize_t bytes_read = read(mock_servfds[PIPE_READ],
                                          client_buffer.ptr + client_buffer.used,
                                          client_buffer.max - client_buffer.used);
                if (bytes_read == 0)
                {
                    goto error;
                }
                else if (bytes_read < 0)
                {
                    THREAD_ERROR_GOTO(arg);
                }
                printf("%.*s", (int)bytes_read, client_buffer.ptr + client_buffer.used);
                client_buffer.used += bytes_read;

                enum nDPIsrvd_parse_return parse_ret = parse_json_lines(&client_buffer);
                if (parse_ret != PARSE_NEED_MORE_DATA)
                {
                    fprintf(stderr, "JSON parsing failed: %s\n", nDPIsrvd_enum_to_string(parse_ret));
                    THREAD_ERROR(arg);
                }
            }
            else if (events[i].data.fd == signalfd)
            {
                struct signalfd_siginfo fdsi;
                ssize_t s;

                s = read(signalfd, &fdsi, sizeof(struct signalfd_siginfo));
                if (s != sizeof(struct signalfd_siginfo))
                {
                    THREAD_ERROR(arg);
                }

                if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGQUIT)
                {
                    fprintf(stderr, "Got signal %d, abort.\n", fdsi.ssi_signo);
                    THREAD_ERROR(arg);
                }
            }
            else
            {
                THREAD_ERROR(arg);
            }
        }
    }

error:
    del_event(dis_epollfd, signalfd);
    del_event(dis_epollfd, mock_servfds[PIPE_READ]);
    close(dis_epollfd);
    close(signalfd);
    free(client_buffer.ptr);

    return NULL;
}

static void * nDPId_mainloop_thread(void * const arg)
{
    if (setup_reader_threads() != 0)
    {
        THREAD_ERROR(arg);
        return NULL;
    }

    /* Replace nDPId JSON socket fd with the one in our pipe and hope that no socket specific code-path triggered. */
    reader_threads[0].json_sockfd = mock_pipefds[PIPE_nDPId];
    reader_threads[0].json_sock_reconnect = 0;

    run_pcap_loop(&reader_threads[0]);
    free_reader_threads();

    close(mock_pipefds[PIPE_nDPId]);

    return NULL;
}

static void usage(char const * const arg0)
{
    fprintf(stderr, "usage: %s [path-to-pcap-file]\n", arg0);
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

#define THREADS_RETURNED_ERROR() (nDPId_return.val != 0 || nDPIsrvd_return.val != 0 || distributor_return.val != 0)
int main(int argc, char ** argv)
{
    if (argc != 2)
    {
        usage(argv[0]);
        return -1;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        return -1;
    }

    nDPId_options.reader_thread_count = 1; /* Please do not change this! Generating meaningful pcap diff's relies on a
                                              single reader thread! */
    nDPId_options.instance_alias = strdup("nDPId-test");
    nDPId_options.pcap_file_or_interface = strdup(argv[1]);
    if (validate_options(argv[0]) != 0)
    {
        return -1;
    }

    if (setup_pipe(mock_pipefds) != 0 || setup_pipe(mock_servfds) != 0)
    {
        return -1;
    }

    /* We do not have any sockets, any socket operation must fail! */
    json_sockfd = -1;
    serv_sockfd = -1;

    if (setup_remote_descriptors(MAX_REMOTE_DESCRIPTORS) != 0)
    {
        return -1;
    }

    pthread_t nDPId_thread;
    struct thread_return_value nDPId_return = {};
    if (pthread_create(&nDPId_thread, NULL, nDPId_mainloop_thread, &nDPId_return) != 0)
    {
        return -1;
    }

    pthread_t nDPIsrvd_thread;
    struct thread_return_value nDPIsrvd_return = {};
    if (pthread_create(&nDPIsrvd_thread, NULL, nDPIsrvd_mainloop_thread, &nDPIsrvd_return) != 0)
    {
        return -1;
    }

    pthread_t distributor_thread;
    struct thread_return_value distributor_return = {};
    if (pthread_create(&distributor_thread, NULL, distributor_client_mainloop_thread, &distributor_return) != 0)
    {
        return -1;
    }

    /* Try to gracefully shutdown all threads. */

    while (thread_wait_for_termination(distributor_thread, 1, &distributor_return) == 0)
    {
        if (THREADS_RETURNED_ERROR() != 0)
        {
            return -1;
        }
    }

    while (thread_wait_for_termination(nDPId_thread, 1, &nDPId_return) == 0)
    {
        if (THREADS_RETURNED_ERROR() != 0)
        {
            return -1;
        }
    }

    while (thread_wait_for_termination(nDPIsrvd_thread, 1, &nDPIsrvd_return) == 0)
    {
        if (THREADS_RETURNED_ERROR() != 0)
        {
            return -1;
        }
    }

    return THREADS_RETURNED_ERROR();
}
