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

static int epollfd = -1;
static int mock_pipefds[PIPE_COUNT] = {};
static int mock_servfds[PIPE_COUNT] = {};
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

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
    struct remote_desc * mock_json_desc = NULL;
    struct remote_desc * mock_serv_desc = NULL;

    mock_json_desc = get_unused_remote_descriptor(JSON_SOCK, mock_pipefds[PIPE_nDPIsrvd]);
    if (mock_json_desc == NULL)
    {
        goto error;
    }

    mock_serv_desc = get_unused_remote_descriptor(SERV_SOCK, mock_servfds[PIPE_WRITE]);
    if (mock_serv_desc == NULL)
    {
        goto error;
    }
    strncpy(mock_serv_desc->event_serv.peer_addr, "0.0.0.0", sizeof(mock_serv_desc->event_serv.peer_addr));
    mock_serv_desc->event_serv.peer.sin_port = 0;

    if (add_event(epollfd, mock_pipefds[PIPE_nDPIsrvd], mock_json_desc) != 0)
    {
        goto error;
    }

    if (add_event(epollfd, mock_servfds[PIPE_WRITE], mock_serv_desc) != 0)
    {
        goto error;
    }

    if (mainloop(epollfd) != 0)
    {
        goto error;
    }

    while (handle_incoming_data(epollfd, mock_json_desc) == 0) {}

error:
    close(mock_servfds[PIPE_WRITE]);

    return NULL;
}

static void * distributor_mainloop_thread(void * const arg)
{
    char buf[NETWORK_BUFFER_MAX_SIZE];

    (void)arg;

    int dis_thread_shutdown = 0;
    int dis_epollfd = create_evq();
    int signalfd = setup_signalfd(dis_epollfd);

    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);

    if (dis_epollfd < 0)
    {
        goto error;
    }
    if (add_event(dis_epollfd, mock_servfds[PIPE_READ], NULL) != 0)
    {
        goto error;
    }
    if (signalfd < 0)
    {
        goto error;
    }

    while (dis_thread_shutdown == 0)
    {
        int nready = epoll_wait(dis_epollfd, events, events_size, -1);

        for (int i = 0; i < nready; i++)
        {
            if ((events[i].events & EPOLLERR) != 0)
            {
                dis_thread_shutdown = 1;
                break;
            }
            if ((events[i].events & EPOLLIN) == 0)
            {
                dis_thread_shutdown = 1;
                break;
            }

            if (events[i].data.fd == mock_servfds[PIPE_READ])
            {
                ssize_t bytes_read = read(mock_servfds[PIPE_READ], buf, sizeof(buf));
                if (bytes_read <= 0)
                {
                    dis_thread_shutdown = 1;
                    break;
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
                    dis_thread_shutdown = 1;
                    break;
                }

                if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGQUIT)
                {
                    dis_thread_shutdown = 1;
                    break;
                }
            }
            else
            {
                dis_thread_shutdown = 1;
                break;
            }
        }
    }
    ssize_t bytes_read;
    while ((bytes_read = read(mock_servfds[PIPE_READ], buf, sizeof(buf))) > 0)
    {
        printf("%.*s", (int)bytes_read, buf);
    }

error:
    del_event(dis_epollfd, signalfd);
    del_event(dis_epollfd, mock_servfds[PIPE_READ]);
    close(dis_epollfd);
    close(signalfd);

    return NULL;
}

static void * nDPId_mainloop_thread(void * const arg)
{
    (void)arg;

    if (setup_reader_threads() != 0)
    {
        exit(EXIT_FAILURE);
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
    printf("usage: %s [path-to-pcap-file]\n", arg0);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        usage(argv[0]);
        return -1;
    }

    nDPId_options.reader_thread_count = 1; /* Please do not change this! Generating meaningful pcap diff's relies on a single reader thread! */
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

    if (setup_remote_descriptors(2) != 0)
    {
        return -1;
    }

    epollfd = create_evq();
    if (epollfd < 0)
    {
        return -1;
    }

    pthread_t nDPId_thread;
    if (pthread_create(&nDPId_thread, NULL, nDPId_mainloop_thread, NULL) != 0)
    {
        return -1;
    }

    pthread_t nDPIsrvd_thread;
    if (pthread_create(&nDPIsrvd_thread, NULL, nDPIsrvd_mainloop_thread, NULL) != 0)
    {
        return -1;
    }

    pthread_t distributor_thread;
    if (pthread_create(&distributor_thread, NULL, distributor_mainloop_thread, NULL) != 0)
    {
        return -1;
    }

    if (pthread_join(nDPId_thread, NULL) != 0)
    {
        return -1;
    }

    pthread_kill(nDPIsrvd_thread, SIGINT);

    if (pthread_join(nDPIsrvd_thread, NULL) != 0)
    {
        return -1;
    }

    pthread_kill(distributor_thread, SIGINT);

    if (pthread_join(distributor_thread, NULL) != 0)
    {
        return -1;
    }

    return 0;
}
