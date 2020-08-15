#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <linux/un.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "utils.h"

enum ev_type
{
    JSON_SOCK,
    SERV_SOCK
};

struct io_buffer
{
    uint8_t * ptr;
    size_t used;
    size_t max;
};

struct remote_desc
{
    enum ev_type type;
    int fd;
    struct io_buffer buf;
    union {
        struct
        {
            int json_sockfd;
            struct sockaddr_un peer;
            unsigned long long int json_bytes;
        } event_json;
        struct
        {
            int serv_sockfd;
            struct sockaddr_in peer;
            char peer_addr[INET_ADDRSTRLEN];
        } event_serv;
    };
};

static struct remotes
{
    struct remote_desc * desc;
    size_t desc_size;
    size_t desc_used;
} remotes = {NULL, 0, 0};

static int main_thread_shutdown = 0;
static int log_to_stderr = 0;
static char pidfile[UNIX_PATH_MAX] = nDPIsrvd_PIDFILE;
static char json_sockpath[UNIX_PATH_MAX] = COLLECTOR_UNIX_SOCKET;
static char serv_listen_addr[INET_ADDRSTRLEN] = DISTRIBUTOR_HOST;
static uint16_t serv_listen_port = DISTRIBUTOR_PORT;
static int json_sockfd;
static int serv_sockfd;

static int create_listen_sockets(void)
{
    json_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    serv_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (json_sockfd < 0 || serv_sockfd < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error opening socket: %s", strerror(errno));
        return 1;
    }

    int opt = 1;
    if (setsockopt(json_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0 ||
        setsockopt(serv_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "setsockopt with SO_REUSEADDR failed: %s", strerror(errno));
        return 1;
    }

    struct sockaddr_un json_addr;
    json_addr.sun_family = AF_UNIX;
    if (snprintf(json_addr.sun_path, sizeof(json_addr.sun_path), "%s", json_sockpath) <= 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "snprintf failed: %s", strerror(errno));
        return 1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, &serv_listen_addr[0], &serv_addr.sin_addr) != 1)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error converting an internet address: %s", strerror(errno));
        return 1;
    }
    serv_addr.sin_port = htons(serv_listen_port);

    if (bind(json_sockfd, (struct sockaddr *)&json_addr, sizeof(json_addr)) < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error on binding a JSON socket: %s", strerror(errno));
        return 1;
    }

    if (bind(serv_sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error on binding the INET socket: %s", strerror(errno));
        return 1;
    }

    if (listen(json_sockfd, 16) < 0 || listen(serv_sockfd, 16) < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error on listen: %s", strerror(errno));
        return 1;
    }

    int json_flags = fcntl(json_sockfd, F_GETFL, 0);
    int serv_flags = fcntl(serv_sockfd, F_GETFL, 0);
    if (json_flags == -1 || serv_flags == -1)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error getting fd flags: %s", strerror(errno));
        return 1;
    }
    if (fcntl(json_sockfd, F_SETFL, json_flags | O_NONBLOCK) == -1 ||
        fcntl(serv_sockfd, F_SETFL, serv_flags | O_NONBLOCK) == -1)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error setting fd flags: %s", strerror(errno));
        return 1;
    }

    return 0;
}

static struct remote_desc * get_unused_remote_descriptor(void)
{
    if (remotes.desc_used == remotes.desc_size)
    {
        return NULL;
    }

    for (size_t i = 0; i < remotes.desc_size; ++i)
    {
        if (remotes.desc[i].fd == -1)
        {
            remotes.desc_used++;
            remotes.desc[i].buf.ptr = (uint8_t *)malloc(NETWORK_BUFFER_MAX_SIZE);
            remotes.desc[i].buf.max = NETWORK_BUFFER_MAX_SIZE;
            remotes.desc[i].buf.used = 0;
            return &remotes.desc[i];
        }
    }

    return NULL;
}

static void disconnect_client(int epollfd, struct remote_desc * const current)
{
    if (current->fd > -1)
    {
        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, current->fd, NULL) < 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Error deleting fd %d from epollq %d: %s",
                   current->fd, epollfd, strerror(errno));
        }
        if (close(current->fd) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Error closing fd: %s", strerror(errno));
        }
    }
    free(current->buf.ptr);
    current->buf.ptr = NULL;
    current->fd = -1;
    remotes.desc_used--;
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

    while ((opt = getopt(argc, argv, "hlc:dp:")) != -1)
    {
        switch (opt)
        {
            case 'l':
                log_to_stderr = 1;
                break;
            case 'c':
                strncpy(json_sockpath, optarg, sizeof(json_sockpath) - 1);
                json_sockpath[sizeof(json_sockpath) - 1] = '\0';
                break;
            case 'd':
                daemonize_enable();
                break;
            case 'p':
                strncpy(pidfile, optarg, sizeof(pidfile) - 1);
                pidfile[sizeof(pidfile) - 1] = '\0';
                break;
            default:
                fprintf(stderr, "Usage: %s [-l] [-c path-to-unix-sock] [-d] [-p pidfile]\n", argv[0]);
                return 1;
        }
    }

    return 0;
}

int main(int argc, char ** argv)
{
    if (argc == 0)
    {
        return 1;
    }

    if (parse_options(argc, argv) != 0)
    {
        return 1;
    }

    openlog("nDPIsrvd", LOG_CONS | LOG_PERROR, LOG_DAEMON);

    if (access(json_sockpath, F_OK) == 0)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "UNIX socket %s exists; nDPIsrvd already running? "
               "Please remove the socket manually or change socket path.",
               json_sockpath);
        return 1;
    }

    if (daemonize_with_pidfile(pidfile) != 0)
    {
        return 1;
    }
    closelog();
    openlog("nDPIsrvd", LOG_CONS | (log_to_stderr != 0 ? LOG_PERROR : 0), LOG_DAEMON);

    remotes.desc_used = 0;
    remotes.desc_size = 32;
    remotes.desc = (struct remote_desc *)malloc(remotes.desc_size * sizeof(*remotes.desc));
    if (remotes.desc == NULL)
    {
        return 1;
    }
    for (size_t i = 0; i < remotes.desc_size; ++i)
    {
        remotes.desc[i].fd = -1;
        remotes.desc[i].buf.ptr = NULL;
        remotes.desc[i].buf.max = 0;
    }

    if (create_listen_sockets() != 0)
    {
        return 1;
    }
    syslog(LOG_DAEMON, "collector listen on %s", json_sockpath);
    syslog(
        LOG_DAEMON, "distributor listen on %.*s:%u", (int)sizeof(serv_listen_addr), serv_listen_addr, serv_listen_port);

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    int epollfd = epoll_create1(0);
    if (epollfd < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error creating epoll: %s", strerror(errno));
        return 1;
    }

    struct epoll_event accept_event = {};
    accept_event.data.fd = json_sockfd;
    accept_event.events = EPOLLIN;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, json_sockfd, &accept_event) < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error adding JSON fd to epoll: %s", strerror(errno));
        return 1;
    }
    accept_event.data.fd = serv_sockfd;
    accept_event.events = EPOLLIN;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, serv_sockfd, &accept_event) < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error adding INET fd to epoll: %s", strerror(errno));
        return 1;
    }

    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);
    while (main_thread_shutdown == 0)
    {
        struct remote_desc * current = NULL;
        int nready = epoll_wait(epollfd, events, events_size, -1);

        for (int i = 0; i < nready; i++)
        {
            if (events[i].events & EPOLLERR)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "Epoll event error: %s",
                       (errno != 0 ? strerror(errno) : "Client disconnected"));
                if (events[i].data.fd != json_sockfd && events[i].data.fd != serv_sockfd)
                {
                    current = (struct remote_desc *)events[i].data.ptr;
                    disconnect_client(epollfd, current);
                }
                continue;
            }

            /* New connection to collector / distributor. */
            if (events[i].data.fd == json_sockfd || events[i].data.fd == serv_sockfd)
            {
                current = get_unused_remote_descriptor();
                if (current == NULL)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Max number of connections reached: %zu", remotes.desc_used);
                    continue;
                }
                current->type = (events[i].data.fd == json_sockfd ? JSON_SOCK : SERV_SOCK);

                int sockfd = (current->type == JSON_SOCK ? json_sockfd : serv_sockfd);
                socklen_t peer_addr_len =
                    (current->type == JSON_SOCK ? sizeof(current->event_json.peer) : sizeof(current->event_serv.peer));

                current->fd = accept(sockfd,
                                     (current->type == JSON_SOCK ? (struct sockaddr *)&current->event_json.peer
                                                                 : (struct sockaddr *)&current->event_serv.peer),
                                     &peer_addr_len);
                if (current->fd < 0)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Accept failed: %s", strerror(errno));
                    disconnect_client(epollfd, current);
                    continue;
                }

                switch (current->type)
                {
                    case JSON_SOCK:
                        current->event_json.json_bytes = 0;
                        syslog(LOG_DAEMON, "New collector connection");
                        break;
                    case SERV_SOCK:
                        if (inet_ntop(current->event_serv.peer.sin_family,
                                      &current->event_serv.peer.sin_addr,
                                      &current->event_serv.peer_addr[0],
                                      sizeof(current->event_serv.peer_addr)) == NULL)
                        {
                            syslog(LOG_DAEMON | LOG_ERR, "Error converting an internet address: %s", strerror(errno));
                            current->event_serv.peer_addr[0] = '\0';
                        }
                        syslog(LOG_DAEMON,
                               "New distributor connection from %.*s:%u",
                               (int)sizeof(current->event_serv.peer_addr),
                               current->event_serv.peer_addr,
                               ntohs(current->event_serv.peer.sin_port));
                        break;
                }

                /* nonblocking fd is mandatory */
                int fd_flags = fcntl(current->fd, F_GETFL, 0);
                if (fd_flags == -1 || fcntl(current->fd, F_SETFL, fd_flags | O_NONBLOCK) == -1)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Error setting fd flags: %s", strerror(errno));
                    disconnect_client(epollfd, current);
                    continue;
                }

                /* shutdown writing end for collector clients */
                if (current->type == JSON_SOCK)
                {
                    shutdown(current->fd, SHUT_WR); // collector
                    /* setup epoll event */
                    struct epoll_event accept_event = {};
                    accept_event.data.ptr = current;
                    accept_event.events = EPOLLIN;
                    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, current->fd, &accept_event) < 0)
                    {
                        disconnect_client(epollfd, current);
                        continue;
                    }
                }
                else
                {
                    shutdown(current->fd, SHUT_RD); // distributor
                }
            }
            else
            {
                current = (struct remote_desc *)events[i].data.ptr;

                if (current->fd < 0)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "file descriptor `%d' got from event data invalid", current->fd);
                    continue;
                }

                if (events[i].events & EPOLLHUP)
                {
                    syslog(LOG_DAEMON,
                           "%s connection closed",
                           (current->type == JSON_SOCK ? "collector" : "distributor"));
                    disconnect_client(epollfd, current);
                    continue;
                }

                if (events[i].events & EPOLLIN && current->type == JSON_SOCK)
                {
                    /* read JSON strings (or parts) from the UNIX socket (collecting) */
                    if (current->buf.used == current->buf.max)
                    {
                        syslog(LOG_DAEMON, "Collector read buffer full. No more read possible.");
                        disconnect_client(epollfd, current);
                        continue;
                    }

                    errno = 0;
                    ssize_t bytes_read =
                        read(current->fd, current->buf.ptr + current->buf.used, current->buf.max - current->buf.used);
                    if (errno == EAGAIN)
                    {
                        continue;
                    }
                    if (bytes_read < 0 || errno != 0)
                    {
                        disconnect_client(epollfd, current);
                        continue;
                    }
                    if (bytes_read == 0)
                    {
                        syslog(LOG_DAEMON, "collector connection closed during read");
                        disconnect_client(epollfd, current);
                        continue;
                    }
                    current->buf.used += bytes_read;

                    while (current->buf.used >= nDPIsrvd_JSON_BYTES + 1)
                    {
                        if (current->buf.ptr[nDPIsrvd_JSON_BYTES] != '{')
                        {
                            syslog(LOG_DAEMON | LOG_ERR,
                                   "BUG: JSON invalid opening character: '%c'",
                                   current->buf.ptr[nDPIsrvd_JSON_BYTES]);
                            disconnect_client(epollfd, current);
                            break;
                        }

                        errno = 0;
                        char * json_str_start = NULL;
                        current->event_json.json_bytes = strtoull((char *)current->buf.ptr, &json_str_start, 10);
                        current->event_json.json_bytes += (uint8_t *)json_str_start - current->buf.ptr;

                        if (errno == ERANGE)
                        {
                            syslog(LOG_DAEMON | LOG_ERR, "BUG: Size of JSON exceeds limit");
                            disconnect_client(epollfd, current);
                            break;
                        }
                        if ((uint8_t *)json_str_start == current->buf.ptr)
                        {
                            syslog(LOG_DAEMON | LOG_ERR,
                                   "BUG: Missing size before JSON string: \"%.*s\"",
                                   nDPIsrvd_JSON_BYTES,
                                   current->buf.ptr);
                            disconnect_client(epollfd, current);
                            break;
                        }
                        if (current->event_json.json_bytes > current->buf.max)
                        {
                            syslog(LOG_DAEMON | LOG_ERR,
                                   "BUG: JSON string too big: %llu > %zu",
                                   current->event_json.json_bytes,
                                   current->buf.max);
                            disconnect_client(epollfd, current);
                            break;
                        }
                        if (current->event_json.json_bytes > current->buf.used)
                        {
                            break;
                        }

                        if (current->buf.ptr[current->event_json.json_bytes - 1] != '}')
                        {
                            syslog(LOG_DAEMON | LOG_ERR,
                                   "BUG: Invalid JSON string: %.*s",
                                   (int)current->event_json.json_bytes,
                                   current->buf.ptr);
                            disconnect_client(epollfd, current);
                            break;
                        }

                        for (size_t i = 0; i < remotes.desc_size; ++i)
                        {
                            if (remotes.desc[i].fd < 0)
                            {
                                continue;
                            }
                            if (remotes.desc[i].type != SERV_SOCK)
                            {
                                continue;
                            }
                            if (current->event_json.json_bytes > remotes.desc[i].buf.max - remotes.desc[i].buf.used)
                            {
                                continue;
                            }

                            memcpy(remotes.desc[i].buf.ptr + remotes.desc[i].buf.used,
                                   current->buf.ptr,
                                   current->event_json.json_bytes);
                            remotes.desc[i].buf.used += current->event_json.json_bytes;

                            errno = 0;
                            ssize_t bytes_written =
                                write(remotes.desc[i].fd, remotes.desc[i].buf.ptr, remotes.desc[i].buf.used);
                            if (errno == EAGAIN)
                            {
                                continue;
                            }
                            if (bytes_written < 0 || errno != 0)
                            {
                                syslog(LOG_DAEMON | LOG_ERR,
                                       "Distributor connection closed, send failed: %s",
                                       strerror(errno));
                                disconnect_client(epollfd, &remotes.desc[i]);
                                continue;
                            }
                            if (bytes_written == 0)
                            {
                                syslog(LOG_DAEMON, "Distributor connection closed during write");
                                disconnect_client(epollfd, &remotes.desc[i]);
                                continue;
                            }
                            if ((size_t)bytes_written < remotes.desc[i].buf.used)
                            {
                                syslog(LOG_DAEMON,
                                       "Distributor write less than expected: %zd < %zu",
                                       bytes_written,
                                       remotes.desc[i].buf.used);
                                memmove(remotes.desc[i].buf.ptr,
                                        remotes.desc[i].buf.ptr + bytes_written,
                                        remotes.desc[i].buf.used - bytes_written);
                                remotes.desc[i].buf.used -= bytes_written;
                                continue;
                            }

                            remotes.desc[i].buf.used = 0;
                        }

                        memmove(current->buf.ptr,
                                current->buf.ptr + current->event_json.json_bytes,
                                current->buf.used - current->event_json.json_bytes);
                        current->buf.used -= current->event_json.json_bytes;
                        current->event_json.json_bytes = 0;
                    }
                }
            }
        }
    }

    close(json_sockfd);
    close(serv_sockfd);

    daemonize_shutdown(pidfile);
    syslog(LOG_DAEMON | LOG_NOTICE, "Bye.");
    closelog();

    unlink(json_sockpath);

    return 0;
}
