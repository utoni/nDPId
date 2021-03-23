#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "nDPIsrvd.h"
#include "utils.h"

struct io_buffer
{
    uint8_t * ptr;
    size_t used;
    size_t max;
};

enum sock_type
{
    JSON_SOCK,
    SERV_SOCK
};

struct remote_desc
{
    enum sock_type sock_type;
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
static char * pidfile = NULL;
static char * json_sockpath = NULL;
static char * serv_optarg = NULL;
static struct nDPIsrvd_address serv_address = {
    .raw.sa_family = 0xFFFF,
};
static int json_sockfd;
static int serv_sockfd;
static char * user = NULL;
static char * group = NULL;

static int fcntl_add_flags(int fd, int flags)
{
    int cur_flags = fcntl(fd, F_GETFL, 0);

    if (cur_flags == -1)
    {
        return 1;
    }

    return fcntl(fd, F_SETFL, cur_flags | flags);
}

static int fcntl_del_flags(int fd, int flags)
{
    int cur_flags = fcntl(fd, F_GETFL, 0);

    if (cur_flags == -1)
    {
        return 1;
    }

    return fcntl(fd, F_SETFL, cur_flags & ~flags);
}

static int create_listen_sockets(void)
{
    json_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    serv_sockfd = socket(serv_address.raw.sa_family, SOCK_STREAM, 0);
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

    if (bind(json_sockfd, (struct sockaddr *)&json_addr, sizeof(json_addr)) < 0)
    {
        unlink(json_sockpath);
        syslog(LOG_DAEMON | LOG_ERR,
               "Error on binding UNIX socket (collector) to %s: %s",
               json_sockpath,
               strerror(errno));
        return 1;
    }

    if (bind(serv_sockfd, &serv_address.raw, serv_address.size) < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error on binding socket (distributor) to %s: %s", serv_optarg, strerror(errno));
        unlink(json_sockpath);
        return 1;
    }

    if (listen(json_sockfd, 16) < 0 || listen(serv_sockfd, 16) < 0)
    {
        unlink(json_sockpath);
        syslog(LOG_DAEMON | LOG_ERR, "Error on listen: %s", strerror(errno));
        return 1;
    }

    if (fcntl_add_flags(json_sockfd, O_NONBLOCK) != 0)
    {
        unlink(json_sockpath);
        syslog(LOG_DAEMON | LOG_ERR, "Error setting fd flags for the collector socket: %s", strerror(errno));
        return 1;
    }

    if (fcntl_add_flags(serv_sockfd, O_NONBLOCK) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error setting fd flags for the distributor socket: %s", strerror(errno));
        return 1;
    }

    return 0;
}

static struct remote_desc * get_unused_remote_descriptor(enum sock_type type, int remote_fd)
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
            remotes.desc[i].sock_type = type;
            remotes.desc[i].fd = remote_fd;
            return &remotes.desc[i];
        }
    }

    return NULL;
}

static int add_event(int epollfd, int fd, void * ptr)
{
    struct epoll_event event = {};

    if (ptr != NULL)
    {
        event.data.ptr = ptr;
    }
    else
    {
        event.data.fd = fd;
    }
    event.events = EPOLLIN;
    return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
}

static int del_event(int epollfd, int fd)
{
    return epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
}

static void disconnect_client(int epollfd, struct remote_desc * const current)
{
    if (current->fd > -1)
    {
        del_event(epollfd, current->fd);
        if (close(current->fd) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Error closing fd: %s", strerror(errno));
        }
        current->fd = -1;
        remotes.desc_used--;
    }
    free(current->buf.ptr);
    current->buf.ptr = NULL;
}

static int parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "hlc:dp:s:u:g:")) != -1)
    {
        switch (opt)
        {
            case 'l':
                log_to_stderr = 1;
                break;
            case 'c':
                free(json_sockpath);
                json_sockpath = strdup(optarg);
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
            default:
                fprintf(stderr,
                        "Usage: %s [-l] [-c path-to-unix-sock] [-d] [-p pidfile] "
                        "[-s path-to-unix-socket|distributor-host:port] [-u user] [-g group]\n",
                        argv[0]);
                return 1;
        }
    }

    if (pidfile == NULL)
    {
        pidfile = strdup(nDPIsrvd_PIDFILE);
    }

    if (json_sockpath == NULL)
    {
        json_sockpath = strdup(COLLECTOR_UNIX_SOCKET);
    }

    if (serv_optarg == NULL)
    {
        serv_optarg = strdup(DISTRIBUTOR_UNIX_SOCKET);
    }

    if (nDPIsrvd_setup_address(&serv_address, serv_optarg) != 0)
    {
        fprintf(stderr, "%s: Could not parse address `%s'\n", argv[0], serv_optarg);
        return 1;
    }

    if (optind < argc)
    {
        fprintf(stderr, "%s: Unexpected argument after options\n", argv[0]);
        return 1;
    }

    return 0;
}

static int new_connection(int epollfd, int eventfd)
{
    union {
        struct sockaddr_un event_json;
        struct sockaddr_un event_serv;
    } sockaddr;

    socklen_t peer_addr_len;
    enum sock_type stype;
    int server_fd;
    if (eventfd == json_sockfd)
    {
        peer_addr_len = sizeof(sockaddr.event_json);
        stype = JSON_SOCK;
        server_fd = json_sockfd;
    }
    else if (eventfd == serv_sockfd)
    {
        peer_addr_len = sizeof(sockaddr.event_serv);
        stype = SERV_SOCK;
        server_fd = serv_sockfd;
    }
    else
    {
        return 1;
    }

    int client_fd = accept(server_fd, (struct sockaddr *)&sockaddr, &peer_addr_len);
    if (client_fd < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Accept failed: %s", strerror(errno));
        return 1;
    }

    struct remote_desc * current = get_unused_remote_descriptor(stype, client_fd);
    if (current == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Max number of connections reached: %zu", remotes.desc_used);
        return 1;
    }

    char const * sock_type = NULL;
    switch (current->sock_type)
    {
        case JSON_SOCK:
            sock_type = "collector";
            current->event_json.json_bytes = 0;
            syslog(LOG_DAEMON, "New collector connection");
            break;
        case SERV_SOCK:
            sock_type = "distributor";
            if (inet_ntop(current->event_serv.peer.sin_family,
                          &current->event_serv.peer.sin_addr,
                          &current->event_serv.peer_addr[0],
                          sizeof(current->event_serv.peer_addr)) == NULL)
            {
                if (errno == EAFNOSUPPORT)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "New distributor connection.");
                }
                else
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Error converting an internet address: %s", strerror(errno));
                }
                current->event_serv.peer_addr[0] = '\0';
            }
            else
            {
                syslog(LOG_DAEMON,
                       "New distributor connection from %.*s:%u",
                       (int)sizeof(current->event_serv.peer_addr),
                       current->event_serv.peer_addr,
                       ntohs(current->event_serv.peer.sin_port));
            }
            break;
    }

    /* nonblocking fd is mandatory */
    if (fcntl_add_flags(current->fd, O_NONBLOCK) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error setting %s fd flags: %s", sock_type, strerror(errno));
        disconnect_client(epollfd, current);
        return 1;
    }

    /* shutdown writing end for collector clients */
    if (current->sock_type == JSON_SOCK)
    {
        shutdown(current->fd, SHUT_WR); // collector
        /* setup epoll event */
        if (add_event(epollfd, current->fd, current) != 0)
        {
            disconnect_client(epollfd, current);
            return 1;
        }
    }
    else
    {
        shutdown(current->fd, SHUT_RD); // distributor
    }

    return 0;
}

static int handle_collector_protocol(int epollfd, struct remote_desc * const current)
{
    char * json_str_start = NULL;

    if (current->buf.ptr[NETWORK_BUFFER_LENGTH_DIGITS] != '{')
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "BUG: JSON invalid opening character: '%c'",
               current->buf.ptr[NETWORK_BUFFER_LENGTH_DIGITS]);
        disconnect_client(epollfd, current);
        return 1;
    }

    errno = 0;
    current->event_json.json_bytes = strtoull((char *)current->buf.ptr, &json_str_start, 10);
    current->event_json.json_bytes += (uint8_t *)json_str_start - current->buf.ptr;

    if (errno == ERANGE)
    {
        syslog(LOG_DAEMON | LOG_ERR, "BUG: Size of JSON exceeds limit");
        disconnect_client(epollfd, current);
        return 1;
    }

    if ((uint8_t *)json_str_start == current->buf.ptr)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "BUG: Missing size before JSON string: \"%.*s\"",
               NETWORK_BUFFER_LENGTH_DIGITS,
               current->buf.ptr);
        disconnect_client(epollfd, current);
        return 1;
    }

    if (current->event_json.json_bytes > current->buf.max)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "BUG: JSON string too big: %llu > %zu",
               current->event_json.json_bytes,
               current->buf.max);
        disconnect_client(epollfd, current);
        return 1;
    }

    if (current->event_json.json_bytes > current->buf.used)
    {
        return 1;
    }

    if (current->buf.ptr[current->event_json.json_bytes - 2] != '}' ||
        current->buf.ptr[current->event_json.json_bytes - 1] != '\n')
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "BUG: Invalid JSON string: %.*s",
               (int)current->event_json.json_bytes,
               current->buf.ptr);
        disconnect_client(epollfd, current);
        return 1;
    }

    return 0;
}

static int handle_incoming_data(int epollfd, struct remote_desc * const current)
{
    if (current->sock_type != JSON_SOCK)
    {
        return 0;
    }

    /* read JSON strings (or parts) from the UNIX socket (collecting) */
    if (current->buf.used == current->buf.max)
    {
        syslog(LOG_DAEMON, "Collector read buffer full. No more read possible.");
    }
    else
    {
        errno = 0;
        ssize_t bytes_read =
            read(current->fd, current->buf.ptr + current->buf.used, current->buf.max - current->buf.used);
        if (bytes_read < 0 || errno != 0)
        {
            disconnect_client(epollfd, current);
            return 1;
        }
        if (bytes_read == 0)
        {
            syslog(LOG_DAEMON, "Collector connection closed during read");
            disconnect_client(epollfd, current);
            return 1;
        }
        current->buf.used += bytes_read;
    }

    while (current->buf.used >= NETWORK_BUFFER_LENGTH_DIGITS + 1)
    {
        if (handle_collector_protocol(epollfd, current) != 0)
        {
            break;
        }

        for (size_t i = 0; i < remotes.desc_size; ++i)
        {
            if (remotes.desc[i].fd < 0)
            {
                continue;
            }
            if (remotes.desc[i].sock_type != SERV_SOCK)
            {
                continue;
            }
            if (current->event_json.json_bytes > remotes.desc[i].buf.max - remotes.desc[i].buf.used)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "Buffer capacity threshold (%zu of max %zu bytes) reached, "
                       "falling back to blocking mode.",
                       remotes.desc[i].buf.used,
                       remotes.desc[i].buf.max);
                /*
                 * FIXME: Maybe switch to a Multithreading distributor data transmission,
                 *        so that we do not have to switch back to blocking mode here!
                 * NOTE: If *one* distributer peer is too slow, all other distributors are
                 *       affected by this. This causes starvation and leads to a possible data loss on
                 *       the nDPId collector side.
                 */
                if (fcntl_del_flags(remotes.desc[i].fd, O_NONBLOCK) != 0)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Error setting distributor fd flags: %s", strerror(errno));
                    disconnect_client(epollfd, &remotes.desc[i]);
                    continue;
                }
                if (write(remotes.desc[i].fd, remotes.desc[i].buf.ptr, remotes.desc[i].buf.used) !=
                    (ssize_t)remotes.desc[i].buf.used)
                {
                    syslog(LOG_DAEMON | LOG_ERR,
                           "Could not drain buffer by %zu bytes. (forced)",
                           remotes.desc[i].buf.used);
                    disconnect_client(epollfd, &remotes.desc[i]);
                    continue;
                }
                remotes.desc[i].buf.used = 0;
                if (fcntl_add_flags(remotes.desc[i].fd, O_NONBLOCK) != 0)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Error setting distributor fd flags: %s", strerror(errno));
                    disconnect_client(epollfd, &remotes.desc[i]);
                    continue;
                }
            }

            memcpy(remotes.desc[i].buf.ptr + remotes.desc[i].buf.used,
                   current->buf.ptr,
                   current->event_json.json_bytes);
            remotes.desc[i].buf.used += current->event_json.json_bytes;

            errno = 0;
            ssize_t bytes_written = write(remotes.desc[i].fd, remotes.desc[i].buf.ptr, remotes.desc[i].buf.used);
            if (errno == EAGAIN)
            {
                continue;
            }
            if (bytes_written < 0 || errno != 0)
            {
                if (remotes.desc[i].event_serv.peer_addr[0] == '\0')
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Distributor connection closed, send failed: %s", strerror(errno));
                }
                else
                {
                    syslog(LOG_DAEMON | LOG_ERR,
                           "Distributor connection to %.*s:%u closed, send failed: %s",
                           (int)sizeof(remotes.desc[i].event_serv.peer_addr),
                           remotes.desc[i].event_serv.peer_addr,
                           ntohs(remotes.desc[i].event_serv.peer.sin_port),
                           strerror(errno));
                }
                disconnect_client(epollfd, &remotes.desc[i]);
                continue;
            }
            if (bytes_written == 0)
            {
                syslog(LOG_DAEMON,
                       "Distributor connection to %.*s:%u closed during write",
                       (int)sizeof(remotes.desc[i].event_serv.peer_addr),
                       remotes.desc[i].event_serv.peer_addr,
                       ntohs(remotes.desc[i].event_serv.peer.sin_port));
                disconnect_client(epollfd, &remotes.desc[i]);
                continue;
            }
            if ((size_t)bytes_written < remotes.desc[i].buf.used)
            {
                syslog(LOG_DAEMON,
                       "Distributor wrote less than expected to %.*s:%u: %zd < %zu",
                       (int)sizeof(remotes.desc[i].event_serv.peer_addr),
                       remotes.desc[i].event_serv.peer_addr,
                       ntohs(remotes.desc[i].event_serv.peer.sin_port),
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

    return 0;
}

static int handle_incoming_data_event(int epollfd, struct epoll_event * const event)
{
    struct remote_desc * current = (struct remote_desc *)event->data.ptr;

    if (current == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR, "%s", "remote descriptor got from event data invalid");
        return 1;
    }

    if (current->fd < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "file descriptor `%d' got from event data invalid", current->fd);
        return 1;
    }

    if ((event->events & EPOLLIN) == 0)
    {
        return 1;
    }

    return handle_incoming_data(epollfd, current);
}

static int setup_signalfd(int epollfd)
{
    sigset_t mask;
    int sfd;

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
    {
        return -1;
    }
    sfd = signalfd(-1, &mask, 0);
    if (sfd == -1)
    {
        return -1;
    }

    if (add_event(epollfd, sfd, NULL) != 0)
    {
        return -1;
    }

    if (fcntl_add_flags(sfd, O_NONBLOCK) != 0)
    {
        return -1;
    }

    return sfd;
}

static int mainloop(int epollfd)
{
    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);
    int signalfd = setup_signalfd(epollfd);

    while (main_thread_shutdown == 0)
    {
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
                    struct remote_desc * current = (struct remote_desc *)events[i].data.ptr;
                    disconnect_client(epollfd, current);
                }
                continue;
            }

            if (events[i].data.fd == json_sockfd || events[i].data.fd == serv_sockfd)
            {
                /* New connection to collector / distributor. */
                if (new_connection(epollfd, events[i].data.fd) != 0)
                {
                    continue;
                }
            }
            else if (events[i].data.fd == signalfd)
            {
                struct signalfd_siginfo fdsi;
                ssize_t s;

                s = read(signalfd, &fdsi, sizeof(struct signalfd_siginfo));
                if (s != sizeof(struct signalfd_siginfo))
                {
                    syslog(LOG_DAEMON | LOG_ERR,
                           "Invalid signal fd read size. Got %zd, wanted %zu bytes.",
                           s,
                           sizeof(struct signalfd_siginfo));
                    continue;
                }

                if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGQUIT)
                {
                    main_thread_shutdown = 1;
                    break;
                }
            }
            else
            {
                /* Incoming data. */
                if (handle_incoming_data_event(epollfd, &events[i]) != 0)
                {
                    continue;
                }
            }
        }
    }

    close(signalfd);

    return 0;
}

static int create_evq(void)
{
    return epoll_create1(EPOLL_CLOEXEC);
}

static int setup_event_queue(void)
{
    int epollfd = create_evq();
    if (epollfd < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error creating epoll: %s", strerror(errno));
        return -1;
    }

    if (add_event(epollfd, json_sockfd, NULL) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error adding JSON fd to epoll: %s", strerror(errno));
        return -1;
    }

    if (add_event(epollfd, serv_sockfd, NULL) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error adding SERV fd to epoll: %s", strerror(errno));
        return -1;
    }

    return epollfd;
}

static void close_event_queue(int epollfd)
{
    for (size_t i = 0; i < remotes.desc_size; ++i)
    {
        disconnect_client(epollfd, &remotes.desc[i]);
    }
    close(epollfd);
}

static int setup_remote_descriptors(size_t max_descriptors)
{
    remotes.desc_used = 0;
    remotes.desc_size = max_descriptors;
    remotes.desc = (struct remote_desc *)malloc(remotes.desc_size * sizeof(*remotes.desc));
    if (remotes.desc == NULL)
    {
        return -1;
    }
    for (size_t i = 0; i < remotes.desc_size; ++i)
    {
        remotes.desc[i].fd = -1;
        remotes.desc[i].buf.ptr = NULL;
        remotes.desc[i].buf.max = 0;
    }

    return 0;
}

#ifndef NO_MAIN
int main(int argc, char ** argv)
{
    int retval = 1;

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
        goto error;
    }
    closelog();
    openlog("nDPIsrvd", LOG_CONS | (log_to_stderr != 0 ? LOG_PERROR : 0), LOG_DAEMON);

    if (setup_remote_descriptors(32) != 0)
    {
        goto error;
    }

    if (create_listen_sockets() != 0)
    {
        goto error;
    }
    syslog(LOG_DAEMON, "collector listen on %s", json_sockpath);
    switch (serv_address.raw.sa_family)
    {
        default:
            goto error;
        case AF_INET:
        case AF_INET6:
            syslog(LOG_DAEMON, "distributor listen on %s", serv_optarg);
            syslog(LOG_DAEMON | LOG_ERR,
                   "Please keep in mind that using a TCP Socket may leak sensitive information to "
                   "everyone with access to the device/network. You've been warned!");
            break;
        case AF_UNIX:
            syslog(LOG_DAEMON, "distributor listen on %s", json_sockpath);
            break;
    }

    errno = 0;
    if (change_user_group(
            user, group, pidfile, json_sockpath, (serv_address.raw.sa_family == AF_UNIX ? serv_optarg : NULL)) != 0)
    {
        if (errno != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Change user/group failed: %s", strerror(errno));
        }
        else
        {
            syslog(LOG_DAEMON | LOG_ERR, "Change user/group failed.");
        }
        goto error;
    }

    signal(SIGPIPE, SIG_IGN);

    int epollfd = setup_event_queue();
    if (epollfd < 0)
    {
        goto error;
    }

    retval = mainloop(epollfd);
    close_event_queue(epollfd);
error:
    close(json_sockfd);
    close(serv_sockfd);

    daemonize_shutdown(pidfile);
    syslog(LOG_DAEMON | LOG_NOTICE, "Bye.");
    closelog();

    unlink(json_sockpath);
    unlink(serv_optarg);

    return retval;
}
#endif
