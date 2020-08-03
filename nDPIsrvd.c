#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <linux/un.h>
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

enum ev_type { JSON_SOCK, SERV_SOCK };

struct remote_desc {
    enum ev_type type;
    int fd;
    union {
        struct {
            int json_sockfd;
            struct sockaddr_un peer;
        } event_json;
        struct {
            int serv_sockfd;
            struct sockaddr_in peer;
        } event_serv;
    };
};

static struct remotes {
    struct remote_desc * desc;
    size_t desc_size;
    size_t desc_used;
} remotes = {NULL, 0, 0};

static char json_sockpath[UNIX_PATH_MAX] = COLLECTOR_UNIX_SOCKET;
static char serv_listen_addr[INET6_ADDRSTRLEN] = DISTRIBUTOR_HOST;
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
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(serv_listen_port);
    if (inet_ntop(AF_INET, &serv_addr.sin_addr, &serv_listen_addr[0], INET_ADDRSTRLEN) == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error converting an internet address: %s", strerror(errno));
        return 1;
    }

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
    if (remotes.desc_used == remotes.desc_size) {
        return NULL;
    }

    for (size_t i = 0; i < remotes.desc_size; ++i) {
        if (remotes.desc[i].fd == -1) {
            remotes.desc_used++;
            return &remotes.desc[i];
        }
    }

    return NULL;
}

static void disconnect_client(int epollfd, struct remote_desc * const current)
{
    if (current->fd > -1) {
        if (epoll_ctl(epollfd, EPOLL_CTL_DEL, current->fd, NULL) < 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Error deleting fd from epollq: %s", strerror(errno));
        }
        if (close(current->fd) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Error closing fd: %s", strerror(errno));
        }
    }
    current->fd = -1;
    remotes.desc_used--;
}

int main(void)
{
    openlog("nDPIsrvd", LOG_CONS | LOG_PERROR, LOG_DAEMON);

    remotes.desc_used = 0;
    remotes.desc_size = 32;
    remotes.desc = (struct remote_desc *) malloc(remotes.desc_size * sizeof(*remotes.desc));
    if (remotes.desc == NULL) {
        return 1;
    }
    for (size_t i = 0; i < remotes.desc_size; ++i)
    {
        remotes.desc[i].fd = -1;
    }

    unlink(json_sockpath);

    if (create_listen_sockets() != 0)
    {
        return 1;
    }

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
    while (1)
    {
        struct remote_desc * current = NULL;
        int nready = epoll_wait(epollfd, events, events_size, -1);

        for (int i = 0; i < nready; i++)
        {
            if (events[i].events & EPOLLERR)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Epoll event error: %s", strerror(errno));
                continue;
            }

            /* New connection to collector / distributor. */
            if (events[i].data.fd == json_sockfd ||
                events[i].data.fd == serv_sockfd)
            {
                current = get_unused_remote_descriptor();
                if (current == NULL) {
                    syslog(LOG_DAEMON | LOG_ERR, "Max number of connections reached: %zu", remotes.desc_used);
                    continue;
                }
                current->type = (events[i].data.fd == json_sockfd ? JSON_SOCK : SERV_SOCK);

                int sockfd = (events[i].data.fd == json_sockfd ? json_sockfd : serv_sockfd);
                socklen_t peer_addr_len = (events[i].data.fd == json_sockfd
                                           ? sizeof(current->event_json.peer)
                                           : sizeof(current->event_serv.peer));

                current->fd = accept(sockfd,
                                     (current->type == JSON_SOCK
                                      ? (struct sockaddr *) &current->event_json.peer
                                      : (struct sockaddr *) &current->event_serv.peer),
                                     &peer_addr_len);
                if (current->fd < 0) {
                    syslog(LOG_DAEMON | LOG_ERR, "Accept failed: %s", strerror(errno));
                    disconnect_client(epollfd, current);
                    continue;
                }

                syslog(LOG_DAEMON, "New %s connection", (current->type == JSON_SOCK
                                                         ? "collector"
                                                         : "distributor"));

                /* nonblocking fd is mandatory */
                int fd_flags = fcntl(current->fd, F_GETFL, 0);
                if (fd_flags == -1 || fcntl(current->fd, F_SETFL, fd_flags | O_NONBLOCK) == -1)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Error setting fd flags: %s", strerror(errno));
                    disconnect_client(epollfd, current);
                    continue;
                }

                /* shutdown writing end for collector clients */
                if (current->type == JSON_SOCK) {
                    shutdown(current->fd, SHUT_WR); // collector
                }

                /* setup epoll event */
                struct epoll_event accept_event = {};
                accept_event.data.ptr = current;
                accept_event.events = EPOLLIN;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, current->fd, &accept_event) < 0) {
                    disconnect_client(epollfd, current);
                    continue;
                }
            } else {
                current = (struct remote_desc *) events[i].data.ptr;

                if (current->fd < 0) {
                    syslog(LOG_DAEMON | LOG_ERR, "file descriptor `%d' got from event data invalid", current->fd);
                    continue;
                }

                if (events[i].events & EPOLLHUP) {
                    syslog(LOG_DAEMON, "%s connection closed", (current->type == JSON_SOCK
                                                                ? "collector"
                                                                : "distributor"));
                    disconnect_client(epollfd, current);
                    continue;
                }
                if (events[i].events & EPOLLIN) {
                    errno = 0;
                    char buf[BUFSIZ];
                    ssize_t bytes_read = read(current->fd, buf, sizeof(buf));
                    if (bytes_read < 0 || errno != 0) {
                        disconnect_client(epollfd, current);
                        continue;
                    }
                    if (bytes_read == 0) {
                        syslog(LOG_DAEMON, "%s connection closed during read", (current->type == JSON_SOCK
                                                                                ? "collector"
                                                                                : "distributor"));
                        disconnect_client(epollfd, current);
                        continue;
                    }

                    /* broadcast data coming from the json-collector socket to all tcp clients */
                    if (current->type == JSON_SOCK) {
                        for (size_t i = 0; i < remotes.desc_size; ++i) {
                            if (remotes.desc[i].fd < 0) {
                                continue;
                            }
                            if (remotes.desc[i].type == SERV_SOCK) {
                                ssize_t bytes_written = write(remotes.desc[i].fd, buf, bytes_read);
                                if (bytes_written < 0 || errno != 0) {
                                    disconnect_client(epollfd, current);
                                    continue;
                                }
                                if (bytes_written == 0) {
                                    syslog(LOG_DAEMON, "%s connection closed during write", (current->type == JSON_SOCK
                                                                                             ? "collector"
                                                                                             : "distributor"));
                                    disconnect_client(epollfd, current);
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    close(json_sockfd);
    close(serv_sockfd);

    return 0;
}
