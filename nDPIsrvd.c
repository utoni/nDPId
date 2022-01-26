#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifndef NO_MAIN
#include <syslog.h>
#endif
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "nDPIsrvd.h"
#include "utils.h"

enum sock_type
{
    JSON_SOCK,
    SERV_SOCK
};

struct remote_desc
{
    enum sock_type sock_type;
    int fd;
    struct nDPIsrvd_buffer buf;
    UT_array * buf_cache;
    union
    {
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

static struct
{
    struct remote_desc * desc;
    size_t desc_size;
    size_t desc_used;
} remotes = {NULL, 0, 0};

static int nDPIsrvd_main_thread_shutdown = 0;
static int json_sockfd;
static int serv_sockfd;
static struct nDPIsrvd_address serv_address = {
    .raw.sa_family = 0xFFFF,
};

static struct
{
    int log_to_stderr;
    char * pidfile;
    char * json_sockpath;
    char * serv_optarg;
    char * user;
    char * group;
    nDPIsrvd_ull cache_array_length;
    int cache_fallback_to_blocking;
} nDPIsrvd_options = {.cache_array_length = nDPIsrvd_CACHE_ARRAY_LENGTH, .cache_fallback_to_blocking = 1};

static int fcntl_add_flags(int fd, int flags);
static int fcntl_del_flags(int fd, int flags);
static void disconnect_client(int epollfd, struct remote_desc * const current);
static int add_in_event(int epollfd, int fd, void * ptr);
static int add_out_event(int epollfd, int fd, void * ptr);
static int del_event(int epollfd, int fd);
static int drain_cache_blocking(struct remote_desc * const remote);

static void nDPIsrvd_buffer_array_copy(void * dst, const void * src)
{
    struct nDPIsrvd_buffer * const buf_dst = (struct nDPIsrvd_buffer *)dst;
    struct nDPIsrvd_buffer const * const buf_src = (struct nDPIsrvd_buffer *)src;

    buf_dst->ptr.raw = NULL;
    if (nDPIsrvd_buffer_init(buf_dst, buf_src->used) != 0)
    {
        return;
    }

    buf_dst->json_string_start = buf_src->json_string_start;
    buf_dst->json_string_length = buf_src->json_string_length;
    buf_dst->json_string = buf_src->json_string;
    buf_dst->used = buf_src->used;
    memcpy(buf_dst->ptr.raw, buf_src->ptr.raw, buf_src->used);
}

static void nDPIsrvd_buffer_array_dtor(void * elt)
{
    struct nDPIsrvd_buffer * const buf = (struct nDPIsrvd_buffer *)elt;

    nDPIsrvd_buffer_free(buf);
}

static const UT_icd nDPIsrvd_buffer_array_icd = {sizeof(struct nDPIsrvd_buffer),
                                                 NULL,
                                                 nDPIsrvd_buffer_array_copy,
                                                 nDPIsrvd_buffer_array_dtor};

#ifndef NO_MAIN
#ifdef ENABLE_MEMORY_PROFILING
void nDPIsrvd_memprof_log(char const * const format, ...)
{
    va_list ap;

    va_start(ap, format);
    vsyslog(LOG_DAEMON, format, ap);
    va_end(ap);
}
#endif
#endif

static int add_to_cache(struct remote_desc * const remote, uint8_t * const buf, nDPIsrvd_ull json_string_length)
{
    struct nDPIsrvd_buffer buf_src = {};

    if (utarray_len(remote->buf_cache) >= nDPIsrvd_options.cache_array_length)
    {
        if (nDPIsrvd_options.cache_fallback_to_blocking == 0)
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "Buffer cache limit (%u lines) reached, remote too slow.",
                   utarray_len(remote->buf_cache));
            return -1;
        }
        else
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "Buffer JSON string cache limit (%u lines) reached, falling back to blocking I/O.",
                   utarray_len(remote->buf_cache));
            if (drain_cache_blocking(remote) != 0)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Could not drain buffer cache in blocking I/O: %s", strerror(errno));
                return -1;
            }
        }
    }

    buf_src.ptr.raw = buf;
    buf_src.used = buf_src.max = buf_src.json_string_length = json_string_length;
    utarray_push_back(remote->buf_cache, &buf_src);

    return 0;
}

static int drain_main_buffer(struct remote_desc * const remote)
{
    if (remote->buf.used == 0)
    {
        return 0;
    }

    errno = 0;
    ssize_t bytes_written = write(remote->fd, remote->buf.ptr.raw, remote->buf.used);
    if (errno == EAGAIN)
    {
        return 0;
    }
    if (bytes_written < 0 || errno != 0)
    {
        if (remote->event_serv.peer_addr[0] == '\0')
        {
            syslog(LOG_DAEMON | LOG_ERR, "Distributor connection closed, send failed: %s", strerror(errno));
        }
        else
        {
            syslog(LOG_DAEMON | LOG_ERR,
                   "Distributor connection to %.*s:%u closed, send failed: %s",
                   (int)sizeof(remote->event_serv.peer_addr),
                   remote->event_serv.peer_addr,
                   ntohs(remote->event_serv.peer.sin_port),
                   strerror(errno));
        }
        return -1;
    }
    if (bytes_written == 0)
    {
        if (remote->event_serv.peer_addr[0] == '\0')
        {
            syslog(LOG_DAEMON, "%s", "Distributor connection closed during write");
        }
        else
        {
            syslog(LOG_DAEMON,
                   "Distributor connection to %.*s:%u closed during write",
                   (int)sizeof(remote->event_serv.peer_addr),
                   remote->event_serv.peer_addr,
                   ntohs(remote->event_serv.peer.sin_port));
        }
        return -1;
    }
    if ((size_t)bytes_written < remote->buf.used)
    {
#if 0
        syslog(LOG_DAEMON,
               "Distributor wrote less than expected to %.*s:%u: %zd < %zu",
               (int)sizeof(remote->event_serv.peer_addr),
               remote->event_serv.peer_addr,
               ntohs(remote->event_serv.peer.sin_port),
               bytes_written,
               remote->buf.used);
#endif
        memmove(remote->buf.ptr.raw, remote->buf.ptr.raw + bytes_written, remote->buf.used - bytes_written);
    }

    remote->buf.used -= bytes_written;
    return 0;
}

static int drain_cache(struct remote_desc * const remote)
{
    errno = 0;

    if (drain_main_buffer(remote) != 0)
    {
        return -1;
    }

    while (utarray_len(remote->buf_cache) > 0)
    {
        struct nDPIsrvd_buffer * buf = (struct nDPIsrvd_buffer *)utarray_front(remote->buf_cache);
        ssize_t written = write(remote->fd, buf->ptr.raw + buf->json_string_start, buf->json_string_length);
        switch (written)
        {
            case -1:
                if (errno == EAGAIN)
                {
                    return 0;
                }
                return -1;
            case 0:
                return -1;
            default:
                buf->json_string_start += written;
                buf->json_string_length -= written;
                if (buf->json_string_length == 0)
                {
                    utarray_erase(remote->buf_cache, 0, 1);
                }
                break;
        }
    }

    return 0;
}

static int drain_cache_blocking(struct remote_desc * const remote)
{
    int retval = 0;

    if (fcntl_del_flags(remote->fd, O_NONBLOCK) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error setting distributor fd flags: %s", strerror(errno));
        return -1;
    }
    if (drain_cache(remote) != 0)
    {
        retval = -1;
    }
    if (fcntl_add_flags(remote->fd, O_NONBLOCK) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error setting distributor fd flags: %s", strerror(errno));
        return -1;
    }

    return retval;
}

static int handle_outgoing_data(int epollfd, struct remote_desc * const remote)
{
    if (remote->sock_type != SERV_SOCK)
    {
        return -1;
    }
    if (drain_cache(remote) != 0)
    {
        disconnect_client(epollfd, remote);
        return -1;
    }
    if (utarray_len(remote->buf_cache) == 0)
    {
        del_event(epollfd, remote->fd);
    }

    return 0;
}

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
        return -1;
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
    }

    struct sockaddr_un json_addr;
    json_addr.sun_family = AF_UNIX;
    if (snprintf(json_addr.sun_path, sizeof(json_addr.sun_path), "%s", nDPIsrvd_options.json_sockpath) <= 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "snprintf failed: %s", strerror(errno));
        return 1;
    }

    if (bind(json_sockfd, (struct sockaddr *)&json_addr, sizeof(json_addr)) < 0)
    {
        unlink(nDPIsrvd_options.json_sockpath);
        syslog(LOG_DAEMON | LOG_ERR,
               "Error on binding UNIX socket (collector) to %s: %s",
               nDPIsrvd_options.json_sockpath,
               strerror(errno));
        return 1;
    }

    if (bind(serv_sockfd, &serv_address.raw, serv_address.size) < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "Error on binding socket (distributor) to %s: %s",
               nDPIsrvd_options.serv_optarg,
               strerror(errno));
        unlink(nDPIsrvd_options.json_sockpath);
        return 1;
    }

    if (listen(json_sockfd, 16) < 0 || listen(serv_sockfd, 16) < 0)
    {
        unlink(nDPIsrvd_options.json_sockpath);
        syslog(LOG_DAEMON | LOG_ERR, "Error on listen: %s", strerror(errno));
        return 1;
    }

    if (fcntl_add_flags(json_sockfd, O_NONBLOCK) != 0)
    {
        unlink(nDPIsrvd_options.json_sockpath);
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

static struct remote_desc * get_unused_remote_descriptor(enum sock_type type, int remote_fd, size_t max_buffer_size)
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
            utarray_new(remotes.desc[i].buf_cache, &nDPIsrvd_buffer_array_icd);
            if (nDPIsrvd_buffer_init(&remotes.desc[i].buf, max_buffer_size) != 0 || remotes.desc[i].buf_cache == NULL)
            {
                return NULL;
            }
            remotes.desc[i].sock_type = type;
            remotes.desc[i].fd = remote_fd;
            return &remotes.desc[i];
        }
    }

    return NULL;
}

static void free_remote_descriptor_data(void)
{
    for (size_t i = 0; i < remotes.desc_size; ++i)
    {
        if (remotes.desc[i].buf_cache != NULL)
        {
            utarray_free(remotes.desc[i].buf_cache);
            remotes.desc[i].buf_cache = NULL;
        }
        nDPIsrvd_buffer_free(&remotes.desc[i].buf);
    }
}

static int add_event(int epollfd, int events, int fd, void * ptr)
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
    event.events = events;

    return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event);
}

static int add_in_event(int epollfd, int fd, void * ptr)
{
    return add_event(epollfd, EPOLLIN, fd, ptr);
}

static int add_out_event(int epollfd, int fd, void * ptr)
{
    return add_event(epollfd, EPOLLOUT, fd, ptr);
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
    if (current->buf_cache != NULL)
    {
        utarray_clear(current->buf_cache);
    }
    nDPIsrvd_buffer_free(&current->buf);
}

static int nDPIsrvd_parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "lc:dp:s:u:g:C:Dvh")) != -1)
    {
        switch (opt)
        {
            case 'l':
                nDPIsrvd_options.log_to_stderr = 1;
                break;
            case 'c':
                free(nDPIsrvd_options.json_sockpath);
                nDPIsrvd_options.json_sockpath = strdup(optarg);
                break;
            case 'd':
                daemonize_enable();
                break;
            case 'p':
                free(nDPIsrvd_options.pidfile);
                nDPIsrvd_options.pidfile = strdup(optarg);
                break;
            case 's':
                free(nDPIsrvd_options.serv_optarg);
                nDPIsrvd_options.serv_optarg = strdup(optarg);
                break;
            case 'u':
                free(nDPIsrvd_options.user);
                nDPIsrvd_options.user = strdup(optarg);
                break;
            case 'g':
                free(nDPIsrvd_options.group);
                nDPIsrvd_options.group = strdup(optarg);
                break;
            case 'C':
                if (str_value_to_ull(optarg, &nDPIsrvd_options.cache_array_length) != CONVERSION_OK)
                {
                    fprintf(stderr, "%s: Argument for `-C' is not a number: %s\n", argv[0], optarg);
                    return 1;
                }
                break;
            case 'D':
                nDPIsrvd_options.cache_fallback_to_blocking = 0;
                break;
            case 'v':
                fprintf(stderr, "%s", get_nDPId_version());
                return 1;
            case 'h':
            default:
                fprintf(stderr, "%s\n", get_nDPId_version());
                fprintf(stderr,
                        "Usage: %s [-l] [-c path-to-unix-sock] [-d] [-p pidfile]\n"
                        "\t[-s path-to-unix-socket|distributor-host:port] [-u user] [-g group]\n"
                        "\t[-C max-buffered-collector-json-lines] [-D]\n"
                        "\t[-v] [-h]\n",
                        argv[0]);
                return 1;
        }
    }

    if (nDPIsrvd_options.pidfile == NULL)
    {
        nDPIsrvd_options.pidfile = strdup(nDPIsrvd_PIDFILE);
    }
    if (is_path_absolute("Pidfile", nDPIsrvd_options.pidfile) != 0)
    {
        return 1;
    }

    if (nDPIsrvd_options.json_sockpath == NULL)
    {
        nDPIsrvd_options.json_sockpath = strdup(COLLECTOR_UNIX_SOCKET);
    }
    if (is_path_absolute("JSON socket", nDPIsrvd_options.json_sockpath) != 0)
    {
        return 1;
    }

    if (nDPIsrvd_options.serv_optarg == NULL)
    {
        nDPIsrvd_options.serv_optarg = strdup(DISTRIBUTOR_UNIX_SOCKET);
    }

    if (nDPIsrvd_setup_address(&serv_address, nDPIsrvd_options.serv_optarg) != 0)
    {
        fprintf(stderr, "%s: Could not parse address `%s'\n", argv[0], nDPIsrvd_options.serv_optarg);
        return 1;
    }
    if (serv_address.raw.sa_family == AF_UNIX && is_path_absolute("SERV socket", nDPIsrvd_options.serv_optarg) != 0)
    {
        return 1;
    }

    if (optind < argc)
    {
        fprintf(stderr, "%s: Unexpected argument after options\n", argv[0]);
        return 1;
    }

    return 0;
}

static struct remote_desc * accept_remote(int server_fd,
                                          enum sock_type socktype,
                                          struct sockaddr * const sockaddr,
                                          socklen_t * const addrlen)
{
    int client_fd = accept(server_fd, sockaddr, addrlen);
    if (client_fd < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Accept failed: %s", strerror(errno));
        return NULL;
    }

    struct remote_desc * current = get_unused_remote_descriptor(socktype, client_fd, NETWORK_BUFFER_MAX_SIZE);
    if (current == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Max number of connections reached: %zu", remotes.desc_used);
        return NULL;
    }

    return current;
}

static int new_connection(int epollfd, int eventfd)
{
    union
    {
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

    struct remote_desc * const current = accept_remote(server_fd, stype, (struct sockaddr *)&sockaddr, &peer_addr_len);
    if (current == NULL)
    {
        return 1;
    }

    char const * sock_type = NULL;
    int sockopt = NETWORK_BUFFER_MAX_SIZE;
    switch (current->sock_type)
    {
        case JSON_SOCK:
            sock_type = "collector";
            current->event_json.json_bytes = 0;
            syslog(LOG_DAEMON, "New collector connection");

            if (setsockopt(current->fd, SOL_SOCKET, SO_RCVBUF, &sockopt, sizeof(sockopt)) < 0)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Error setting socket option SO_RCVBUF: %s", strerror(errno));
                return 1;
            }
            break;
        case SERV_SOCK:
            sock_type = "distributor";

            if (setsockopt(current->fd, SOL_SOCKET, SO_SNDBUF, &sockopt, sizeof(sockopt)) < 0)
            {
                syslog(LOG_DAEMON | LOG_ERR, "Error setting socket option SO_SNDBUF: %s", strerror(errno));
                return 1;
            }

            if (inet_ntop(current->event_serv.peer.sin_family,
                          &current->event_serv.peer.sin_addr,
                          &current->event_serv.peer_addr[0],
                          sizeof(current->event_serv.peer_addr)) == NULL)
            {
                if (errno == EAFNOSUPPORT)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "%s", "New distributor connection.");
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
            {
                struct timeval send_timeout = {1, 0};
                if (setsockopt(current->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&send_timeout, sizeof(send_timeout)) != 0)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Error setting socket option send timeout: %s", strerror(errno));
                }
                if (setsockopt(current->fd, SOL_SOCKET, SO_SNDBUF, &sockopt, sizeof(sockopt)) < 0)
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Error setting socket option SO_SNDBUF: %s", strerror(errno));
                }
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
        if (add_in_event(epollfd, current->fd, current) != 0)
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

    if (current->buf.ptr.text[NETWORK_BUFFER_LENGTH_DIGITS] != '{')
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "BUG: JSON invalid opening character: '%c'",
               current->buf.ptr.text[NETWORK_BUFFER_LENGTH_DIGITS]);
        disconnect_client(epollfd, current);
        return 1;
    }

    errno = 0;
    current->event_json.json_bytes = strtoull((char *)current->buf.ptr.text, &json_str_start, 10);
    current->event_json.json_bytes += json_str_start - current->buf.ptr.text;

    if (errno == ERANGE)
    {
        syslog(LOG_DAEMON | LOG_ERR, "BUG: Size of JSON exceeds limit");
        disconnect_client(epollfd, current);
        return 1;
    }

    if (json_str_start == current->buf.ptr.text)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "BUG: Missing size before JSON string: \"%.*s\"",
               NETWORK_BUFFER_LENGTH_DIGITS,
               current->buf.ptr.text);
        disconnect_client(epollfd, current);
        return 1;
    }

    if (json_str_start - current->buf.ptr.text != NETWORK_BUFFER_LENGTH_DIGITS)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "BUG: Invalid collector protocol data received. Expected protocol preamble of size %u bytes, got %ld "
               "bytes",
               NETWORK_BUFFER_LENGTH_DIGITS,
               (long int)(json_str_start - current->buf.ptr.text));
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

    if (current->buf.ptr.text[current->event_json.json_bytes - 2] != '}' ||
        current->buf.ptr.text[current->event_json.json_bytes - 1] != '\n')
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "BUG: Invalid JSON string: %.*s",
               (int)current->event_json.json_bytes,
               current->buf.ptr.text);
        disconnect_client(epollfd, current);
        return 1;
    }

    return 0;
}

static int handle_incoming_data(int epollfd, struct remote_desc * const current)
{
    if (current->sock_type != JSON_SOCK)
    {
        return 1;
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
            read(current->fd, current->buf.ptr.raw + current->buf.used, current->buf.max - current->buf.used);
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
            if (current->event_json.json_bytes > remotes.desc[i].buf.max - remotes.desc[i].buf.used ||
                utarray_len(remotes.desc[i].buf_cache) > 0)
            {
                if (utarray_len(remotes.desc[i].buf_cache) == 0)
                {
#if 0
                    syslog(LOG_DAEMON, "Buffer capacity threshold (%zu bytes) reached, caching JSON strings.", remotes.desc[i].buf.used);
#endif
                    errno = 0;
                    if (add_out_event(epollfd, remotes.desc[i].fd, &remotes.desc[i]) != 0 &&
                        errno != EEXIST /* required for nDPId-test */)
                    {
                        syslog(LOG_DAEMON | LOG_ERR, "%s: %s", "Could not add event, disconnecting", strerror(errno));
                        disconnect_client(epollfd, &remotes.desc[i]);
                        continue;
                    }
                }
                if (add_to_cache(&remotes.desc[i], current->buf.ptr.raw, current->event_json.json_bytes) != 0)
                {
                    disconnect_client(epollfd, &remotes.desc[i]);
                    continue;
                }
            }
            else
            {
                memcpy(remotes.desc[i].buf.ptr.raw + remotes.desc[i].buf.used,
                       current->buf.ptr.raw,
                       current->event_json.json_bytes);
                remotes.desc[i].buf.used += current->event_json.json_bytes;
            }

            if (drain_main_buffer(&remotes.desc[i]) != 0)
            {
                disconnect_client(epollfd, &remotes.desc[i]);
            }
        }

        memmove(current->buf.ptr.raw,
                current->buf.ptr.raw + current->event_json.json_bytes,
                current->buf.used - current->event_json.json_bytes);
        current->buf.used -= current->event_json.json_bytes;
        current->event_json.json_bytes = 0;
    }

    return 0;
}

static int handle_data_event(int epollfd, struct epoll_event * const event)
{
    struct remote_desc * current = (struct remote_desc *)event->data.ptr;

    if ((event->events & EPOLLIN) == 0 && (event->events & EPOLLOUT) == 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Can not handle event mask: %d", event->events);
        return 1;
    }

    if (current == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR, "%s", "Remote descriptor got from event data invalid.");
        return 1;
    }

    if (current->fd < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "File descriptor `%d' got from event data invalid.", current->fd);
        return 1;
    }

    if ((event->events & EPOLLIN) != 0)
    {
        return handle_incoming_data(epollfd, current);
    }
    else
    {
        return handle_outgoing_data(epollfd, current);
    }
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

    if (add_in_event(epollfd, sfd, NULL) != 0)
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

    while (nDPIsrvd_main_thread_shutdown == 0)
    {
        int nready = epoll_wait(epollfd, events, events_size, -1);

        for (int i = 0; i < nready; i++)
        {
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP)
            {
                if (events[i].data.fd != json_sockfd && events[i].data.fd != serv_sockfd)
                {
                    struct remote_desc * const current = (struct remote_desc *)events[i].data.ptr;
                    switch (current->sock_type)
                    {
                        case JSON_SOCK:
                            syslog(LOG_DAEMON | LOG_ERR, "Collector disconnected: %d", current->fd);
                            break;
                        case SERV_SOCK:
                            if (current->event_serv.peer_addr[0] == '\0')
                            {
                                syslog(LOG_DAEMON | LOG_ERR, "%s", "Distributor disconnected");
                            }
                            else
                            {
                                syslog(LOG_DAEMON | LOG_ERR,
                                       "Distributor disconnected: %.*s:%u",
                                       (int)sizeof(current->event_serv.peer_addr),
                                       current->event_serv.peer_addr,
                                       current->event_serv.peer.sin_port);
                            }
                            break;
                    }
                    disconnect_client(epollfd, current);
                }
                else
                {
                    syslog(LOG_DAEMON | LOG_ERR, "Epoll event error: %s", (errno != 0 ? strerror(errno) : "unknown"));
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
                    nDPIsrvd_main_thread_shutdown = 1;
                    break;
                }
            }
            else
            {
                /* Incoming data / Outoing data ready to send. */
                if (handle_data_event(epollfd, &events[i]) != 0)
                {
                    continue;
                }
            }
        }
    }

    close(signalfd);

    free_remote_descriptor_data();

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

    if (add_in_event(epollfd, json_sockfd, NULL) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Error adding JSON fd to epoll: %s", strerror(errno));
        return -1;
    }

    if (add_in_event(epollfd, serv_sockfd, NULL) != 0)
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
    remotes.desc = (struct remote_desc *)nDPIsrvd_calloc(remotes.desc_size, sizeof(*remotes.desc));
    if (remotes.desc == NULL)
    {
        return -1;
    }
    for (size_t i = 0; i < remotes.desc_size; ++i)
    {
        remotes.desc[i].fd = -1;
    }

    return 0;
}

#ifndef NO_MAIN
int main(int argc, char ** argv)
{
    int retval = 1;
    int epollfd;

    if (argc == 0)
    {
        return 1;
    }

    if (nDPIsrvd_parse_options(argc, argv) != 0)
    {
        return 1;
    }

    openlog("nDPIsrvd", LOG_CONS | LOG_PERROR, LOG_DAEMON);

    if (access(nDPIsrvd_options.json_sockpath, F_OK) == 0)
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "UNIX socket %s exists; nDPIsrvd already running? "
               "Please remove the socket manually or change socket path.",
               nDPIsrvd_options.json_sockpath);
        return 1;
    }

    if (daemonize_with_pidfile(nDPIsrvd_options.pidfile) != 0)
    {
        goto error;
    }
    closelog();
    openlog("nDPIsrvd", LOG_CONS | (nDPIsrvd_options.log_to_stderr != 0 ? LOG_PERROR : 0), LOG_DAEMON);

    if (setup_remote_descriptors(32) != 0)
    {
        goto error;
    }

    if (create_listen_sockets() != 0)
    {
        goto error;
    }

    syslog(LOG_DAEMON, "collector listen on %s", nDPIsrvd_options.json_sockpath);
    syslog(LOG_DAEMON, "distributor listen on %s", nDPIsrvd_options.serv_optarg);
    switch (serv_address.raw.sa_family)
    {
        default:
            goto error;
        case AF_INET:
        case AF_INET6:
            syslog(LOG_DAEMON | LOG_ERR,
                   "Please keep in mind that using a TCP Socket may leak sensitive information to "
                   "everyone with access to the device/network. You've been warned!");
            break;
        case AF_UNIX:
            break;
    }

    errno = 0;
    if (change_user_group(nDPIsrvd_options.user,
                          nDPIsrvd_options.group,
                          nDPIsrvd_options.pidfile,
                          nDPIsrvd_options.json_sockpath,
                          (serv_address.raw.sa_family == AF_UNIX ? nDPIsrvd_options.serv_optarg : NULL)) != 0)
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

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    epollfd = setup_event_queue();
    if (epollfd < 0)
    {
        goto error;
    }

    retval = mainloop(epollfd);
    close_event_queue(epollfd);
error:
    close(json_sockfd);
    close(serv_sockfd);

    daemonize_shutdown(nDPIsrvd_options.pidfile);
    syslog(LOG_DAEMON | LOG_NOTICE, "Bye.");
    closelog();

    unlink(nDPIsrvd_options.json_sockpath);
    unlink(nDPIsrvd_options.serv_optarg);

    return retval;
}
#endif
