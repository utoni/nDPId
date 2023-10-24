#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#if !defined(__FreeBSD__) && !defined(__APPLE__)
#include <sys/signalfd.h>
#endif
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "nDPIsrvd.h"
#include "nio.h"
#include "utils.h"

enum sock_type
{
    COLLECTOR_UN,
    DISTRIBUTOR_UN,
    DISTRIBUTOR_IN,
};

struct nDPIsrvd_write_buffer
{
    struct nDPIsrvd_buffer buf;
    size_t written;
};

struct remote_desc
{
    enum sock_type sock_type;
    int fd;

    union
    {
        struct
        {
            struct sockaddr_un peer;
            unsigned long long int json_bytes;
#if !defined(__FreeBSD__) && !defined(__APPLE__)
            pid_t pid;
#endif

            struct nDPIsrvd_json_buffer main_read_buffer;
        } event_collector_un;
        struct
        {
            struct sockaddr_un peer;
#if !defined(__FreeBSD__) && !defined(__APPLE__)
            pid_t pid;
            char * user_name;
#endif

            struct nDPIsrvd_write_buffer main_write_buffer;
            UT_array * additional_write_buffers;
        } event_distributor_un; /* UNIX socket */
        struct
        {
            struct sockaddr_in peer;
            char peer_addr[INET_ADDRSTRLEN];

            struct nDPIsrvd_write_buffer main_write_buffer;
            UT_array * additional_write_buffers;
        } event_distributor_in; /* TCP/IP socket */
    };
};

static struct
{
    struct remote_desc * desc;
    nDPIsrvd_ull desc_size;
    nDPIsrvd_ull desc_used;
} remotes = {NULL, 0, 0};

static int nDPIsrvd_main_thread_shutdown = 0;
static int collector_un_sockfd = -1;
static int distributor_un_sockfd = -1;
static int distributor_in_sockfd = -1;
static struct nDPIsrvd_address distributor_in_address = {
    .raw.sa_family = (sa_family_t)0xFFFF,
};

static struct
{
    struct cmdarg pidfile;
    struct cmdarg collector_un_sockpath;
    struct cmdarg distributor_un_sockpath;
    struct cmdarg distributor_in_address;
    struct cmdarg user;
    struct cmdarg group;
    nDPIsrvd_ull max_remote_descriptors;
    nDPIsrvd_ull max_write_buffers;
    uint8_t bufferbloat_fallback_to_blocking;
#ifdef ENABLE_EPOLL
    uint8_t use_poll;
#endif
} nDPIsrvd_options = {.pidfile = CMDARG(nDPIsrvd_PIDFILE),
                      .collector_un_sockpath = CMDARG(COLLECTOR_UNIX_SOCKET),
                      .distributor_un_sockpath = CMDARG(DISTRIBUTOR_UNIX_SOCKET),
                      .distributor_in_address = CMDARG(NULL),
                      .user = CMDARG(DEFAULT_CHUSER),
                      .group = CMDARG(NULL),
                      .max_remote_descriptors = nDPIsrvd_MAX_REMOTE_DESCRIPTORS,
                      .max_write_buffers = nDPIsrvd_MAX_WRITE_BUFFERS,
                      .bufferbloat_fallback_to_blocking = 1};

static void logger_nDPIsrvd(struct remote_desc const * const remote,
                            char const * const prefix,
                            char const * const format,
                            ...);
static int fcntl_add_flags(int fd, int flags);
static int fcntl_del_flags(int fd, int flags);
static int add_in_event_fd(struct nio * const io, int fd);
static int add_in_event(struct nio * const io, struct remote_desc * const remote);
static int del_event(struct nio * const io, int fd);
static int set_in_event(struct nio * const io, struct remote_desc * const remote);
static void disconnect_client(struct nio * const io, struct remote_desc * const current);
static int drain_write_buffers_blocking(struct remote_desc * const remote);

static void nDPIsrvd_buffer_array_copy(void * dst, const void * src)
{
    struct nDPIsrvd_write_buffer * const buf_dst = (struct nDPIsrvd_write_buffer *)dst;
    struct nDPIsrvd_write_buffer const * const buf_src = (struct nDPIsrvd_write_buffer *)src;

    buf_dst->buf.ptr.raw = NULL;
    if (nDPIsrvd_buffer_init(&buf_dst->buf, buf_src->buf.used) != 0)
    {
        logger(1, "Additional write buffer init failed, size: %zu bytes", buf_src->buf.used);
        return;
    }

    buf_dst->written = buf_src->written;
    buf_dst->buf.used = buf_src->buf.used;
    memcpy(buf_dst->buf.ptr.raw, buf_src->buf.ptr.raw, buf_src->buf.used);
}

static void nDPIsrvd_buffer_array_dtor(void * elt)
{
    struct nDPIsrvd_write_buffer * const buf_dst = (struct nDPIsrvd_write_buffer *)elt;

    nDPIsrvd_buffer_free(&buf_dst->buf);
    buf_dst->written = 0;
}

static const UT_icd nDPIsrvd_buffer_array_icd = {sizeof(struct nDPIsrvd_write_buffer),
                                                 NULL,
                                                 nDPIsrvd_buffer_array_copy,
                                                 nDPIsrvd_buffer_array_dtor};

#ifndef NO_MAIN
#ifdef ENABLE_MEMORY_PROFILING
void nDPIsrvd_memprof_log_alloc(size_t alloc_size)
{
    (void)alloc_size;
}

void nDPIsrvd_memprof_log_free(size_t free_size)
{
    (void)free_size;
}

void nDPIsrvd_memprof_log(char const * const format, ...)
{
    va_list ap;

    va_start(ap, format);
    vlogger(0, format, ap);
    va_end(ap);
}
#endif
#endif

static struct nDPIsrvd_json_buffer * get_read_buffer(struct remote_desc * const remote)
{
    switch (remote->sock_type)
    {
        case COLLECTOR_UN:
            return &remote->event_collector_un.main_read_buffer;

        case DISTRIBUTOR_UN:
        case DISTRIBUTOR_IN:
            return NULL;
    }

    return NULL;
}

static struct nDPIsrvd_write_buffer * get_write_buffer(struct remote_desc * const remote)
{
    switch (remote->sock_type)
    {
        case COLLECTOR_UN:
            return NULL;

        case DISTRIBUTOR_UN:
            return &remote->event_distributor_un.main_write_buffer;

        case DISTRIBUTOR_IN:
            return &remote->event_distributor_in.main_write_buffer;
    }

    return NULL;
}

static UT_array * get_additional_write_buffers(struct remote_desc * const remote)
{
    switch (remote->sock_type)
    {
        case COLLECTOR_UN:
            return NULL;

        case DISTRIBUTOR_UN:
            return remote->event_distributor_un.additional_write_buffers;

        case DISTRIBUTOR_IN:
            return remote->event_distributor_in.additional_write_buffers;
    }

    return NULL;
}

static int add_to_additional_write_buffers(struct remote_desc * const remote,
                                           uint8_t * const buf,
                                           nDPIsrvd_ull json_string_length)
{
    struct nDPIsrvd_write_buffer buf_src = {};
    UT_array * const additional_write_buffers = get_additional_write_buffers(remote);

    if (additional_write_buffers == NULL)
    {
        return -1;
    }

    if (utarray_len(additional_write_buffers) >= nDPIsrvd_options.max_write_buffers)
    {
        if (nDPIsrvd_options.bufferbloat_fallback_to_blocking == 0)
        {
            logger_nDPIsrvd(remote,
                            "Buffer limit for",
                            "for reached, remote too slow: %u lines",
                            utarray_len(additional_write_buffers));
            logger_nDPIsrvd(remote, "%s", "You can try to increase buffer limits with `-C'.");
            return -1;
        }
        else
        {
            logger_nDPIsrvd(remote,
                            "Buffer limit for",
                            "reached, falling back to blocking I/O: %u lines",
                            utarray_len(additional_write_buffers));
            if (drain_write_buffers_blocking(remote) != 0)
            {
                return -1;
            }
        }
    }

    buf_src.buf.ptr.raw = buf;
    buf_src.buf.used = buf_src.buf.max = json_string_length;
    utarray_push_back(additional_write_buffers, &buf_src);

    return 0;
}

static void logger_nDPIsrvd(struct remote_desc const * const remote,
                            char const * const prefix,
                            char const * const format,
                            ...)
{
    char logbuf[512];
    va_list ap;

    va_start(ap, format);
    vsnprintf(logbuf, sizeof(logbuf), format, ap);

    switch (remote->sock_type)
    {
        case DISTRIBUTOR_UN:
#if !defined(__FreeBSD__) && !defined(__APPLE__)
            logger(1,
                   "%s PID %d (User: %s) %s",
                   prefix,
                   remote->event_distributor_un.pid,
                   remote->event_distributor_un.user_name,
                   logbuf);
#else
            logger(1, "%s %s", prefix, logbuf);
#endif
            break;
        case DISTRIBUTOR_IN:
            logger(1,
                   "%s %.*s:%u %s",
                   prefix,
                   (int)sizeof(remote->event_distributor_in.peer_addr),
                   remote->event_distributor_in.peer_addr,
                   ntohs(remote->event_distributor_in.peer.sin_port),
                   logbuf);
            break;
        case COLLECTOR_UN:
#if !defined(__FreeBSD__) && !defined(__APPLE__)
            logger(1, "%s PID %d %s", prefix, remote->event_collector_un.pid, logbuf);
#else
            logger(1, "%s %s", prefix, logbuf);
#endif
            break;
    }

    va_end(ap);
}

static int drain_main_buffer(struct remote_desc * const remote)
{
    ssize_t bytes_written;
    struct nDPIsrvd_write_buffer * const write_buffer = get_write_buffer(remote);

    if (write_buffer == NULL)
    {
        return -1;
    }

    if (write_buffer->buf.used == 0)
    {
        return 0;
    }

    errno = 0;
    while ((bytes_written = write(remote->fd, write_buffer->buf.ptr.raw, write_buffer->buf.used)) < 0 && errno == EINTR)
    {
        errno = 0;
    }
    if (errno == EAGAIN)
    {
        return 0;
    }
    if (bytes_written < 0 || errno != 0)
    {
        logger_nDPIsrvd(remote, "Distributor connection", "closed, send failed: %s", strerror(errno));
        return -1;
    }
    if (bytes_written == 0)
    {
        logger_nDPIsrvd(remote, "Distributor connection", "closed");
        return -1;
    }
    if ((size_t)bytes_written < write_buffer->buf.used)
    {
#if 0
        logger_nDPIsrvd(
            remote, "Distributor", "wrote less than expected: %zd < %zu", bytes_written, remote->buf.used);
#endif
        memmove(write_buffer->buf.ptr.raw,
                write_buffer->buf.ptr.raw + bytes_written,
                write_buffer->buf.used - bytes_written);
    }

    write_buffer->buf.used -= bytes_written;
    return 0;
}

static int drain_write_buffers(struct remote_desc * const remote)
{
    UT_array * const additional_write_buffers = get_additional_write_buffers(remote);

    errno = 0;

    if (drain_main_buffer(remote) != 0 || additional_write_buffers == NULL)
    {
        return -1;
    }

    while (utarray_len(additional_write_buffers) > 0)
    {
        struct nDPIsrvd_write_buffer * buf = (struct nDPIsrvd_write_buffer *)utarray_front(additional_write_buffers);
        ssize_t written;

        while ((written = write(remote->fd, buf->buf.ptr.raw + buf->written, buf->buf.used - buf->written)) < 0 &&
               errno == EINTR)
        {
        }
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
                buf->written += written;
                if (buf->written == buf->buf.max)
                {
                    utarray_erase(additional_write_buffers, 0, 1);
                }
                break;
        }
    }

    return 0;
}

static int drain_write_buffers_blocking(struct remote_desc * const remote)
{
    int retval = 0;

    if (fcntl_del_flags(remote->fd, O_NONBLOCK) != 0)
    {
        logger_nDPIsrvd(remote, "Error setting distributor", "fd flags to blocking mode: %s", strerror(errno));
        return -1;
    }
    if (drain_write_buffers(remote) != 0)
    {
        logger_nDPIsrvd(remote, "Could not drain buffers for", "in blocking I/O: %s", strerror(errno));
        retval = -1;
    }
    if (fcntl_add_flags(remote->fd, O_NONBLOCK) != 0)
    {
        logger_nDPIsrvd(remote, "Error setting distributor", "fd flags to non-blocking mode: %s", strerror(errno));
        return -1;
    }

    return retval;
}

static int handle_outgoing_data(struct nio * const io, struct remote_desc * const remote)
{
    UT_array * const additional_write_buffers = get_additional_write_buffers(remote);

    if (additional_write_buffers == NULL)
    {
        return -1;
    }
    if (drain_write_buffers(remote) != 0)
    {
        logger_nDPIsrvd(remote, "Could not drain buffers for", ": %s", strerror(errno));
        disconnect_client(io, remote);
        return -1;
    }
    if (utarray_len(additional_write_buffers) == 0)
    {
        struct nDPIsrvd_write_buffer * const write_buffer = get_write_buffer(remote);

        if (write_buffer->buf.used == 0)
        {
            return set_in_event(io, remote);
        }
        else
        {
            return drain_main_buffer(remote);
        }
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
    collector_un_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    distributor_un_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (collector_un_sockfd < 0 || distributor_un_sockfd < 0 || set_fd_cloexec(collector_un_sockfd) < 0 ||
        set_fd_cloexec(distributor_un_sockfd) < 0)
    {
        logger(1, "Error creating UNIX socket: %s", strerror(errno));
        return 1;
    }

    if (is_cmdarg_set(&nDPIsrvd_options.distributor_in_address) != 0)
    {
        distributor_in_sockfd = socket(distributor_in_address.raw.sa_family, SOCK_STREAM, 0);
        if (distributor_in_sockfd < 0 || set_fd_cloexec(distributor_in_sockfd) < 0)
        {
            logger(1, "Error creating TCP/IP socket: %s", strerror(errno));
            return 1;
        }
        int opt = 1;
        if (setsockopt(distributor_in_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            logger(1, "Setting TCP/IP socket option SO_REUSEADDR failed: %s", strerror(errno));
        }
    }

    {
        int opt = 1;
        if (setsockopt(collector_un_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0 ||
            setsockopt(distributor_un_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            logger(1, "Setting UNIX socket option SO_REUSEADDR failed: %s", strerror(errno));
        }
    }

    {
        struct sockaddr_un collector_addr;
        collector_addr.sun_family = AF_UNIX;
        int written = snprintf(collector_addr.sun_path,
                               sizeof(collector_addr.sun_path),
                               "%s",
                               get_cmdarg(&nDPIsrvd_options.collector_un_sockpath));
        if (written < 0)
        {
            logger(1, "snprintf failed: %s", strerror(errno));
            return 1;
        }
        else if (written == sizeof(collector_addr.sun_path))
        {
            logger(1,
                   "Collector UNIX socket path too long, current/max: %zu/%zu",
                   strlen(get_cmdarg(&nDPIsrvd_options.collector_un_sockpath)),
                   sizeof(collector_addr.sun_path) - 1);
            return 1;
        }

        if (bind(collector_un_sockfd, (struct sockaddr *)&collector_addr, sizeof(collector_addr)) < 0)
        {
            logger(1,
                   "Error binding Collector UNIX socket to `%s': %s",
                   get_cmdarg(&nDPIsrvd_options.collector_un_sockpath),
                   strerror(errno));
            return 1;
        }
    }

    {
        struct sockaddr_un distributor_addr;
        distributor_addr.sun_family = AF_UNIX;
        int written = snprintf(distributor_addr.sun_path,
                               sizeof(distributor_addr.sun_path),
                               "%s",
                               get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath));
        if (written < 0)
        {
            logger(1, "snprintf failed: %s", strerror(errno));
            return 2;
        }
        else if (written == sizeof(distributor_addr.sun_path))
        {
            logger(1,
                   "Distributor UNIX socket path too long, current/max: %zu/%zu",
                   strlen(get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath)),
                   sizeof(distributor_addr.sun_path) - 1);
            return 2;
        }

        if (bind(distributor_un_sockfd, (struct sockaddr *)&distributor_addr, sizeof(distributor_addr)) < 0)
        {
            logger(1,
                   "Error binding Distributor socket to `%s': %s",
                   get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath),
                   strerror(errno));
            return 2;
        }
    }

    if (is_cmdarg_set(&nDPIsrvd_options.distributor_in_address) != 0)
    {
        if (bind(distributor_in_sockfd, &distributor_in_address.raw, distributor_in_address.size) < 0)
        {
            logger(1,
                   "Error binding Distributor TCP/IP socket to %s: %s",
                   get_cmdarg(&nDPIsrvd_options.distributor_in_address),
                   strerror(errno));
            return 3;
        }
        if (listen(distributor_in_sockfd, 16) < 0)
        {
            logger(1,
                   "Error listening Distributor TCP/IP socket to %s: %s",
                   get_cmdarg(&nDPIsrvd_options.distributor_in_address),
                   strerror(errno));
            return 3;
        }
        if (fcntl_add_flags(distributor_in_sockfd, O_NONBLOCK) != 0)
        {
            logger(1,
                   "Error setting Distributor TCP/IP socket %s to non-blocking mode: %s",
                   get_cmdarg(&nDPIsrvd_options.distributor_in_address),
                   strerror(errno));
            return 3;
        }
    }

    if (listen(collector_un_sockfd, 16) < 0 || listen(distributor_un_sockfd, 16) < 0)
    {
        logger(1, "Error listening UNIX socket: %s", strerror(errno));
        return 3;
    }

    if (fcntl_add_flags(collector_un_sockfd, O_NONBLOCK) != 0)
    {
        logger(1,
               "Error setting Collector UNIX socket `%s' to non-blocking mode: %s",
               get_cmdarg(&nDPIsrvd_options.collector_un_sockpath),
               strerror(errno));
        return 3;
    }

    if (fcntl_add_flags(distributor_un_sockfd, O_NONBLOCK) != 0)
    {
        logger(1,
               "Error setting Distributor UNIX socket `%s' to non-blocking mode: %s",
               get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath),
               strerror(errno));
        return 3;
    }

    return 0;
}

static struct remote_desc * get_remote_descriptor(enum sock_type type, int remote_fd, size_t max_buffer_size)
{
    if (remotes.desc_used == remotes.desc_size)
    {
        logger(1, "Max number of connections reached: %llu", remotes.desc_used);
        return NULL;
    }

    for (size_t i = 0; i < remotes.desc_size; ++i)
    {
        if (remotes.desc[i].fd == -1)
        {
            remotes.desc_used++;

            struct nDPIsrvd_write_buffer * write_buffer = NULL;
            UT_array ** additional_write_buffers = NULL;

            switch (type)
            {
                case COLLECTOR_UN:
                    if (nDPIsrvd_json_buffer_init(&remotes.desc[i].event_collector_un.main_read_buffer,
                                                  max_buffer_size) != 0)
                    {
                        logger(1, "Read/JSON buffer init failed, size: %zu bytes", max_buffer_size);
                        return NULL;
                    }
                    break;
                case DISTRIBUTOR_UN:
                    write_buffer = &remotes.desc[i].event_distributor_un.main_write_buffer;
                    additional_write_buffers = &remotes.desc[i].event_distributor_un.additional_write_buffers;
                    break;
                case DISTRIBUTOR_IN:
                    write_buffer = &remotes.desc[i].event_distributor_in.main_write_buffer;
                    additional_write_buffers = &remotes.desc[i].event_distributor_in.additional_write_buffers;
                    break;
            }

            if (additional_write_buffers != NULL && *additional_write_buffers == NULL)
            {
                utarray_new(*additional_write_buffers, &nDPIsrvd_buffer_array_icd);
                if (*additional_write_buffers == NULL)
                {
                    logger(1, "%s", "Could not create additional write buffers");
                    return NULL;
                }
            }
            if (write_buffer != NULL && nDPIsrvd_buffer_init(&write_buffer->buf, max_buffer_size) != 0)
            {
                logger(1, "Write buffer init failed, size: %zu bytes", max_buffer_size);
                return NULL;
            }

            remotes.desc[i].sock_type = type;
            remotes.desc[i].fd = remote_fd;
            return &remotes.desc[i];
        }
    }

    logger(1, "%s", "BUG: Unknown error while finding the remote descriptor");
    return NULL;
}

static void free_remote(struct nio * const io, struct remote_desc * remote)
{
    if (remote->fd > -1)
    {
        errno = 0;
        if (del_event(io, remote->fd) != 0)
        {
            logger_nDPIsrvd(remote,
                            "Could not delete event from queue for connection",
                            ": %s",
                            (errno != 0 ? strerror(errno) : "Internal Error"));
        }
        errno = 0;
        close(remote->fd);

        switch (remote->sock_type)
        {
            case COLLECTOR_UN:
                if (errno != 0)
                {
                    logger_nDPIsrvd(remote, "Error closing collector connection", ": %s", strerror(errno));
                }
                nDPIsrvd_json_buffer_free(&remote->event_collector_un.main_read_buffer);
                break;
            case DISTRIBUTOR_UN:
                if (errno != 0)
                {
                    logger_nDPIsrvd(remote, "Error closing distributor connection", ": %s", strerror(errno));
                }
                if (remote->event_distributor_un.additional_write_buffers != NULL)
                {
                    utarray_free(remote->event_distributor_un.additional_write_buffers);
                }
                nDPIsrvd_buffer_free(&remote->event_distributor_un.main_write_buffer.buf);
#if !defined(__FreeBSD__) && !defined(__APPLE__)
                free(remote->event_distributor_un.user_name);
#endif
                break;
            case DISTRIBUTOR_IN:
                if (errno != 0)
                {
                    logger_nDPIsrvd(remote, "Error closing distributor connection", ": %s", strerror(errno));
                }
                if (remote->event_distributor_in.additional_write_buffers != NULL)
                {
                    utarray_free(remote->event_distributor_in.additional_write_buffers);
                }
                nDPIsrvd_buffer_free(&remote->event_distributor_in.main_write_buffer.buf);
                break;
        }

        memset(remote, 0, sizeof(*remote));
        remote->fd = -1;
        remotes.desc_used--;
    }
}

static void free_remotes(struct nio * const io)
{
    for (size_t i = 0; i < remotes.desc_size; ++i)
    {
        free_remote(io, &remotes.desc[i]);
    }
    nDPIsrvd_free(remotes.desc);
    remotes.desc = NULL;
    remotes.desc_used = 0;
    remotes.desc_size = 0;
}

static int add_in_event_fd(struct nio * const io, int fd)
{
    return nio_add_fd(io, fd, NIO_EVENT_INPUT, NULL) != NIO_SUCCESS;
}

static int add_in_event(struct nio * const io, struct remote_desc * const remote)
{
    return nio_add_fd(io, remote->fd, NIO_EVENT_INPUT, remote) != NIO_SUCCESS;
}

static int set_out_event(struct nio * const io, struct remote_desc * const remote)
{
    return nio_mod_fd(io, remote->fd, NIO_EVENT_OUTPUT, remote) != NIO_SUCCESS;
}

static int set_in_event(struct nio * const io, struct remote_desc * const remote)
{
    return nio_mod_fd(io, remote->fd, NIO_EVENT_INPUT, remote) != NIO_SUCCESS;
}

static int del_event(struct nio * const io, int fd)
{
    return nio_del_fd(io, fd) != NIO_SUCCESS;
}

static void disconnect_client(struct nio * const io, struct remote_desc * const remote)
{
    free_remote(io, remote);
}

static int nDPIsrvd_parse_options(int argc, char ** argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "lL:c:dp:s:S:m:u:g:C:Dvh")) != -1)
    {
        switch (opt)
        {
            case 'l':
                enable_console_logger();
                break;
            case 'L':
                if (enable_file_logger(optarg) != 0)
                {
                    return 1;
                }
                break;
            case 'c':
                set_cmdarg(&nDPIsrvd_options.collector_un_sockpath, optarg);
                break;
            case 'e':
#ifdef ENABLE_EPOLL
                nDPIsrvd_options.use_poll = 1;
#else
                logger_early(1, "%s", "nDPIsrvd was built w/o epoll() support, poll() is already the default");
#endif
                break;
            case 'd':
                daemonize_enable();
                break;
            case 'p':
                set_cmdarg(&nDPIsrvd_options.pidfile, optarg);
                break;
            case 's':
                set_cmdarg(&nDPIsrvd_options.distributor_un_sockpath, optarg);
                break;
            case 'S':
                set_cmdarg(&nDPIsrvd_options.distributor_in_address, optarg);
                break;
            case 'm':
                if (str_value_to_ull(optarg, &nDPIsrvd_options.max_remote_descriptors) != CONVERSION_OK)
                {
                    fprintf(stderr, "%s: Argument for `-C' is not a number: %s\n", argv[0], optarg);
                    return 1;
                }
                break;
            case 'u':
                set_cmdarg(&nDPIsrvd_options.user, optarg);
                break;
            case 'g':
                set_cmdarg(&nDPIsrvd_options.group, optarg);
                break;
            case 'C':
                if (str_value_to_ull(optarg, &nDPIsrvd_options.max_write_buffers) != CONVERSION_OK)
                {
                    fprintf(stderr, "%s: Argument for `-C' is not a number: %s\n", argv[0], optarg);
                    return 1;
                }
                break;
            case 'D':
                nDPIsrvd_options.bufferbloat_fallback_to_blocking = 0;
                break;
            case 'v':
                fprintf(stderr, "%s", get_nDPId_version());
                return 1;
            case 'h':
            default:
                fprintf(stderr, "%s\n", get_nDPId_version());
                fprintf(stderr,
                        "Usage: %s [-l] [-L logfile] [-c path-to-unix-sock] [-e] [-d] [-p pidfile]\n"
                        "\t[-s path-to-distributor-unix-socket] [-S distributor-host:port]\n"
                        "\t[-m max-remote-descriptors] [-u user] [-g group]\n"
                        "\t[-C max-buffered-json-lines] [-D]\n"
                        "\t[-v] [-h]\n\n"
                        "\t-l\tLog all messages to stderr.\n"
                        "\t-L\tLog all messages to a log file.\n"
                        "\t-c\tPath to a listening UNIX socket (nDPIsrvd Collector).\n"
                        "\t  \tDefault: %s\n"
                        "\t-e\tUse poll() instead of epoll().\n"
                        "\t  \tDefault: epoll() on Linux, poll() otherwise\n"
                        "\t-d\tFork into background after initialization.\n"
                        "\t-p\tWrite the daemon PID to the given file path.\n"
                        "\t  \tDefault: %s\n"
                        "\t-m\tMax accepted (Collector and Distributor) clients.\n"
                        "\t-u\tChange UID to the numeric value of user.\n"
                        "\t  \tDefault: %s\n"
                        "\t-g\tChange GID to the numeric value of group.\n"
                        "\t-C\tMax buffered JSON lines before nDPIsrvd disconnects/blocking-IO a client.\n"
                        "\t-D\tDisconnect a slow client instead of falling back to blocking-IO.\n"
                        "\t-s\tPath to a listening UNIX socket (nDPIsrvd Distributor).\n"
                        "\t  \tDefault: %s\n"
                        "\t-S\tAddress:Port of the listening TCP/IP socket (nDPIsrvd Distributor).\n"
                        "\t-v\tversion\n"
                        "\t-h\tthis\n\n",
                        argv[0],
                        get_cmdarg(&nDPIsrvd_options.collector_un_sockpath),
                        get_cmdarg(&nDPIsrvd_options.pidfile),
                        get_cmdarg(&nDPIsrvd_options.user),
                        get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath));
                return 1;
        }
    }

    if (is_path_absolute("Pidfile", get_cmdarg(&nDPIsrvd_options.pidfile)) != 0)
    {
        return 1;
    }

    if (is_path_absolute("Collector UNIX socket", get_cmdarg(&nDPIsrvd_options.collector_un_sockpath)) != 0)
    {
        return 1;
    }

    if (is_path_absolute("Distributor UNIX socket", get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath)) != 0)
    {
        return 1;
    }

    if (is_cmdarg_set(&nDPIsrvd_options.distributor_in_address) != 0)
    {
        if (nDPIsrvd_setup_address(&distributor_in_address, get_cmdarg(&nDPIsrvd_options.distributor_in_address)) != 0)
        {
            logger_early(1,
                         "%s: Could not parse address %s",
                         argv[0],
                         get_cmdarg(&nDPIsrvd_options.distributor_in_address));
            return 1;
        }
        if (distributor_in_address.raw.sa_family == AF_UNIX)
        {
            logger_early(1,
                         "%s: You've requested to setup another UNIX socket `%s', but there is already one at `%s'",
                         argv[0],
                         get_cmdarg(&nDPIsrvd_options.distributor_in_address),
                         get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath));
            return 1;
        }
    }

    if (optind < argc)
    {
        logger_early(1, "%s: Unexpected argument after options", argv[0]);
        return 1;
    }

    return 0;
}

static struct remote_desc * accept_remote(int server_fd,
                                          enum sock_type socktype,
                                          struct sockaddr * const sockaddr,
                                          socklen_t * const addrlen)
{
    int client_fd;

    while ((client_fd = accept(server_fd, sockaddr, addrlen)) < 0 && errno == EINTR) {}
    if (client_fd < 0 || set_fd_cloexec(client_fd) < 0)
    {
        logger(1, "Accept failed: %s", strerror(errno));
        return NULL;
    }

    struct remote_desc * current = get_remote_descriptor(socktype, client_fd, NETWORK_BUFFER_MAX_SIZE);
    if (current == NULL)
    {
        return NULL;
    }

    return current;
}

static int new_connection(struct nio * const io, int eventfd)
{
    union
    {
        struct sockaddr_un saddr_collector_un;
        struct sockaddr_un saddr_distributor_un;
        struct sockaddr_in saddr_distributor_in;
    } sockaddr;

    socklen_t peer_addr_len;
    enum sock_type stype;
    int server_fd;
    if (eventfd == collector_un_sockfd)
    {
        peer_addr_len = sizeof(sockaddr.saddr_collector_un);
        stype = COLLECTOR_UN;
        server_fd = collector_un_sockfd;
    }
    else if (eventfd == distributor_un_sockfd)
    {
        peer_addr_len = sizeof(sockaddr.saddr_distributor_un);
        stype = DISTRIBUTOR_UN;
        server_fd = distributor_un_sockfd;
    }
    else if (eventfd == distributor_in_sockfd)
    {
        peer_addr_len = sizeof(sockaddr.saddr_distributor_in);
        stype = DISTRIBUTOR_IN;
        server_fd = distributor_in_sockfd;
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

    int sockopt;
    switch (current->sock_type)
    {
        case COLLECTOR_UN:
            current->event_collector_un.peer = sockaddr.saddr_collector_un;
            current->event_collector_un.json_bytes = 0;

            sockopt = NETWORK_BUFFER_MAX_SIZE;
            if (setsockopt(current->fd, SOL_SOCKET, SO_RCVBUF, &sockopt, sizeof(sockopt)) < 0)
            {
                logger(1, "Error setting socket option SO_RCVBUF: %s", strerror(errno));
                return 1;
            }

#if !defined(__FreeBSD__) && !defined(__APPLE__)
            struct ucred ucred = {};
            socklen_t ucred_len = sizeof(ucred);
            if (getsockopt(current->fd, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1)
            {
                logger(1, "Error getting credentials from UNIX socket: %s", strerror(errno));
                return 1;
            }
            current->event_collector_un.pid = ucred.pid;
#endif

            logger_nDPIsrvd(current, "New collector connection from", "");
            break;
        case DISTRIBUTOR_UN:
        case DISTRIBUTOR_IN:
            if (current->sock_type == DISTRIBUTOR_UN)
            {
                current->event_distributor_un.peer = sockaddr.saddr_distributor_un;

#if !defined(__FreeBSD__) && !defined(__APPLE__)
                struct ucred ucred = {};
                socklen_t ucred_len = sizeof(ucred);
                if (getsockopt(current->fd, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1)
                {
                    logger(1, "Error getting credentials from UNIX socket: %s", strerror(errno));
                    return 1;
                }

                struct passwd pwnam = {};
                struct passwd * pwres = NULL;
                ssize_t pwsiz = sysconf(_SC_GETPW_R_SIZE_MAX);
                if (pwsiz == -1)
                {
                    pwsiz = BUFSIZ;
                }
                char buf[pwsiz];
                if (getpwuid_r(ucred.uid, &pwnam, &buf[0], pwsiz, &pwres) != 0)
                {
                    logger(1, "Could not get passwd entry for user id %u", ucred.uid);
                    return 1;
                }

                current->event_distributor_un.pid = ucred.pid;
                current->event_distributor_un.user_name = strdup(pwres->pw_name);
#endif
            }
            else
            {
                current->event_distributor_in.peer = sockaddr.saddr_distributor_in;

                sockopt = 1;
                if (setsockopt(current->fd, SOL_SOCKET, SO_RCVBUF, &sockopt, sizeof(sockopt)) < 0)
                {
                    logger(1, "Error setting socket option SO_RCVBUF: %s", strerror(errno));
                    return 1;
                }

                if (inet_ntop(current->event_distributor_in.peer.sin_family,
                              &current->event_distributor_in.peer.sin_addr,
                              &current->event_distributor_in.peer_addr[0],
                              sizeof(current->event_distributor_in.peer_addr)) == NULL)
                {
                    logger(1, "Error converting an internet address: %s", strerror(errno));
                    return 1;
                }
            }

            sockopt = NETWORK_BUFFER_MAX_SIZE;
            if (setsockopt(current->fd, SOL_SOCKET, SO_SNDBUF, &sockopt, sizeof(sockopt)) < 0)
            {
                logger(1, "Error setting socket option SO_SNDBUF: %s", strerror(errno));
                return 1;
            }

            {
                struct timeval send_timeout = {1, 0};
                if (setsockopt(current->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&send_timeout, sizeof(send_timeout)) != 0)
                {
                    logger(1, "Error setting socket option send timeout: %s", strerror(errno));
                }
            }

            logger_nDPIsrvd(current, "New distributor connection from", "");
            break;
    }

    /* nonblocking fd is mandatory */
    if (fcntl_add_flags(current->fd, O_NONBLOCK) != 0)
    {
        logger(1, "Error setting fd flags to non-blocking mode: %s", strerror(errno));
        disconnect_client(io, current);
        return 1;
    }

    /* shutdown writing end for collector clients */
    if (current->sock_type == COLLECTOR_UN)
    {
        shutdown(current->fd, SHUT_WR); // collector
        /* shutdown reading end for distributor clients does not work due to epoll usage */
    }

    /* setup event I/O */
    errno = 0;
    if (add_in_event(io, current) != NIO_SUCCESS)
    {
        logger(1, "Error adding input event to %d: %s", current->fd, (errno != 0 ? strerror(errno) : "Internal Error"));
        disconnect_client(io, current);
        return 1;
    }

    return 0;
}

static int handle_collector_protocol(struct nio * const io, struct remote_desc * const current)
{
    struct nDPIsrvd_json_buffer * const json_read_buffer = get_read_buffer(current);
    char * json_str_start = NULL;

    if (json_read_buffer == NULL)
    {
        return 1;
    }

    if (json_read_buffer->buf.ptr.text[NETWORK_BUFFER_LENGTH_DIGITS] != '{')
    {
        logger_nDPIsrvd(current,
                        "BUG: Collector connection",
                        "JSON invalid opening character: '%c'",
                        json_read_buffer->buf.ptr.text[NETWORK_BUFFER_LENGTH_DIGITS]);
        disconnect_client(io, current);
        return 1;
    }

    errno = 0;
    current->event_collector_un.json_bytes = strtoull(json_read_buffer->buf.ptr.text, &json_str_start, 10);
    current->event_collector_un.json_bytes += json_str_start - json_read_buffer->buf.ptr.text;

    if (errno == ERANGE)
    {
        logger_nDPIsrvd(current, "BUG: Collector connection", "JSON string length exceeds numceric limits");
        disconnect_client(io, current);
        return 1;
    }

    if (json_str_start == json_read_buffer->buf.ptr.text)
    {
        logger_nDPIsrvd(current,
                        "BUG: Collector connection",
                        "missing JSON string length in protocol preamble: \"%.*s\"",
                        NETWORK_BUFFER_LENGTH_DIGITS,
                        json_read_buffer->buf.ptr.text);
        disconnect_client(io, current);
        return 1;
    }

    if (json_str_start - json_read_buffer->buf.ptr.text != NETWORK_BUFFER_LENGTH_DIGITS)
    {
        logger_nDPIsrvd(current,
                        "BUG: Collector connection",
                        "invalid collector protocol data received. Expected protocol preamble of size %u bytes, got "
                        "%ld "
                        "bytes",
                        NETWORK_BUFFER_LENGTH_DIGITS,
                        (long int)(json_str_start - json_read_buffer->buf.ptr.text));
    }

    if (current->event_collector_un.json_bytes > json_read_buffer->buf.max)
    {
        logger_nDPIsrvd(current,
                        "BUG: Collector connection",
                        "JSON string too big: %llu > %zu",
                        current->event_collector_un.json_bytes,
                        json_read_buffer->buf.max);
        disconnect_client(io, current);
        return 1;
    }

    if (current->event_collector_un.json_bytes > json_read_buffer->buf.used)
    {
        return 1;
    }

    if (json_read_buffer->buf.ptr.text[current->event_collector_un.json_bytes - 2] != '}' ||
        json_read_buffer->buf.ptr.text[current->event_collector_un.json_bytes - 1] != '\n')
    {
        logger_nDPIsrvd(current,
                        "BUG: Collector connection",
                        "invalid JSON string: %.*s...",
                        (int)current->event_collector_un.json_bytes > 512 ? 512
                                                                          : (int)current->event_collector_un.json_bytes,
                        json_read_buffer->buf.ptr.text);
        disconnect_client(io, current);
        return 1;
    }

    return 0;
}

static int handle_incoming_data(struct nio * const io, struct remote_desc * const current)
{
    struct nDPIsrvd_json_buffer * const json_read_buffer = get_read_buffer(current);

    if (json_read_buffer == NULL)
    {
        unsigned char garbage = 0;

        if (read(current->fd, &garbage, sizeof(garbage)) == sizeof(garbage))
        {
            logger_nDPIsrvd(current, "Received data from", "who is not allowed to send us some.");
        }
        else
        {
            logger_nDPIsrvd(current, "Distributor connection", "closed");
        }
        disconnect_client(io, current);
        return 1;
    }

    /* read JSON strings (or parts) from the UNIX socket (collecting) */
    if (json_read_buffer->buf.used == json_read_buffer->buf.max)
    {
        logger_nDPIsrvd(current,
                        "Collector connection",
                        "read buffer (%zu bytes) full. No more read possible.",
                        json_read_buffer->buf.max);
    }
    else
    {
        errno = 0;
        ssize_t bytes_read;

        while ((bytes_read = read(current->fd,
                                  json_read_buffer->buf.ptr.raw + json_read_buffer->buf.used,
                                  json_read_buffer->buf.max - json_read_buffer->buf.used)) < 0 &&
               errno == EINTR)
        {
        }
        if (bytes_read < 0 || errno != 0)
        {
            logger_nDPIsrvd(current, "Could not read remote", ": %s", strerror(errno));
            disconnect_client(io, current);
            return 1;
        }
        if (bytes_read == 0)
        {
            logger_nDPIsrvd(current, "Collector connection", "closed during read");
            disconnect_client(io, current);
            return 1;
        }
        json_read_buffer->buf.used += bytes_read;
    }

    while (json_read_buffer->buf.used >= NETWORK_BUFFER_LENGTH_DIGITS + 1)
    {
        if (handle_collector_protocol(io, current) != 0)
        {
            break;
        }

        for (size_t i = 0; i < remotes.desc_size; ++i)
        {
            struct nDPIsrvd_write_buffer * const write_buffer = get_write_buffer(&remotes.desc[i]);
            UT_array * const additional_write_buffers = get_additional_write_buffers(&remotes.desc[i]);

            if (remotes.desc[i].fd < 0 || write_buffer == NULL || additional_write_buffers == NULL)
            {
                continue;
            }

            if (current->event_collector_un.json_bytes > write_buffer->buf.max - write_buffer->buf.used ||
                utarray_len(additional_write_buffers) > 0)
            {
                if (utarray_len(additional_write_buffers) == 0)
                {
                    errno = 0;
                    if (set_out_event(io, &remotes.desc[i]) != 0)
                    {
                        logger_nDPIsrvd(&remotes.desc[i],
                                        "Could not add event to",
                                        ", disconnecting: %s",
                                        (errno != 0 ? strerror(errno) : "Internal Error"));
                        disconnect_client(io, &remotes.desc[i]);
                        continue;
                    }
                }
                if (add_to_additional_write_buffers(&remotes.desc[i],
                                                    json_read_buffer->buf.ptr.raw,
                                                    current->event_collector_un.json_bytes) != 0)
                {
                    disconnect_client(io, &remotes.desc[i]);
                    continue;
                }
            }
            else
            {
                memcpy(write_buffer->buf.ptr.raw + write_buffer->buf.used,
                       json_read_buffer->buf.ptr.raw,
                       current->event_collector_un.json_bytes);
                write_buffer->buf.used += current->event_collector_un.json_bytes;
            }

            if (drain_main_buffer(&remotes.desc[i]) != 0)
            {
                disconnect_client(io, &remotes.desc[i]);
            }
        }

        memmove(json_read_buffer->buf.ptr.raw,
                json_read_buffer->buf.ptr.raw + current->event_collector_un.json_bytes,
                json_read_buffer->buf.used - current->event_collector_un.json_bytes);
        json_read_buffer->buf.used -= current->event_collector_un.json_bytes;
        current->event_collector_un.json_bytes = 0;
    }

    return 0;
}

static int handle_data_event(struct nio * const io, int index)
{
    struct remote_desc * const current = (struct remote_desc *)nio_get_ptr(io, index);

    if (nio_has_input(io, index) != NIO_SUCCESS && nio_can_output(io, index) != NIO_SUCCESS)
    {
        logger(1, "%s", "Neither input nor output event set.");
        return 1;
    }

    if (current == NULL)
    {
        logger(1, "%s", "Remote descriptor got from event data invalid.");
        return 1;
    }

    if (current->fd < 0)
    {
        logger(1, "File descriptor `%d' got from event data invalid.", current->fd);
        return 1;
    }

    if (nio_has_input(io, index) == NIO_SUCCESS)
    {
        return handle_incoming_data(io, current);
    }
    else
    {
        return handle_outgoing_data(io, current);
    }
}

#if !defined(__FreeBSD__) && !defined(__APPLE__)
static int setup_signalfd(struct nio * const io)
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

    if (add_in_event_fd(io, sfd) != 0)
    {
        return -1;
    }

    if (fcntl_add_flags(sfd, O_NONBLOCK) != 0)
    {
        return -1;
    }

    return sfd;
}
#endif

static int mainloop(struct nio * const io)
{
#if !defined(__FreeBSD__) && !defined(__APPLE__)
    int signalfd = setup_signalfd(io);
#endif

    while (nDPIsrvd_main_thread_shutdown == 0)
    {
        if (nio_run(io, 1000) != NIO_SUCCESS)
        {
            logger(1, "Event I/O returned error: %s", strerror(errno));
        }

        int nready = nio_get_nready(io);

        for (int i = 0; i < nready; i++)
        {
            int fd = nio_get_fd(io, i);

            if (nio_has_error(io, i) == NIO_SUCCESS)
            {
                if (fd != collector_un_sockfd && fd != distributor_un_sockfd && fd != distributor_in_sockfd)
                {
                    struct remote_desc * const current = (struct remote_desc *)nio_get_ptr(io, i);
                    switch (current->sock_type)
                    {
                        case COLLECTOR_UN:
                            logger_nDPIsrvd(current, "Collector connection", "closed");
                            break;
                        case DISTRIBUTOR_UN:
                        case DISTRIBUTOR_IN:
                            logger_nDPIsrvd(current, "Distributor connection", "closed");
                            break;
                    }
                    disconnect_client(io, current);
                }
                else
                {
                    logger(1, "Event I/O error: %s", (errno != 0 ? strerror(errno) : "unknown"));
                }
                break;
            }

            if (fd == collector_un_sockfd || fd == distributor_un_sockfd || fd == distributor_in_sockfd)
            {
                /* New connection to collector / distributor. */
                if (new_connection(io, fd) != 0)
                {
                    continue;
                }
            }
#if !defined(__FreeBSD__) && !defined(__APPLE__)
            else if (fd == signalfd)
            {
                struct signalfd_siginfo fdsi;
                ssize_t s;

                s = read(signalfd, &fdsi, sizeof(struct signalfd_siginfo));
                if (s != sizeof(struct signalfd_siginfo))
                {
                    if (s < 0)
                    {
                        logger(1, "Read from signal fd returned: %s", strerror(errno));
                        nDPIsrvd_main_thread_shutdown = 1;
                    }
                    else
                    {
                        logger(1,
                               "Invalid signal fd read size. Got %zd, wanted %zu bytes.",
                               s,
                               sizeof(struct signalfd_siginfo));
                    }
                    continue;
                }

                if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGQUIT)
                {
                    nDPIsrvd_main_thread_shutdown = 1;
                    continue;
                }
            }
#endif
            else
            {
                /* Incoming data / Outoing data ready to receive / send. */
                if (handle_data_event(io, i) != 0)
                {
                    /* do nothing */
                }
            }
        }
    }

    free_remotes(io);
    nio_free(io);
#if !defined(__FreeBSD__) && !defined(__APPLE__)
    close(signalfd);
#endif

    return 0;
}

static int setup_event_queue(struct nio * const io)
{
#ifdef ENABLE_EPOLL
    if ((nDPIsrvd_options.use_poll == 0 && nio_use_epoll(io, 32) != NIO_SUCCESS)
        || (nDPIsrvd_options.use_poll != 0 && nio_use_poll(io, nDPIsrvd_MAX_REMOTE_DESCRIPTORS) != NIO_SUCCESS))
#else
    if (nio_use_poll(io, nDPIsrvd_MAX_REMOTE_DESCRIPTORS) != NIO_SUCCESS)
#endif
    {
        logger(1, "%s", "Event I/O poll/epoll setup failed");
        return -1;
    }

    errno = 0;
    if (add_in_event_fd(io, collector_un_sockfd) != 0)
    {
        logger(1,
               "Error adding collector UNIX socket fd to event I/O: %s",
               (errno != 0 ? strerror(errno) : "Internal Error"));
        return -1;
    }

    errno = 0;
    if (add_in_event_fd(io, distributor_un_sockfd) != 0)
    {
        logger(1,
               "Error adding distributor UNIX socket fd to event I/O: %s",
               (errno != 0 ? strerror(errno) : "Internal Error"));
        return -1;
    }

    if (distributor_in_sockfd >= 0)
    {
        errno = 0;
        if (add_in_event_fd(io, distributor_in_sockfd) != 0)
        {
            logger(1,
                   "Error adding distributor TCP/IP socket fd to event I/O: %s",
                   (errno != 0 ? strerror(errno) : "Internal Error"));
            return -1;
        }
    }

    return 0;
}

static int setup_remote_descriptors(nDPIsrvd_ull max_remote_descriptors)
{
    remotes.desc_used = 0;
    remotes.desc_size = max_remote_descriptors;
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
    struct nio io;

    if (argc == 0)
    {
        return 1;
    }

    nio_init(&io);
    init_logging("nDPIsrvd");

    if (nDPIsrvd_parse_options(argc, argv) != 0)
    {
        return 1;
    }

    if (is_daemonize_enabled() != 0 && is_console_logger_enabled() != 0)
    {
        logger_early(1,
                     "%s",
                     "Daemon mode `-d' and `-l' can not be used together, "
                     "because stdout/stderr is beeing redirected to /dev/null");
        return 1;
    }

    if (access(get_cmdarg(&nDPIsrvd_options.collector_un_sockpath), F_OK) == 0)
    {
        logger_early(1,
                     "UNIX socket `%s' exists; nDPIsrvd already running? "
                     "Please remove the socket manually or change socket path.",
                     get_cmdarg(&nDPIsrvd_options.collector_un_sockpath));
        return 1;
    }

    if (access(get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath), F_OK) == 0)
    {
        logger_early(1,
                     "UNIX socket `%s' exists; nDPIsrvd already running? "
                     "Please remove the socket manually or change socket path.",
                     get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath));
        return 1;
    }

    log_app_info();

    if (daemonize_with_pidfile(get_cmdarg(&nDPIsrvd_options.pidfile)) != 0)
    {
        goto error;
    }

    if (setup_remote_descriptors(nDPIsrvd_options.max_remote_descriptors) != 0)
    {
        goto error;
    }

    switch (create_listen_sockets())
    {
        case 0:
            break;
        case 1:
            goto error;
        case 2:
            if (unlink(get_cmdarg(&nDPIsrvd_options.collector_un_sockpath)) != 0)
            {
                logger(1,
                       "Could not unlink `%s': %s",
                       get_cmdarg(&nDPIsrvd_options.collector_un_sockpath),
                       strerror(errno));
            }
            goto error;
        case 3:
            goto error_unlink_sockets;
        default:
            goto error;
    }

    logger(0, "collector UNIX socket listen on `%s'", get_cmdarg(&nDPIsrvd_options.collector_un_sockpath));
    logger(0, "distributor UNIX listen on `%s'", get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath));
    switch (distributor_in_address.raw.sa_family)
    {
        default:
            goto error_unlink_sockets;
        case AF_INET:
        case AF_INET6:
            logger(1,
                   "Please keep in mind that using a TCP Socket may leak sensitive information to "
                   "everyone with access to the device/network. You've been warned!");
            break;
        case AF_UNIX:
        case (sa_family_t)0xFFFF:
            break;
    }

    errno = 0;
    if (change_user_group(get_cmdarg(&nDPIsrvd_options.user),
                          get_cmdarg(&nDPIsrvd_options.group),
                          get_cmdarg(&nDPIsrvd_options.pidfile),
                          get_cmdarg(&nDPIsrvd_options.collector_un_sockpath),
                          get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath)) != 0 &&
        errno != EPERM)
    {
        if (errno != 0)
        {
            logger(1,
                   "Change user/group to %s/%s failed: %s",
                   get_cmdarg(&nDPIsrvd_options.user),
                   (is_cmdarg_set(&nDPIsrvd_options.group) != 0 ? get_cmdarg(&nDPIsrvd_options.group) : "-"),
                   strerror(errno));
        }
        else
        {
            logger(1,
                   "Change user/group to %s/%s failed.",
                   get_cmdarg(&nDPIsrvd_options.user),
                   (is_cmdarg_set(&nDPIsrvd_options.group) != 0 ? get_cmdarg(&nDPIsrvd_options.group) : "-"));
        }
        goto error_unlink_sockets;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    if (setup_event_queue(&io) != 0)
    {
        goto error_unlink_sockets;
    }

    retval = mainloop(&io);

error_unlink_sockets:
    if (unlink(get_cmdarg(&nDPIsrvd_options.collector_un_sockpath)) != 0)
    {
        logger(1, "Could not unlink `%s': %s", get_cmdarg(&nDPIsrvd_options.collector_un_sockpath), strerror(errno));
    }
    if (unlink(get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath)) != 0)
    {
        logger(1, "Could not unlink `%s': %s", get_cmdarg(&nDPIsrvd_options.distributor_un_sockpath), strerror(errno));
    }
error:
    close(collector_un_sockfd);
    close(distributor_un_sockfd);
    close(distributor_in_sockfd);

    daemonize_shutdown(get_cmdarg(&nDPIsrvd_options.pidfile));
    logger(0, "Bye.");
    shutdown_logging();

    return retval;
}
#endif
