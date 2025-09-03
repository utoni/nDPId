#ifndef NIO_H
#define NIO_H 1

#include <poll.h>

#define WARN_UNUSED __attribute__((__warn_unused_result__))

enum
{
    NIO_SUCCESS = 0,
    NIO_ERROR_INTERNAL = 1,
    NIO_ERROR_SYSTEM = -1
};

enum
{
    NIO_EVENT_INVALID = 0,
    NIO_EVENT_INPUT = 1,
    NIO_EVENT_OUTPUT = 2,
    NIO_EVENT_ERROR = 4,
};

struct nio
{
    int nready;

    nfds_t poll_max_fds;
    struct pollfd * poll_fds;
    void ** poll_ptrs;
    nfds_t * poll_fds_set;

    int epoll_fd;
    int max_events;
    void * events;
};

void nio_init(struct nio * io);

WARN_UNUSED
int nio_use_poll(struct nio * io, nfds_t max_fds);

WARN_UNUSED
int nio_use_epoll(struct nio * io, int max_events);

WARN_UNUSED
int nio_add_fd(struct nio * io, int fd, int event_flags, void * ptr);

WARN_UNUSED
int nio_mod_fd(struct nio * io, int fd, int event_flags, void * ptr);

WARN_UNUSED
int nio_del_fd(struct nio * io, int fd);

WARN_UNUSED
int nio_run(struct nio * io, int timeout);

WARN_UNUSED
static inline int nio_get_nready(struct nio const * const io)
{
    return io->nready;
}

WARN_UNUSED
int nio_check(struct nio * io, int index, int events);

WARN_UNUSED
int nio_is_valid(struct nio const * const io, int index);

WARN_UNUSED
int nio_get_fd(struct nio * io, int index);

WARN_UNUSED
void * nio_get_ptr(struct nio * io, int index);

WARN_UNUSED
static inline int nio_has_input(struct nio * io, int index)
{
    return nio_check(io, index, NIO_EVENT_INPUT);
}

WARN_UNUSED
static inline int nio_can_output(struct nio * io, int index)
{
    return nio_check(io, index, NIO_EVENT_OUTPUT);
}

WARN_UNUSED
static inline int nio_has_error(struct nio * io, int index)
{
    return nio_check(io, index, NIO_EVENT_ERROR);
}

void nio_free(struct nio * io);

#endif
