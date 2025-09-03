#include "nio.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef ENABLE_EPOLL
#include <sys/epoll.h>
#endif
#include <unistd.h>

void nio_init(struct nio * io)
{
    io->nready = -1;
    io->poll_max_fds = 0;
    io->poll_fds = NULL;
    io->poll_ptrs = NULL;
    io->poll_fds_set = NULL;
    io->epoll_fd = -1;
    io->max_events = 0;
    io->events = NULL;
}

int nio_use_poll(struct nio * io, nfds_t max_fds)
{
    if (io->epoll_fd != -1 || io->poll_max_fds != 0 || max_fds <= 0)
        return NIO_ERROR_INTERNAL;

    io->poll_max_fds = max_fds;
    io->poll_fds = (struct pollfd *)calloc(max_fds, sizeof(*io->poll_fds));
    io->poll_ptrs = calloc(max_fds, sizeof(*io->poll_ptrs));
    io->poll_fds_set = calloc(max_fds, sizeof(*io->poll_fds_set));

    for (size_t i = 0; i < max_fds; ++i)
    {
        io->poll_fds[i].fd = -1;
    }

    return io->poll_fds == NULL || io->poll_ptrs == NULL || io->poll_fds_set == NULL; // return NIO_ERROR_INTERNAL on
                                                                                      // error
}

int nio_use_epoll(struct nio * io, int max_events)
{
#ifdef ENABLE_EPOLL
    if (io->epoll_fd != -1 || io->poll_max_fds != 0 || max_events == 0)
        return NIO_ERROR_INTERNAL;

    io->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    io->max_events = max_events;
    io->events = calloc(max_events, sizeof(struct epoll_event));

    return io->events == NULL || io->epoll_fd < 0; // return NIO_ERROR_INTERNAL on error
#else
    (void)io;
    (void)max_events;

    return NIO_ERROR_INTERNAL;
#endif
}

int nio_add_fd(struct nio * io, int fd, int event_flags, void * ptr)
{
    if (fd < 0)
        return NIO_ERROR_INTERNAL;

#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        int rv;
        struct epoll_event event = {};

        if (ptr == NULL)
        {
            event.data.fd = fd;
        }
        else
        {
            event.data.ptr = ptr;
        }

        if ((event_flags & NIO_EVENT_INPUT) != 0)
            event.events |= EPOLLIN;
        if ((event_flags & NIO_EVENT_OUTPUT) != 0)
            event.events |= EPOLLOUT;
        if (event.events == 0)
            return NIO_ERROR_INTERNAL;

        while ((rv = epoll_ctl(io->epoll_fd, EPOLL_CTL_ADD, fd, &event)) != 0 && errno == EINTR)
        {
            /* If epoll_ctl() was interrupted by the system, repeat. */
        }
        return rv;
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        struct pollfd * unused_pollfd = NULL;
        void ** unused_ptr = NULL;

        for (size_t i = 0; i < io->poll_max_fds; ++i)
        {
            if (io->poll_fds[i].fd < 0)
            {
                unused_pollfd = &io->poll_fds[i];
                unused_ptr = &io->poll_ptrs[i];
                break;
            }
        }
        if (unused_pollfd == NULL)
            return NIO_ERROR_INTERNAL;

        unused_pollfd->events = 0;
        if ((event_flags & NIO_EVENT_INPUT) != 0)
            unused_pollfd->events |= POLLIN;
        if ((event_flags & NIO_EVENT_OUTPUT) != 0)
            unused_pollfd->events |= POLLOUT;
        if (unused_pollfd->events == 0)
            return NIO_ERROR_INTERNAL;

        unused_pollfd->fd = fd;
        *unused_ptr = ptr;

        return NIO_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_mod_fd(struct nio * io, int fd, int event_flags, void * ptr)
{
    if (fd < 0)
        return NIO_ERROR_INTERNAL;

#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        int rv;
        struct epoll_event event = {};

        if (ptr == NULL)
        {
            event.data.fd = fd;
        }
        else
        {
            event.data.ptr = ptr;
        }

        if ((event_flags & NIO_EVENT_INPUT) != 0)
            event.events |= EPOLLIN;
        if ((event_flags & NIO_EVENT_OUTPUT) != 0)
            event.events |= EPOLLOUT;
        if (event.events == 0)
            return NIO_ERROR_INTERNAL;

        while ((rv = epoll_ctl(io->epoll_fd, EPOLL_CTL_MOD, fd, &event)) != 0 && errno == EINTR)
        {
            /* If epoll_ctl() was interrupted by the system, repeat. */
        }
        return rv;
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        struct pollfd * used_pollfd = NULL;
        void ** used_ptr = NULL;

        for (size_t i = 0; i < io->poll_max_fds; ++i)
        {
            if (io->poll_fds[i].fd == fd)
            {
                used_pollfd = &io->poll_fds[i];
                used_ptr = &io->poll_ptrs[i];
                break;
            }
        }
        if (used_pollfd == NULL)
            return NIO_ERROR_INTERNAL;

        used_pollfd->events = 0;
        if ((event_flags & NIO_EVENT_INPUT) != 0)
            used_pollfd->events |= POLLIN;
        if ((event_flags & NIO_EVENT_OUTPUT) != 0)
            used_pollfd->events |= POLLOUT;
        if (used_pollfd->events == 0)
            return NIO_ERROR_INTERNAL;

        used_pollfd->fd = fd;
        *used_ptr = ptr;

        return NIO_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_del_fd(struct nio * io, int fd)
{
    if (fd < 0)
        return NIO_ERROR_INTERNAL;

#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        int rv;

        while ((rv = epoll_ctl(io->epoll_fd, EPOLL_CTL_DEL, fd, NULL)) != 0 && errno == EINTR)
        {
            /* If epoll_ctl() was interrupted by the system, repeat. */
        }
        return rv;
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        struct pollfd * used_pollfd = NULL;
        void ** used_ptr = NULL;

        for (size_t i = 0; i < io->poll_max_fds; ++i)
        {
            if (io->poll_fds[i].fd == fd)
            {
                used_pollfd = &io->poll_fds[i];
                used_ptr = &io->poll_ptrs[i];
                break;
            }
        }
        if (used_pollfd == NULL)
            return NIO_ERROR_INTERNAL;

        used_pollfd->fd = -1;
        *used_ptr = NULL;

        return NIO_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_run(struct nio * io, int timeout)
{
#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        do
        {
            io->nready = epoll_wait(io->epoll_fd, io->events, io->max_events, timeout);
        } while (io->nready < 0 && errno == EINTR);

        if (io->nready < 0)
            return NIO_ERROR_SYSTEM;
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        do
        {
            io->nready = poll(io->poll_fds, io->poll_max_fds, timeout);
        } while (io->nready < 0 && errno == EINTR);

        if (io->nready < 0)
            return NIO_ERROR_SYSTEM;

        if (io->nready > 0)
        {
            for (nfds_t i = 0, j = 0; i < io->poll_max_fds; ++i)
            {
                if (io->poll_fds[i].fd >= 0 && io->poll_fds[i].revents != 0)
                {
                    io->poll_fds_set[j++] = i;
                }
            }
        }
    }

    return NIO_SUCCESS;
}

int nio_check(struct nio * io, int index, int event_flags)
{
    if (nio_is_valid(io, index) != NIO_SUCCESS)
        return NIO_ERROR_INTERNAL;

#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        uint32_t epoll_events = 0;

        if ((event_flags & NIO_EVENT_INPUT) != 0)
            epoll_events |= EPOLLIN;
        if ((event_flags & NIO_EVENT_OUTPUT) != 0)
            epoll_events |= EPOLLOUT;
        if ((event_flags & NIO_EVENT_ERROR) != 0)
            epoll_events |= EPOLLERR | EPOLLHUP;
        if (epoll_events == 0)
            return NIO_ERROR_INTERNAL;

        struct epoll_event const * const events = (struct epoll_event *)io->events;
        if ((events[index].events & epoll_events) == 0)
            return NIO_ERROR_INTERNAL;

        return NIO_SUCCESS;
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        short int poll_events = 0;

        if ((event_flags & NIO_EVENT_INPUT) != 0)
            poll_events |= POLLIN;
        if ((event_flags & NIO_EVENT_OUTPUT) != 0)
            poll_events |= POLLOUT;
        if ((event_flags & NIO_EVENT_ERROR) != 0)
            poll_events |= POLLERR | POLLHUP;
        if (poll_events == 0)
            return NIO_ERROR_INTERNAL;

        if ((io->poll_fds[io->poll_fds_set[index]].revents & poll_events) == 0)
            return NIO_ERROR_INTERNAL;

        return NIO_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_is_valid(struct nio const * const io, int index)
{
    if (index < 0 || index >= io->nready)
        return NIO_ERROR_INTERNAL;

#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        return NIO_SUCCESS;
    }
    else
#endif
        if (io->poll_max_fds > 0 && io->poll_fds[io->poll_fds_set[index]].fd >= 0)
    {
        return NIO_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_get_fd(struct nio * io, int index)
{
    if (nio_is_valid(io, index) != NIO_SUCCESS)
        return -1;

#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        struct epoll_event const * const events = (struct epoll_event *)io->events;

        return events[index].data.fd;
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        return io->poll_fds[io->poll_fds_set[index]].fd;
    }

    return -1;
}

void * nio_get_ptr(struct nio * io, int index)
{
    if (nio_is_valid(io, index) != NIO_SUCCESS)
        return NULL;

#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        struct epoll_event * const events = (struct epoll_event *)io->events;

        return events[index].data.ptr;
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        return io->poll_ptrs[io->poll_fds_set[index]];
    }

    return NULL;
}

void nio_free(struct nio * io)
{
    for (size_t i = 0; i < io->poll_max_fds; ++i)
    {
        if (io->poll_fds[i].fd >= 0)
        {
            close(io->poll_fds[i].fd);
            io->poll_fds[i].fd = -1;
        }
    }
#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        close(io->epoll_fd);
        io->epoll_fd = -1;
    }
#endif
    free(io->poll_fds);
    free(io->poll_ptrs);
    free(io->poll_fds_set);
    free(io->events);
}
