#include "nio.h"

#include <stdint.h>
#include <stdlib.h>
#ifdef ENABLE_EPOLL
#include <sys/epoll.h>
#endif

void nio_init(struct nio * io)
{
    io->nready = -1;
    io->poll_max_fds = -1;
    io->poll_cur_fds = 0;
    io->poll_fds = NULL;
    io->poll_ptrs = NULL;
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

    return io->poll_fds == NULL || io->poll_ptrs == NULL; // return NIO_ERROR_INTERNAL on error
}

int nio_use_epoll(struct nio * io, int max_events)
{
#ifdef ENABLE_EPOLL
    if (io->epoll_fd != -1 || io->poll_max_fds != 0 || max_events == 0)
        return NIO_ERROR_INTERNAL;

    io->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    io->max_events = max_events;
    io->events = calloc(max_events, sizeof(struct epoll_event));

    return io->epoll_fd;
#else
    (void)io;
    (void)max_events;

    return NIO_ERROR_INTERNAL;
#endif
}

int nio_add_fd(struct nio * io, int fd, int event_flags, void * ptr)
{
#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
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

        return epoll_ctl(io->epoll_fd, EPOLL_CTL_ADD, fd, &event);
    }
    else
#endif
    if (io->poll_max_fds > 0)
    {
        struct pollfd * unused_pollfd = NULL;
        void ** unused_ptr = NULL;

        if (io->poll_cur_fds == io->poll_max_fds || fd < 0)
            return NIO_ERROR_INTERNAL;

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
        io->poll_cur_fds++;

        return NIO_ERROR_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_mod_fd(struct nio * io, int fd, int event_flags, void * ptr)
{
#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
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

        return epoll_ctl(io->epoll_fd, EPOLL_CTL_MOD, fd, &event);
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        struct pollfd * unused_pollfd = NULL;
        void ** unused_ptr = NULL;

        if (io->poll_cur_fds == io->poll_max_fds || fd < 0)
            return NIO_ERROR_INTERNAL;

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
        io->poll_cur_fds++;

        return NIO_ERROR_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_del_fd(struct nio * io, int fd)
{
#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        return epoll_ctl(io->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        struct pollfd * unused_pollfd = NULL;
        void ** unused_ptr = NULL;

        if (io->poll_cur_fds == io->poll_max_fds || fd < 0)
            return NIO_ERROR_INTERNAL;

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

        unused_pollfd->fd = -1;
        *unused_ptr = NULL;
        io->poll_cur_fds--;

        return NIO_ERROR_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_run(struct nio * io, int timeout)
{
#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0)
    {
        io->nready = epoll_wait(io->epoll_fd, io->events, io->max_events, timeout);
        if (io->nready < 0)
            return NIO_ERROR_SYSTEM;
    }
    else
#endif
        if (io->poll_max_fds > 0)
    {
        io->nready = poll(io->poll_fds, io->poll_max_fds, timeout);
        if (io->nready < 0)
            return NIO_ERROR_SYSTEM;
        else
            io->nready = io->poll_max_fds;
    }

    return NIO_ERROR_SUCCESS;
}

int nio_check(struct nio * io, int index, int events)
{
    if (index < 0 || index >= io->nready)
        return NIO_ERROR_INTERNAL;

#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0 && index >= 0 && index < io->max_events)
    {
        uint32_t epoll_events = 0;

        if ((events & NIO_EVENT_INPUT) != 0)
            epoll_events |= EPOLLIN;
        if ((events & NIO_EVENT_OUTPUT) != 0)
            epoll_events |= EPOLLOUT;
        if (epoll_events == 0)
            return NIO_ERROR_INTERNAL;

        struct epoll_event * ee = (struct epoll_event *)io->events;
        if ((ee[index].events & epoll_events) != epoll_events)
            return NIO_ERROR_INTERNAL;

        return NIO_ERROR_SUCCESS;
    }
    else
#endif
        if (io->poll_max_fds > 0 && index >= 0 && index < (int)io->poll_max_fds)
    {
        short int poll_events = 0;

        if ((events & NIO_EVENT_INPUT) != 0)
            poll_events |= POLLIN;
        if ((events & NIO_EVENT_OUTPUT) != 0)
            poll_events |= POLLOUT;
        if (poll_events == 0)
            return NIO_ERROR_INTERNAL;

        if (io->poll_fds[index].revents != poll_events)
            return NIO_ERROR_INTERNAL;

        return NIO_ERROR_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_is_valid(struct nio * io, int index)
{
    if (index < 0 || index >= io->nready)
        return NIO_ERROR_INTERNAL;

#ifdef ENABLE_EPOLL
    if (io->epoll_fd >= 0 && index >= 0 && index <= io->max_events)
    {
        return NIO_ERROR_SUCCESS;
    }
    else
#endif
        if (io->poll_max_fds > 0 && index >= 0 && index < (int)io->poll_max_fds)
    {
        if (io->poll_fds[index].revents != 0)
            return NIO_ERROR_SUCCESS;
    }

    return NIO_ERROR_INTERNAL;
}

int nio_has_input(struct nio * io, int index)
{
    return nio_check(io, index, NIO_EVENT_INPUT);
}

int nio_can_output(struct nio * io, int index)
{
    return nio_check(io, index, NIO_EVENT_OUTPUT);
}

int nio_has_error(struct nio * io, int index)
{
    return nio_check(io, index, NIO_EVENT_ERROR);
}

void nio_free(struct nio * io)
{
    free(io->poll_fds);
    free(io->poll_ptrs);
    free(io->events);
}
