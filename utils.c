#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

typedef char pid_str[16];

static int daemonize = 0;

void daemonize_enable(void)
{
    daemonize = 1;
}

static int is_daemon_running(char const * const pidfile, pid_str ps)
{
    int pfd = open(pidfile, O_RDONLY, 0);
    char proc_path[32];

    if (pfd < 0)
    {
        return 0;
    }

    if (read(pfd, ps, sizeof(pid_str)) <= 0)
    {
        close(pfd);
        return 1;
    }

    close(pfd);

    if (snprintf(proc_path, sizeof(pid_str), "/proc/%s", ps) <= 0)
    {
        return 1;
    }

    if (access(proc_path, F_OK) == 0)
    {
        return 1;
    }

    return 0;
}

static int create_pidfile(char const * const pidfile)
{
    int pfd;

    if (is_path_absolute("Pidfile", pidfile) != 0)
    {
        return 1;
    }

    pfd = open(pidfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    if (pfd < 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Could open pidfile %s for writing: %s", pidfile, strerror(errno));
        return 1;
    }

    if (dprintf(pfd, "%d", getpid()) <= 0)
    {
        close(pfd);
        return 1;
    }

    close(pfd);

    return 0;
}

int is_path_absolute(char const * const prefix, char const * const path)
{
    if (path[0] != '/')
    {
        syslog(LOG_DAEMON | LOG_ERR,
               "%s path must be absolut i.e. starting with a `/', path given: `%s'",
               prefix,
               path);
        return 1;
    }

    return 0;
}

int daemonize_with_pidfile(char const * const pidfile)
{
    pid_str ps = {};

    if (daemonize != 0)
    {
        if (is_daemon_running(pidfile, ps) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Pidfile %s found and daemon %s still running", pidfile, ps);
            return 1;
        }

        if (daemon(0, 0) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "daemon: %s", strerror(errno));
            return 1;
        }

        if (create_pidfile(pidfile) != 0)
        {
            return 1;
        }
    }

    return 0;
}

int daemonize_shutdown(char const * const pidfile)
{
    if (daemonize != 0)
    {
        if (unlink(pidfile) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "Could not unlink pidfile %s: %s", pidfile, strerror(errno));
            return 1;
        }
    }

    return 0;
}

int change_user_group(char const * const user,
                      char const * const group,
                      char const * const pidfile,
                      char const * const uds_collector_path,
                      char const * const uds_distributor_path)
{
    struct passwd * pwd;
    struct group * grp;
    gid_t gid;

    if (getuid() != 0)
    {
        return 0;
    }

    if (user == NULL)
    {
        return 1;
    }

    pwd = getpwnam(user);
    if (pwd == NULL)
    {
        return 1;
    }

    if (group != NULL)
    {
        grp = getgrnam(group);
        if (grp == NULL)
        {
            return 1;
        }
        gid = grp->gr_gid;
    }
    else
    {
        gid = pwd->pw_gid;
    }

    if (uds_collector_path != NULL)
    {
        chmod(uds_collector_path, S_IRUSR | S_IWUSR);
        chown(uds_collector_path, pwd->pw_uid, gid);
    }
    if (uds_distributor_path != NULL)
    {
        chmod(uds_distributor_path, S_IRUSR | S_IWUSR | S_IRGRP);
        chown(uds_distributor_path, pwd->pw_uid, gid);
    }
    if (pidfile != NULL)
    {
        chown(pidfile, pwd->pw_uid, gid);
    }
    return setregid(gid, gid) != 0 || setreuid(pwd->pw_uid, pwd->pw_uid);
}

char const * get_nDPId_version()
{
    return "nDPId version "
#ifdef GIT_VERSION
        GIT_VERSION
#else
           "unknown"
#endif
           "\n"
           "(C) 2020-2021 Toni Uhlig\n"
           "Please report BUGs to toni@impl.cc\n";
}
