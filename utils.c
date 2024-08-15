#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef NO_MAIN
#include <syslog.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

typedef char pid_str[16];

static char const * app_name = NULL;
static int daemonize = 0;
static int log_to_console = 0;
static int log_to_file_fd = -1;

void set_cmdarg(struct cmdarg * const ca, char const * const val)
{
    if (ca == NULL || val == NULL)
    {
        return;
    }

    free(ca->value);
    ca->value = strdup(val);
}

char const * get_cmdarg(struct cmdarg const * const ca)
{
    if (ca == NULL)
    {
        return NULL;
    }

    if (ca->value != NULL)
    {
        return ca->value;
    }

    return ca->default_value;
}

int is_cmdarg_set(struct cmdarg const * const ca)
{
    if (ca == NULL)
    {
        return 0;
    }

    return ca->value != NULL;
}

void daemonize_enable(void)
{
    daemonize = 1;
}

int is_daemonize_enabled(void)
{
    return daemonize != 0;
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
        logger_early(1, "Could not open pidfile %s for writing: %s", pidfile, strerror(errno));
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
        logger_early(1, "%s path must be absolut i.e. starting with a `/', path given: `%s'", prefix, path);
        return 1;
    }

    return 0;
}

int daemonize_with_pidfile(char const * const pidfile)
{
    pid_str ps = {};
    int nullfd;

    if (daemonize != 0)
    {
        if (pidfile == NULL)
        {
            logger_early(1, "%s", "Missing pidfile.");
            return 1;
        }

        if (is_daemon_running(pidfile, ps) != 0)
        {
            logger_early(1, "Pidfile %s found and daemon %s still running", pidfile, ps);
            return 1;
        }

        nullfd = open("/dev/null", O_NONBLOCK, O_WRONLY);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0 || dup2(nullfd, STDOUT_FILENO) < 0 ||
            dup2(nullfd, STDERR_FILENO) < 0)
        {
            logger_early(1, "Opening /dev/null or replacing stdin/stdout/stderr failed: %s", strerror(errno));
            return 1;
        }

        // For compatiblity reasons, we use the UNIX double fork() technique.

        switch (fork())
        {
            case 0:
                break;
            case -1:
                logger_early(1, "Could not fork (first time): %s", strerror(errno));
                return 1;
            default:
                exit(0);
        }

        if (chdir("/") < 0 || setsid() < 0)
        {
            logger_early(1, "chdir() / setsid() failed: %s", strerror(errno));
            return 1;
        }

        switch (fork())
        {
            case 0:
                break;
            case -1:
                logger_early(1, "Could not fork (second time): %s", strerror(errno));
                return 1;
            default:
                exit(0);
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
        if (pidfile != NULL && unlink(pidfile) != 0 && errno != ENOENT)
        {
            logger(1, "Could not unlink pidfile %s: %s", pidfile, strerror(errno));
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

    if (user == NULL)
    {
        return 1;
    }

    errno = 0;
    pwd = getpwnam(user);
    if (pwd == NULL)
    {
        return -errno;
    }

    if (group != NULL)
    {
        errno = 0;
        grp = getgrnam(group);
        if (grp == NULL)
        {
            return -errno;
        }
        gid = grp->gr_gid;
    }
    else
    {
        gid = pwd->pw_gid;
    }

    if (uds_collector_path != NULL)
    {
        errno = 0;
        if (chmod(uds_collector_path, S_IRUSR | S_IWUSR) != 0 || chown(uds_collector_path, pwd->pw_uid, gid) != 0)
        {
            return -errno;
        }
    }
    if (uds_distributor_path != NULL)
    {
        errno = 0;
        if (chmod(uds_distributor_path, S_IRUSR | S_IWUSR | S_IRGRP) != 0 ||
            chown(uds_distributor_path, pwd->pw_uid, gid) != 0)
        {
            return -errno;
        }
    }
    if (daemonize != 0 && pidfile != NULL)
    {
        errno = 0;
        if (chown(pidfile, pwd->pw_uid, gid) != 0)
        {
            return -errno;
        }
    }
    return setregid(gid, gid) != 0 || setreuid(pwd->pw_uid, pwd->pw_uid);
}

void init_logging(char const * const name)
{
    app_name = name;
#ifndef NO_MAIN
    openlog(app_name, LOG_CONS, LOG_DAEMON);
#endif
}

void log_app_info(void)
{
    logger(0,
           "version %s",
#ifdef GIT_VERSION
           GIT_VERSION
#else
           "unknown"
#endif
    );
}

void shutdown_logging(void)
{
#ifndef NO_MAIN
    closelog();
#endif
}

int enable_file_logger(char const * const log_file)
{
    log_to_file_fd = open(log_file, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    if (log_to_file_fd < 0)
    {
        logger_early(1, "Could not open logfile %s for appending: %s", log_file, strerror(errno));
        return 1;
    }

    return 0;
}

int get_log_file_fd(void)
{
    return log_to_file_fd;
}

void enable_console_logger(void)
{
    if (setvbuf(stderr, NULL, _IOLBF, 0) != 0)
    {
        fprintf(stderr,
                "%s",
                "Could not set stderr line-buffered, "
                "console syslog() messages may appear weird.\n");
    }
    else
    {
        log_to_console = 1;
    }
}

int is_console_logger_enabled(void)
{
    return log_to_console != 0;
}

static void vlogger_to(int fd, int is_error, char const * const format, va_list * const ap)
{
    char logbuf[512];

    if (vsnprintf(logbuf, sizeof(logbuf), format, *ap) == sizeof(logbuf))
    {
        fprintf(stderr, "%s\n", "BUG: Log output was truncated due the logging buffer size limit.");
    }

    if (is_error != 0)
    {
        if (dprintf(fd, "%s [error]: %s\n", app_name, logbuf) < 0)
        {
            fprintf(stderr, "Could not write to fd %d: %s\n", fd, strerror(errno));
        }
    }
    else
    {
        if (dprintf(fd, "%s: %s\n", app_name, logbuf) < 0)
        {
            fprintf(stderr, "Could not write to fd %d: %s\n", fd, strerror(errno));
        }
    }
}

void vlogger(int is_error, char const * const format, va_list ap)
{
    va_list logfile_ap, stderr_ap;

    va_copy(logfile_ap, ap);
    va_copy(stderr_ap, ap);

#ifndef NO_MAIN
    if (log_to_console == 0)
    {
        if (is_error == 0)
        {
            vsyslog(LOG_DAEMON | LOG_INFO, format, ap);
        }
        else
        {
            vsyslog(LOG_DAEMON | LOG_ERR, format, ap);
        }
    }
    else
#endif
    {
        vlogger_to(fileno(stderr), is_error, format, &stderr_ap);
    }

    if (log_to_file_fd >= 0)
    {
        vlogger_to(log_to_file_fd, is_error, format, &logfile_ap);
    }

    va_end(stderr_ap);
    va_end(logfile_ap);
}

__attribute__((format(printf, 2, 3))) void logger(int is_error, char const * const format, ...)
{
    va_list ap;

    va_start(ap, format);
    vlogger(is_error, format, ap);
    va_end(ap);
}

__attribute__((format(printf, 2, 3))) void logger_early(int is_error, char const * const format, ...)
{
    int old_log_to_console = log_to_console;
    va_list ap;

    va_start(ap, format);
    vlogger_to(fileno(stderr), is_error, format, &ap);
    va_end(ap);

    log_to_console = 0;

    va_start(ap, format);
    vlogger(is_error, format, ap);
    va_end(ap);

    log_to_console = old_log_to_console;
}

int set_fd_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);

    if (flags < 0)
    {
        return -1;
    }
    return fcntl(fd, F_SETFD, FD_CLOEXEC);
}

char const * get_nDPId_version(void)
{
    return "nDPId version "
#ifdef GIT_VERSION
        GIT_VERSION
#else
           "unknown"
#endif
           "\n"
           "(C) 2020-2023 Toni Uhlig\n"
           "Please report any BUG to toni@impl.cc\n";
}
