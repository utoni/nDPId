#include <ctype.h>
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
#include <unistd.h>

#include "utils.h"

#define UTILS_STRLEN_SZ(s) ((size_t)((sizeof(s) / sizeof(s[0])) - sizeof(s[0])))

#ifndef INI_MAX_LINE
#define INI_MAX_LINE BUFSIZ
#endif

#define INI_INLINE_COMMENT_PREFIXES ";"
#define INI_START_COMMENT_PREFIXES ";#"

typedef char pid_str[16];

static char const * app_name = NULL;
static int daemonize = 0;
static int log_to_console = 0;
static int log_to_file_fd = -1;

void set_config_defaults(struct confopt * const co_array, size_t array_length)
{
    for (size_t i = 0; i < array_length; ++i)
    {
        if (co_array[i].opt == NULL)
        {
            logger_early(1, "%s", "BUG: Config option is NULL");
            continue;
        }
        if (IS_CMDARG_SET(*co_array[i].opt) == 0)
        {
            switch (co_array[i].opt->type)
            {
                case CMDTYPE_INVALID:
                    logger_early(1, "BUG: Config option `%s' has CMDTYPE_INVALID!", co_array[i].key);
                    break;
                case CMDTYPE_STRING:
                    if (co_array[i].opt->string.default_value == NULL)
                    {
                        break;
                    }
                    co_array[i].opt->string.value = strdup(co_array[i].opt->string.default_value);
                    break;
                case CMDTYPE_BOOLEAN:
                    co_array[i].opt->boolean.value = co_array[i].opt->boolean.default_value;
                    break;
                case CMDTYPE_ULL:
                    co_array[i].opt->ull.value = co_array[i].opt->ull.default_value;
                    break;
            }
        }
    }
}

int set_config_from(struct confopt * const co, char const * const from)
{
    if (co == NULL || co->opt == NULL || from == NULL)
    {
        return -1;
    }

    switch (co->opt->type)
    {
        case CMDTYPE_INVALID:
            break;
        case CMDTYPE_STRING:
            set_cmdarg_string(co->opt, from);
            break;
        case CMDTYPE_BOOLEAN:
        {
            uint8_t enabled;

            if ((strnlen(from, INI_MAX_LINE) == UTILS_STRLEN_SZ("true") &&
                 strncasecmp(from, "true", INI_MAX_LINE) == 0) ||
                (strnlen(from, INI_MAX_LINE) == UTILS_STRLEN_SZ("1") && strncasecmp(from, "1", INI_MAX_LINE) == 0))
            {
                enabled = 1;
            }
            else if ((strnlen(from, INI_MAX_LINE) == UTILS_STRLEN_SZ("false") &&
                      strncasecmp(from, "false", INI_MAX_LINE) == 0) ||
                     (strnlen(from, INI_MAX_LINE) == UTILS_STRLEN_SZ("0") && strncasecmp(from, "0", INI_MAX_LINE) == 0))
            {
                enabled = 0;
            }
            else
            {
                logger_early(1, "Config key `%s' has a value not of type bool: `%s'", co->key, from);
                return 1;
            }
            set_cmdarg_boolean(co->opt, enabled);
        }
        break;
        case CMDTYPE_ULL:
        {
            char * endptr;
            long int value_llu = strtoull(from, &endptr, 10);

            if (from == endptr)
            {
                logger_early(1, "Subopt `%s': Value `%s' is not a valid number.", co->key, from);
                return 1;
            }
            if (errno == ERANGE)
            {
                logger_early(1, "Subopt `%s': Number too large.", co->key);
                return 1;
            }
            set_cmdarg_ull(co->opt, value_llu);
        }
        break;
    }

    return 0;
}

void set_cmdarg_string(struct cmdarg * const ca, char const * const val)
{
    if (ca == NULL || val == NULL)
    {
        return;
    }

    if (ca->type != CMDTYPE_STRING)
    {
        logger_early(1, "%s", "BUG: Type is not CMDTYPE_STRING!");
        return;
    }

    ca->is_set = 1;
    free(ca->string.value);
    ca->string.value = strdup(val);
}

void set_cmdarg_boolean(struct cmdarg * const ca, uint8_t val)
{
    if (ca == NULL)
    {
        return;
    }

    if (ca->type != CMDTYPE_BOOLEAN)
    {
        logger_early(1, "%s", "BUG: Type is not CMDTYPE_BOOLEAN!");
        return;
    }

    ca->is_set = 1;
    ca->boolean.value = (val != 0);
}

void set_cmdarg_ull(struct cmdarg * const ca, unsigned long long int val)
{
    if (ca == NULL)
    {
        return;
    }

    if (ca->type != CMDTYPE_ULL)
    {
        logger_early(1, "%s", "BUG: Type is not CMDTYPE_ULL!");
        return;
    }

    ca->is_set = 1;
    ca->ull.value = val;
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

int change_user_group(char const * const user, char const * const group, char const * const pidfile)
{
    struct passwd pwd;
    gid_t gid;

    if (user == NULL)
    {
        return 1;
    }

    {
        struct passwd * result;
        char buf[BUFSIZ];
        int retval;

        retval = getpwnam_r(user, &pwd, buf, sizeof(buf), &result);
        if (result == NULL)
        {
            return (retval != 0 ? -retval : -ENOENT);
        }
    }

    if (group != NULL)
    {
        struct group grp;
        struct group * result;
        char buf[BUFSIZ];
        int retval;

        retval = getgrnam_r(group, &grp, buf, sizeof(buf), &result);
        if (result == NULL)
        {
            return (retval != 0 ? -retval : -ENOENT);
        }
        gid = grp.gr_gid;
    }
    else
    {
        gid = pwd.pw_gid;
    }

    if (daemonize != 0 && pidfile != NULL)
    {
        errno = 0;
        if (chown(pidfile, pwd.pw_uid, gid) != 0)
        {
            return -errno;
        }
    }
    return setregid(gid, gid) != 0 || setreuid(pwd.pw_uid, pwd.pw_uid);
}

WARN_UNUSED
int chmod_chown(char const * const path, mode_t mode, char const * const user, char const * const group)
{
    uid_t path_uid = (uid_t)-1;
    gid_t path_gid = (gid_t)-1;

    if (path == NULL)
    {
        return EINVAL;
    }

    if (mode != 0)
    {
        if (chmod(path, mode) != 0)
        {
            return errno;
        }
    }

    if (user != NULL)
    {
        {
            struct passwd pwd;
            struct passwd * result;
            char buf[BUFSIZ];
            int retval;

            retval = getpwnam_r(user, &pwd, buf, sizeof(buf), &result);
            if (result == NULL)
            {
                return (retval != 0 ? retval : ENOENT);
            }
            path_uid = pwd.pw_uid;
            path_gid = pwd.pw_gid;
        }
    }

    if (group != NULL)
    {
        struct group grp;
        struct group * result;
        char buf[BUFSIZ];
        int retval;

        retval = getgrnam_r(group, &grp, buf, sizeof(buf), &result);
        if (result == NULL)
        {
            return (retval != 0 ? retval : ENOENT);
        }
        path_gid = grp.gr_gid;
    }

    if (path_uid != (uid_t)-1 || path_gid != (gid_t)-1)
    {
        if (chown(path, path_uid, path_gid) != 0)
        {
            return errno;
        }
    }

    return 0;
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

    if (getenv("NDPID_STARTED_BY_SYSTEMD") == NULL)
    {
        va_start(ap, format);
        vlogger_to(fileno(stderr), is_error, format, &ap);
        va_end(ap);
    }

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
           "(C) 2020-2025 Toni Uhlig\n"
           "Please report any BUG to toni@impl.cc\n";
}

/* Strip whitespace chars off end of given string, in place. Return s. */
static char * ini_rstrip(char * s)
{
    char * p = s + strlen(s);
    while (p > s && isspace((unsigned char)(*--p)))
        *p = '\0';
    return s;
}

/* Return pointer to first non-whitespace char in given string. */
static char * ini_lskip(char * s)
{
    while (*s && isspace((unsigned char)(*s)))
        s++;
    return s;
}

/* Return pointer to first char (of chars) or inline comment in given string,
   or pointer to NUL at end of string if neither found. Inline comment must
   be prefixed by a whitespace character to register as a comment. */
static char * ini_find_chars_or_comment(char * s, const char * chars)
{
    int was_space = 0;
    while (*s && (!chars || !strchr(chars, *s)) && !(was_space && strchr(INI_INLINE_COMMENT_PREFIXES, *s)))
    {
        was_space = isspace((unsigned char)(*s));
        s++;
    }
    return s;
}

/* See: https://github.com/benhoyt/inih/blob/master/ini.c#L97C67-L97C74 */
static int parse_config_lines(FILE * const file, config_line_callback cb, void * const user_data)
{
    char line[INI_MAX_LINE];
    int max_line = INI_MAX_LINE;
    char section[INI_MAX_SECTION] = "";
    char prev_name[INI_MAX_NAME] = "";
    char * start;
    char * end;
    char * name;
    char * value;
    int lineno = 0;
    int error = 0;

    while (fgets(line, max_line, file) != NULL)
    {
        lineno++;
        start = line;
        start = ini_lskip(ini_rstrip(start));

        if (strchr(INI_START_COMMENT_PREFIXES, *start))
        {
            /* Start-of-line comment */
        }
        else if (*prev_name && *start && start > line)
        {
            end = ini_find_chars_or_comment(start, NULL);
            if (*end)
            {
                *end = '\0';
            }
            ini_rstrip(start);

            /* Non-blank line with leading whitespace, treat as continuation
               of previous name's value (as per Python configparser). */
            if (!cb(lineno, section, prev_name, start, user_data) && !error)
            {
                error = lineno;
            }
        }
        else if (*start == '[')
        {
            /* A "[section]" line */
            end = ini_find_chars_or_comment(start + 1, "]");
            if (*end == ']')
            {
                *end = '\0';
                snprintf(section, sizeof(section), "%s", start + 1);
                *prev_name = '\0';
            }
            else if (!error)
            {
                /* No ']' found on section line */
                error = lineno;
            }
        }
        else if (*start)
        {
            /* Not a comment, must be a name[=:]value pair */
            end = ini_find_chars_or_comment(start, "=:");
            if (*end == '=' || *end == ':')
            {
                *end = '\0';
                name = ini_rstrip(start);
                value = end + 1;
                end = ini_find_chars_or_comment(value, NULL);
                if (*end)
                {
                    *end = '\0';
                }
                value = ini_lskip(value);
                ini_rstrip(value);

                /* Valid name[=:]value pair found, call handler */
                snprintf(prev_name, sizeof(prev_name), "%s", name);
                if (!cb(lineno, section, prev_name, value, user_data) && !error)
                {
                    error = lineno;
                }
            }
            else if (!error)
            {
                /* No '=' or ':' found on name[=:]value line */
                error = lineno;
            }
        }
    }

    return error;
}

int parse_config_file(char const * const config_file, config_line_callback cb, void * const user_data)
{
    int file_fd;
    FILE * file;
    int error;
    struct stat sbuf;

    file_fd = open(config_file, O_RDONLY);
    if (file_fd < 0)
    {
        return -1;
    }
    if (fstat(file_fd, &sbuf) != 0)
    {
        return -1;
    }
    if ((sbuf.st_mode & S_IFMT) != S_IFREG)
    {
        return -ENOENT;
    }

    file = fdopen(file_fd, "r");
    if (file == NULL)
    {
        return -1;
    }

    error = parse_config_lines(file, cb, user_data);
    fclose(file);
    return error;
}
