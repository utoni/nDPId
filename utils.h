#ifndef UTILS_H
#define UTILS_H 1

#include <stdarg.h>

#define WARN_UNUSED __attribute__((__warn_unused_result__))

#define CMDARG(_default_value)                                                                                         \
    {                                                                                                                  \
        .value = NULL, .default_value = (_default_value)                                                               \
    }

struct cmdarg
{
    char * value;
    char const * const default_value;
};

void set_cmdarg(struct cmdarg * const ca, char const * const val);

WARN_UNUSED
char const * get_cmdarg(struct cmdarg const * const ca);

WARN_UNUSED
int is_cmdarg_set(struct cmdarg const * const ca);

WARN_UNUSED
int is_path_absolute(char const * const prefix, char const * const path);

void daemonize_enable(void);

WARN_UNUSED
int is_daemonize_enabled(void);

WARN_UNUSED
int daemonize_with_pidfile(char const * const pidfile);

int daemonize_shutdown(char const * const pidfile);

WARN_UNUSED
int change_user_group(char const * const user,
                      char const * const group,
                      char const * const pidfile,
                      char const * const uds_collector_path,
                      char const * const uds_distributor_path);

void init_logging(char const * const daemon_name);

void log_app_info(void);

void shutdown_logging(void);

WARN_UNUSED
int enable_file_logger(char const * const log_file);

WARN_UNUSED
int get_log_file_fd(void);

void enable_console_logger(void);

WARN_UNUSED
int is_console_logger_enabled(void);

void vlogger(int is_error, char const * const format, va_list ap);

__attribute__((format(printf, 2, 3))) void logger(int is_error, char const * const format, ...);

__attribute__((format(printf, 2, 3))) void logger_early(int is_error, char const * const format, ...);

WARN_UNUSED
int set_fd_cloexec(int fd);

WARN_UNUSED
char const * get_nDPId_version(void);

#endif
