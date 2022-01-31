#ifndef UTILS_H
#define UTILS_H 1

#include <stdarg.h>

int is_path_absolute(char const * const prefix, char const * const path);

void daemonize_enable(void);

int is_daemonize_enabled(void);

int daemonize_with_pidfile(char const * const pidfile);

int daemonize_shutdown(char const * const pidfile);

int change_user_group(char const * const user,
                      char const * const group,
                      char const * const pidfile,
                      char const * const uds_collector_path,
                      char const * const uds_distributor_path);

void init_logging(char const * const daemon_name);

void log_app_info(void);

void shutdown_logging(void);

int enable_file_logger(char const * const log_file);

int get_log_file_fd(void);

void enable_console_logger(void);

int is_console_logger_enabled(void);

void vlogger(int is_error, char const * const format, va_list ap);

__attribute__((format(printf, 2, 3))) void logger(int is_error, char const * const format, ...);

__attribute__((format(printf, 2, 3))) void logger_early(int is_error, char const * const format, ...);

char const * get_nDPId_version(void);

#endif
