#ifndef UTILS_H
#define UTILS_H 1

#include <stdarg.h>
#include <stdint.h>

#define WARN_UNUSED __attribute__((__warn_unused_result__))

#define INI_MAX_SECTION 50
#define INI_MAX_NAME 50

#define CMDARG_STR(_default_value)                                                                                     \
    {                                                                                                                  \
        .is_set = 0, .type = CMDTYPE_STRING, .string.value = NULL, .string.default_value = (_default_value)            \
    }
#define CMDARG_BOOL(_default_value)                                                                                    \
    {                                                                                                                  \
        .is_set = 0, .type = CMDTYPE_BOOLEAN, .boolean.value = 0, .boolean.default_value = (_default_value)            \
    }
#define CMDARG_ULL(_default_value)                                                                                     \
    {                                                                                                                  \
        .is_set = 0, .type = CMDTYPE_ULL, .ull.value = 0ull, .ull.default_value = (_default_value)                     \
    }
#define CONFOPT(_key, _opt)                                                                                            \
    {                                                                                                                  \
        .key = _key, .opt = _opt                                                                                       \
    }
#define GET_CMDARG_STR(cmdarg) ((cmdarg).string.value)
#define GET_CMDARG_BOOL(cmdarg) ((cmdarg).boolean.value)
#define GET_CMDARG_ULL(cmdarg) ((cmdarg).ull.value)
#define IS_CMDARG_SET(cmdarg) ((cmdarg).is_set)

enum cmdtype
{
    CMDTYPE_INVALID = 0,
    CMDTYPE_STRING,
    CMDTYPE_BOOLEAN,
    CMDTYPE_ULL
};

struct cmdarg
{
    enum cmdtype type;
    int is_set;
    union
    {
        struct
        {
            char * value;
            char const * const default_value;
        } string;
        struct
        {
            uint8_t value;
            uint8_t const default_value;
        } boolean;
        struct
        {
            unsigned long long int value;
            unsigned long long int const default_value;
        } ull;
    };
};

struct confopt
{
    char const * const key;
    struct cmdarg * const opt;
};

typedef int (*config_line_callback)(
    int lineno, char const * const section, char const * const key, char const * const value, void * const user_data);

void set_config_defaults(struct confopt * const co_array, size_t array_length);

WARN_UNUSED
int set_config_from(struct confopt * const co, char const * const from);

void set_cmdarg_string(struct cmdarg * const ca, char const * const val);

void set_cmdarg_boolean(struct cmdarg * const ca, uint8_t val);

void set_cmdarg_ull(struct cmdarg * const ca, unsigned long long int val);

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

WARN_UNUSED
int parse_config_file(char const * const config_file, config_line_callback cb, void * const user_data);

#endif
