#ifndef UTILS_H
#define UTILS_H 1

int is_path_absolute(char const * const prefix,
                     char const * const path);

void daemonize_enable(void);

int daemonize_with_pidfile(char const * const pidfile);

int daemonize_shutdown(char const * const pidfile);

int change_user_group(char const * const user, char const * const group,
                      char const * const pidfile,
                      char const * const uds_collector_path,
                      char const * const uds_distributor_path);

#endif
