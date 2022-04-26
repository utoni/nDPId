#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nDPIsrvd.h"

static int main_thread_shutdown = 0;
static struct nDPIsrvd_socket * sock = NULL;

#ifdef ENABLE_MEMORY_PROFILING
void nDPIsrvd_memprof_log(char const * const format, ...)
{
    va_list ap;

    va_start(ap, format);
    fprintf(stderr, "%s", "nDPIsrvd MemoryProfiler: ");
    vfprintf(stderr, format, ap);
    fprintf(stderr, "%s\n", "");
    va_end(ap);
}
#endif

static void nDPIsrvd_write_flow_info_cb(struct nDPIsrvd_socket const * sock,
                                        struct nDPIsrvd_instance const * instance,
                                        struct nDPIsrvd_thread_data const * thread_data,
                                        struct nDPIsrvd_flow const * flow,
                                        void * user_data)
{
    (void)sock;
    (void)instance;
    (void)user_data;

    fprintf(stderr,
            "[Thread %2d][Flow %5llu][ptr: "
#ifdef __LP64__
            "0x%016llx"
#else
            "0x%08lx"
#endif
            "][last-seen: %13llu][idle-time: %7llu][time-until-timeout: %7llu]\n",
            flow->thread_id,
            flow->id_as_ull,
#ifdef __LP64__
            (unsigned long long int)flow,
#else
            (unsigned long int)flow,
#endif
            flow->last_seen,
            flow->idle_time,
            (flow->last_seen + flow->idle_time >= thread_data->most_recent_flow_time
                 ? flow->last_seen + flow->idle_time - thread_data->most_recent_flow_time
                 : 0));
}

static void nDPIsrvd_verify_flows_cb(struct nDPIsrvd_thread_data const * const thread_data,
                                     struct nDPIsrvd_flow const * const flow,
                                     void * user_data)
{
    (void)user_data;

    if (thread_data != NULL)
    {
        if (flow->last_seen + flow->idle_time >= thread_data->most_recent_flow_time)
        {
            fprintf(stderr,
                    "Thread %d / %d, Flow %llu verification failed\n",
                    thread_data->thread_key,
                    flow->thread_id,
                    flow->id_as_ull);
        }
        else
        {
            fprintf(stderr,
                    "Thread %d / %d, Flow %llu verification failed, diff: %llu\n",
                    thread_data->thread_key,
                    flow->thread_id,
                    flow->id_as_ull,
                    thread_data->most_recent_flow_time - flow->last_seen + flow->idle_time);
        }
    }
    else
    {
        fprintf(stderr, "Thread [UNKNOWN], Flow %llu verification failed\n", flow->id_as_ull);
    }

    exit(1);
}

static void sighandler(int signum)
{
    struct nDPIsrvd_instance * current_instance;
    struct nDPIsrvd_instance * itmp;
    int verification_failed = 0;

    if (signum == SIGUSR1)
    {
        nDPIsrvd_flow_info(sock, nDPIsrvd_write_flow_info_cb, NULL);

        HASH_ITER(hh, sock->instance_table, current_instance, itmp)
        {
            if (nDPIsrvd_verify_flows(current_instance, nDPIsrvd_verify_flows_cb, NULL) != 0)
            {
                fprintf(stderr, "Flow verification failed for instance %d\n", current_instance->alias_source_key);
                verification_failed = 1;
            }
        }
        if (verification_failed == 0)
        {
            fprintf(stderr, "%s\n", "Flow verification succeeded.");
        }
    }
    else if (main_thread_shutdown == 0)
    {
        main_thread_shutdown = 1;
    }
}

static enum nDPIsrvd_callback_return simple_json_callback(struct nDPIsrvd_socket * const sock,
                                                          struct nDPIsrvd_instance * const instance,
                                                          struct nDPIsrvd_thread_data * const thread_data,
                                                          struct nDPIsrvd_flow * const flow)
{
    (void)sock;
    (void)thread_data;

    if (flow == NULL)
    {
        return CALLBACK_OK;
    }

    struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");
    if (TOKEN_VALUE_EQUALS_SZ(flow_event_name, "new") != 0)
    {
        printf("Instance 0x%x, Thread %d, Flow %llu new\n",
               instance->alias_source_key,
               flow->thread_id,
               flow->id_as_ull);
    }

    return CALLBACK_OK;
}

static void simple_flow_cleanup_callback(struct nDPIsrvd_socket * const sock,
                                         struct nDPIsrvd_instance * const instance,
                                         struct nDPIsrvd_thread_data * const thread_data,
                                         struct nDPIsrvd_flow * const flow,
                                         enum nDPIsrvd_cleanup_reason reason)
{
    (void)sock;
    (void)thread_data;

    char const * const reason_str = nDPIsrvd_enum_to_string(reason);
    printf("Instance 0x%x, Thread %d, Flow %llu cleanup, reason: %s\n",
           instance->alias_source_key,
           flow->thread_id,
           flow->id_as_ull,
           (reason_str != NULL ? reason_str : "UNKNOWN"));

    if (reason == CLEANUP_REASON_FLOW_TIMEOUT)
    {
        fprintf(stderr, "Flow %llu timeouted.\n", flow->id_as_ull);
    }
}

int main(int argc, char ** argv)
{
    signal(SIGUSR1, sighandler);
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, sighandler);

    sock = nDPIsrvd_socket_init(0, 0, 0, 0, simple_json_callback, NULL, simple_flow_cleanup_callback);
    if (sock == NULL)
    {
        return 1;
    }

    if (nDPIsrvd_setup_address(&sock->address, (argc > 1 ? argv[1] : "127.0.0.1:7000")) != 0)
    {
        return 1;
    }

    if (nDPIsrvd_connect(sock) != CONNECT_OK)
    {
        nDPIsrvd_socket_free(&sock);
        return 1;
    }

    if (nDPIsrvd_set_read_timeout(sock, 3, 0) != 0)
    {
        return 1;
    }

    enum nDPIsrvd_read_return read_ret = READ_OK;
    while (main_thread_shutdown == 0)
    {
        read_ret = nDPIsrvd_read(sock);
        if (errno == EINTR)
        {
            continue;
        }
        if (read_ret == READ_TIMEOUT)
        {
            printf("No data received during the last %llu second(s).\n",
                   (long long unsigned int)sock->read_timeout.tv_sec);
            continue;
        }
        if (read_ret != READ_OK)
        {
            break;
        }

        enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(sock);
        if (parse_ret != PARSE_NEED_MORE_DATA)
        {
            printf("Could not parse json string: %s\n", nDPIsrvd_enum_to_string(parse_ret));
            break;
        }
    }

    if (main_thread_shutdown == 0 && read_ret != READ_OK)
    {
        printf("Parse read %s\n", nDPIsrvd_enum_to_string(read_ret));
    }

    return 1;
}
