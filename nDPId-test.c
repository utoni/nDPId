#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>

static void nDPIsrvd_memprof_log(char const * const format, ...);
static void nDPIsrvd_memprof_log_alloc(size_t alloc_size);
static void nDPIsrvd_memprof_log_free(size_t free_size);

//#define VERBOSE_MEMORY_PROFILING 1
#define NO_MAIN 1
#include "utils.c"
#include "nio.c"
#include "nDPIsrvd.c"
#include "nDPId.c"

enum
{
    PIPE_nDPId = 1,    /* nDPId mock pipefd array index */
    PIPE_nDPIsrvd = 0, /* nDPIsrvd mock pipefd array index */

    PIPE_TEST_WRITE = 1, /* Distributor (data from nDPIsrvd) write */
    PIPE_TEST_READ = 0,  /* Distributor (do some validation tests) read */

    PIPE_BUFFER_WRITE = 1, /* Distributor (data from nDPIsrvd, buffered json lines) write */
    PIPE_BUFFER_READ = 0,  /* Distributor (do some validation tests, buffered json lines) read */

    PIPE_NULL_WRITE = 1, /* Distributor (data from nDPIsrvd) write */
    PIPE_NULL_READ = 0,  /* Distributor (print to stdout) read */

    PIPE_ARPA_WRITE = 1, /* Distributor (data from nDPIsrvd) write */
    PIPE_ARPA_READ = 0,  /* Distributor (IP mockup) read */

    PIPE_FDS = 2,
    MAX_REMOTE_DESCRIPTORS = 5 /* mock pipefd's + 2 * distributor pipefd's */
};

struct thread_return_value
{
    int val;
};

struct nDPId_return_value
{
    struct thread_return_value thread_return_value;

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_skipped_flows;
    unsigned long long int total_l4_payload_len;

    unsigned long long int not_detected_flow_protocols;
    unsigned long long int guessed_flow_protocols;
    unsigned long long int detected_flow_protocols;
    unsigned long long int flow_detection_updates;
    unsigned long long int flow_updates;

    unsigned long long int total_active_flows;
    unsigned long long int total_idle_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int cur_idle_flows;

#ifdef ENABLE_ZLIB
    unsigned long long int total_compressions;
    unsigned long long int total_compression_diff;
    unsigned long long int current_compression_diff;
#endif

    unsigned long long int total_events_serialized;
};

struct distributor_instance_user_data
{
    unsigned long long int flow_cleanup_count;
    unsigned long long int daemon_event_count;
};

struct distributor_thread_user_data
{
    unsigned long long int flow_new_count;
    unsigned long long int flow_end_count;
    unsigned long long int flow_idle_count;
    unsigned long long int daemon_event_count;
};

struct distributor_global_user_data
{
    unsigned long long int total_packets_processed;
    unsigned long long int total_l4_payload_len;
    unsigned long long int total_events_deserialized;
    unsigned long long int total_events_serialized;
    unsigned long long int total_flow_timeouts;

    unsigned long long int flow_new_count;
    unsigned long long int flow_end_count;
    unsigned long long int flow_idle_count;
    unsigned long long int flow_detected_count;
    unsigned long long int flow_guessed_count;
    unsigned long long int flow_not_detected_count;
    unsigned long long int flow_detection_update_count;
    unsigned long long int flow_update_count;

    unsigned long long int shutdown_events;

    unsigned long long int json_string_len_min;
    unsigned long long int json_string_len_max;
    double json_string_len_avg;

    unsigned long long int cur_active_flows;
    unsigned long long int cur_idle_flows;

    struct distributor_instance_user_data instance_user_data;
    struct distributor_thread_user_data thread_user_data;

    int flow_cleanup_error;

    // please keep this struct at the end
    struct
    {
        int do_hash_checks;
    } options;
};

struct distributor_flow_user_data
{
    unsigned long long int total_packets_processed;
    unsigned long long int flow_total_l4_data_len;
    uint8_t is_flow_timedout;
};

struct distributor_return_value
{
    struct thread_return_value thread_return_value;

    struct distributor_global_user_data stats;
};

#define TC_INIT(initial, wanted)                                                                                       \
    {                                                                                                                  \
        .mutex = PTHREAD_MUTEX_INITIALIZER, .condition = PTHREAD_COND_INITIALIZER, .value = initial,                   \
        .wanted_value = wanted                                                                                         \
    }
struct thread_condition
{
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int value;
    int wanted_value;
};

static int mock_pipefds[PIPE_FDS] = {};
static int mock_testfds[PIPE_FDS] = {};
static int mock_bufffds[PIPE_FDS] = {};
static int mock_nullfds[PIPE_FDS] = {};
static int mock_arpafds[PIPE_FDS] = {};
static struct thread_condition start_condition = TC_INIT(3, 0);
#ifdef VERBOSE_MEMORY_PROFILING
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static pthread_mutex_t mem_mutex = PTHREAD_MUTEX_INITIALIZER; // required; memory wrappers are used from two threads
                                                              // (distributor and nDPIsrvd)
static unsigned long long int nDPIsrvd_alloc_count = 0;
static unsigned long long int nDPIsrvd_alloc_bytes = 0;
static unsigned long long int nDPIsrvd_free_count = 0;
static unsigned long long int nDPIsrvd_free_bytes = 0;

#define THREAD_ERROR(thread_arg)                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        ((struct thread_return_value *)thread_arg)->val = (errno != 0 ? errno : 1);                                    \
    } while (0);
#define THREAD_ERROR_GOTO(thread_arg)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        THREAD_ERROR(thread_arg);                                                                                      \
        goto error;                                                                                                    \
    } while (0);

static void nDPIsrvd_memprof_log(char const * const format, ...)
{
#ifdef VERBOSE_MEMORY_PROFILING
    int logbuf_used, logbuf_used_tmp;
    char logbuf[BUFSIZ];
    va_list ap;

    va_start(ap, format);
    pthread_mutex_lock(&log_mutex);
    logbuf_used = snprintf(logbuf, sizeof(logbuf), "%s", "nDPIsrvd MemoryProfiler: ");
    if (logbuf_used > 0)
    {
        logbuf_used_tmp = vsnprintf(logbuf + logbuf_used, sizeof(logbuf) - logbuf_used, format, ap);
        if (logbuf_used_tmp > 0)
        {
            logbuf_used += logbuf_used_tmp;
        }
    }
    fprintf(stderr, "%s\n", logbuf);
    pthread_mutex_unlock(&log_mutex);
    va_end(ap);
#else
    (void)format;
#endif
}

void nDPIsrvd_memprof_log_alloc(size_t alloc_size)
{
    unsigned long alloc_count;

    // nDPIsrvd.h is used by client applications and nDPIsrvd (two threads!)
    pthread_mutex_lock(&mem_mutex);
    nDPIsrvd_alloc_count++;
    nDPIsrvd_alloc_bytes += alloc_size;
    alloc_count = nDPIsrvd_alloc_count;
    pthread_mutex_unlock(&mem_mutex);
    nDPIsrvd_memprof_log("nDPIsrvd.h: malloc #%llu, %llu bytes", alloc_count, alloc_size);
}

void nDPIsrvd_memprof_log_free(size_t free_size)
{
    unsigned long free_count;

    // nDPIsrvd.h is used by client applications and nDPIsrvd (two threads!)
    pthread_mutex_lock(&mem_mutex);
    nDPIsrvd_free_count++;
    nDPIsrvd_free_bytes += free_size;
    free_count = nDPIsrvd_free_count;
    pthread_mutex_unlock(&mem_mutex);
    nDPIsrvd_memprof_log("nDPIsrvd.h: free #%llu, %llu bytes", free_count, free_size);
}

static int thread_wait(struct thread_condition * const tc)
{
    int ret = 0;

    ret |= (pthread_mutex_lock(&tc->mutex) << 16);
    while (tc->value > tc->wanted_value)
    {
        ret |= (pthread_cond_wait(&tc->condition, &tc->mutex) << 8);
    }
    ret |= (pthread_mutex_unlock(&tc->mutex));

    return ret;
}

static int thread_block_signals()
{
    sigset_t blocked_signals;

    sigfillset(&blocked_signals);
    return pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
}

static int thread_signal(struct thread_condition * const tc)
{
    int ret = 0;

    ret |= (pthread_mutex_lock(&tc->mutex) << 16);
    if (tc->value > tc->wanted_value)
    {
        tc->value--;
    }
    if (tc->value == tc->wanted_value)
    {
        ret |= (pthread_cond_broadcast(&tc->condition) << 8);
    }
    ret |= (pthread_mutex_unlock(&tc->mutex));

    return ret;
}

static int setup_pipe(int pipefd[PIPE_FDS])
{
    if (pipe(pipefd) != 0)
    {
        return -1;
    }

    if (fcntl_add_flags(pipefd[0], O_NONBLOCK) != 0)
    {
        return -1;
    }

    if (fcntl_add_flags(pipefd[1], O_NONBLOCK) != 0)
    {
        return -1;
    }

    return 0;
}

static void * nDPIsrvd_mainloop_thread(void * const arg)
{
    int nDPIsrvd_distributor_disconnects = 0;
    int const nDPIsrvd_distributor_expected_disconnects = 5;
    int epollfd;
    struct remote_desc * mock_json_desc = NULL;
    struct remote_desc * mock_test_desc = NULL;
    struct remote_desc * mock_buff_desc = NULL;
    struct remote_desc * mock_null_desc = NULL;
    struct remote_desc * mock_arpa_desc = NULL;
    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);

    logger(0, "nDPIsrvd thread started, init..");

    if (thread_block_signals() != 0)
    {
        logger(1, "nDPIsrvd block signals failed: %s", strerror(errno));
    }

    errno = 0;
    epollfd = create_evq();
    if (epollfd < 0)
    {
        logger(1, "nDPIsrvd epollfd invalid: %d", epollfd);
        THREAD_ERROR_GOTO(arg);
    }

    mock_json_desc = get_remote_descriptor(COLLECTOR_UN, mock_pipefds[PIPE_nDPIsrvd], NETWORK_BUFFER_MAX_SIZE);
    if (mock_json_desc == NULL)
    {
        logger(1, "%s", "nDPIsrvd could not acquire remote descriptor (Collector)");
        THREAD_ERROR_GOTO(arg);
    }

    mock_test_desc = get_remote_descriptor(DISTRIBUTOR_UN, mock_testfds[PIPE_TEST_WRITE], NETWORK_BUFFER_MAX_SIZE / 4);
    if (mock_test_desc == NULL)
    {
        logger(1, "%s", "nDPIsrvd could not acquire remote descriptor (TEST Distributor)");
        THREAD_ERROR_GOTO(arg);
    }

    mock_buff_desc = get_remote_descriptor(DISTRIBUTOR_UN, mock_bufffds[PIPE_BUFFER_WRITE], 8);
    if (mock_buff_desc == NULL)
    {
        logger(1, "%s", "nDPIsrvd could not acquire remote descriptor (BUFFER Distributor)");
        THREAD_ERROR_GOTO(arg);
    }

    mock_null_desc = get_remote_descriptor(DISTRIBUTOR_UN, mock_nullfds[PIPE_NULL_WRITE], NETWORK_BUFFER_MAX_SIZE);
    if (mock_null_desc == NULL)
    {
        logger(1, "%s", "nDPIsrvd could not acquire remote descriptor (NULL Distributor)");
        THREAD_ERROR_GOTO(arg);
    }

    mock_arpa_desc = get_remote_descriptor(DISTRIBUTOR_IN, mock_arpafds[PIPE_ARPA_WRITE], NETWORK_BUFFER_MAX_SIZE / 8);
    if (mock_arpa_desc == NULL)
    {
        logger(1, "%s", "nDPIsrvd could not acquire remote descriptor (ARPA Distributor)");
        THREAD_ERROR_GOTO(arg);
    }
    strncpy(mock_arpa_desc->event_distributor_in.peer_addr,
            "arpa-mockup",
            sizeof(mock_arpa_desc->event_distributor_in.peer_addr));
    mock_arpa_desc->event_distributor_in.peer.sin_port = 0;

    errno = 0;
    if (add_in_event(epollfd, mock_json_desc) != 0 || add_in_event(epollfd, mock_test_desc) != 0 ||
        add_in_event(epollfd, mock_buff_desc) != 0 || add_in_event(epollfd, mock_null_desc) != 0 ||
        add_in_event(epollfd, mock_arpa_desc) != 0)
    {
        logger(1, "%s", "nDPIsrvd add input event failed");
        THREAD_ERROR_GOTO(arg);
    }

    logger(0, "nDPIsrvd thread init done");
    thread_signal(&start_condition);
    thread_wait(&start_condition);

    while (nDPIsrvd_distributor_disconnects < nDPIsrvd_distributor_expected_disconnects)
    {
        errno = 0;
        int nready = epoll_wait(epollfd, events, events_size, -1);
        if (nready < 0 && errno != EINTR)
        {
            logger(1, "%s", "nDPIsrvd epoll wait failed.");
            THREAD_ERROR_GOTO(arg);
        }
        else if (errno == EINTR)
        {
            continue;
        }

        for (int i = 0; i < nready; i++)
        {
            if (events[i].data.ptr == mock_json_desc || events[i].data.ptr == mock_test_desc ||
                events[i].data.ptr == mock_buff_desc || events[i].data.ptr == mock_null_desc ||
                events[i].data.ptr == mock_arpa_desc)
            {
                if ((events[i].events & EPOLLHUP) != 0 || (events[i].events & EPOLLERR) != 0)
                {
                    char const * remote_desc_name;
                    struct remote_desc * remote = (struct remote_desc *)events[i].data.ptr;
                    if (remote == mock_json_desc)
                    {
                        remote_desc_name = "Mock JSON";
                        do
                        {
                            if (mock_test_desc->fd >= 0)
                                drain_write_buffers_blocking(mock_test_desc);
                            if (mock_buff_desc->fd >= 0)
                                drain_write_buffers_blocking(mock_buff_desc);
                            if (mock_null_desc->fd >= 0)
                                drain_write_buffers_blocking(mock_null_desc);
                            if (mock_arpa_desc->fd >= 0)
                                drain_write_buffers_blocking(mock_arpa_desc);
                        } while (handle_data_event(epollfd, &events[i]) == 0);
                    }
                    else if (remote == mock_test_desc)
                    {
                        remote_desc_name = "Mock Test";
                    }
                    else if (remote == mock_buff_desc)
                    {
                        remote_desc_name = "Mock Buffer";
                    }
                    else if (remote == mock_null_desc)
                    {
                        remote_desc_name = "Mock NULL";
                    }
                    else if (remote == mock_arpa_desc)
                    {
                        remote_desc_name = "Mock ARPA";
                    }
                    else
                    {
                        remote_desc_name = "UNKNOWN";
                    }
                    nDPIsrvd_distributor_disconnects++;
                    logger(1,
                           "nDPIsrvd distributor '%s' connection closed (%d/%d)",
                           remote_desc_name,
                           nDPIsrvd_distributor_disconnects,
                           nDPIsrvd_distributor_expected_disconnects);
                    free_remote(epollfd, remote);
                }
                else
                {
                    if (handle_data_event(epollfd, &events[i]) != 0)
                    {
                        if (mock_arpa_desc == events[i].data.ptr)
                        {
                            // arpa mock does not care about shutdown events
                            disconnect_client(epollfd, mock_arpa_desc);
                            continue;
                        }
                        logger(1, "%s", "nDPIsrvd data event handler failed");
                        THREAD_ERROR_GOTO(arg);
                    }
                }
            }
            else
            {
                logger(1,
                       "nDPIsrvd epoll returned unexpected event data: %d (%p)",
                       events[i].data.fd,
                       events[i].data.ptr);
                THREAD_ERROR_GOTO(arg);
            }
        }
    }

error:
    free_remotes(epollfd);
    close(epollfd);

    logger(0, "%s", "nDPIsrvd worker thread exits..");
    return NULL;
}

static enum nDPIsrvd_callback_return update_flow_packets_processed(struct nDPIsrvd_socket * const sock,
                                                                   struct distributor_flow_user_data * const flow_stats)
{
    struct nDPIsrvd_json_token const * const flow_total_packets_processed[FD_COUNT] = {
        TOKEN_GET_SZ(sock, "flow_src_packets_processed"), TOKEN_GET_SZ(sock, "flow_dst_packets_processed")};

    if (sock->flow_user_data_size > 0)
    {
        flow_stats->total_packets_processed = 0;
    }

    for (int dir = 0; dir < FD_COUNT; ++dir)
    {
        if (flow_total_packets_processed[dir] != NULL)
        {
            nDPIsrvd_ull nmb = 0;
            if (TOKEN_VALUE_TO_ULL(sock, flow_total_packets_processed[dir], &nmb) != CONVERSION_OK)
            {
                return CALLBACK_ERROR;
            }

            if (flow_stats != NULL)
            {
                if (sock->flow_user_data_size > 0)
                {
                    flow_stats->total_packets_processed += nmb;
                }
            }
        }
    }

    return CALLBACK_OK;
}

static enum nDPIsrvd_callback_return update_flow_l4_payload_len(struct nDPIsrvd_socket * const sock,
                                                                struct distributor_flow_user_data * const flow_stats)
{
    struct nDPIsrvd_json_token const * const flow_total_l4_payload_len[FD_COUNT] = {
        TOKEN_GET_SZ(sock, "flow_src_tot_l4_payload_len"), TOKEN_GET_SZ(sock, "flow_dst_tot_l4_payload_len")};

    if (sock->flow_user_data_size > 0)
    {
        flow_stats->flow_total_l4_data_len = 0;
    }

    for (int dir = 0; dir < FD_COUNT; ++dir)
    {
        if (flow_total_l4_payload_len[dir] != NULL)
        {
            nDPIsrvd_ull nmb = 0;
            if (TOKEN_VALUE_TO_ULL(sock, flow_total_l4_payload_len[dir], &nmb) != CONVERSION_OK)
            {
                return CALLBACK_ERROR;
            }

            if (sock->flow_user_data_size > 0 && flow_stats != NULL)
            {
                flow_stats->flow_total_l4_data_len += nmb;
            }
        }
    }

    return CALLBACK_OK;
}

static enum nDPIsrvd_callback_return distributor_json_callback(struct nDPIsrvd_socket * const sock,
                                                               struct nDPIsrvd_instance * const instance,
                                                               struct nDPIsrvd_thread_data * const thread_data,
                                                               struct nDPIsrvd_flow * const flow)
{
    struct distributor_global_user_data * const global_stats =
        (struct distributor_global_user_data *)sock->global_user_data;
    struct distributor_instance_user_data * instance_stats =
        (struct distributor_instance_user_data *)instance->instance_user_data;
    struct distributor_thread_user_data * thread_stats = NULL;
    struct distributor_flow_user_data * flow_stats = NULL;

#if 0
    printf("Distributor: %.*s\n", (int)sock->buffer.json_string_length, sock->buffer.json_string);
#endif

    if (thread_data != NULL)
    {
        thread_stats = (struct distributor_thread_user_data *)thread_data->thread_user_data;
    }
    if (flow != NULL)
    {
        flow_stats = (struct distributor_flow_user_data *)flow->flow_user_data;
    }

    if (sock->buffer.json_string_length < global_stats->json_string_len_min)
    {
        global_stats->json_string_len_min = sock->buffer.json_string_length;
    }
    if (sock->buffer.json_string_length > global_stats->json_string_len_max)
    {
        global_stats->json_string_len_max = sock->buffer.json_string_length;
    }
    global_stats->json_string_len_avg = (global_stats->json_string_len_avg +
                                         (global_stats->json_string_len_max + global_stats->json_string_len_min) / 2) /
                                        2;

    global_stats->total_events_deserialized++;

    {
        struct nDPIsrvd_json_token const * const daemon_event_name = TOKEN_GET_SZ(sock, "daemon_event_name");

        if (daemon_event_name != NULL)
        {
            if (sock->instance_user_data_size > 0)
            {
                instance_stats->daemon_event_count++;
            }
            if (sock->thread_user_data_size > 0)
            {
                thread_stats->daemon_event_count++;
            }

            if (TOKEN_VALUE_EQUALS_SZ(sock, daemon_event_name, "shutdown") != 0)
            {
                struct nDPIsrvd_json_token const * const total_events_serialized =
                    TOKEN_GET_SZ(sock, "total-events-serialized");

                if (total_events_serialized != NULL)
                {
                    nDPIsrvd_ull nmb = 0;
                    if (TOKEN_VALUE_TO_ULL(sock, total_events_serialized, &nmb) != CONVERSION_OK)
                    {
                        goto callback_error;
                    }

                    global_stats->total_events_serialized = nmb;
                }

                logger(0, "%s", "Distributor received shutdown event..");
                global_stats->shutdown_events++;
            }
        }
    }

    {
        struct nDPIsrvd_json_token const * const packet_event_name = TOKEN_GET_SZ(sock, "packet_event_name");

        if (packet_event_name != NULL)
        {
            struct nDPIsrvd_json_token const * const pkt = TOKEN_GET_SZ(sock, "pkt");
            struct nDPIsrvd_json_token const * const packet_id = TOKEN_GET_SZ(sock, "packet_id");

            if (pkt == NULL || packet_id == NULL)
            {
                logger(1, "%s", "Missing base64 packet data");
                goto callback_error;
            }

            nDPIsrvd_ull pkt_id = 0ull;
            TOKEN_VALUE_TO_ULL(sock, packet_id, &pkt_id);
            if (pkt_id == 0ull)
            {
                logger(1, "%s", "Missing packet id");
                goto callback_error;
            }

            nDPIsrvd_ull src_len = nDPIsrvd_get_token_size(sock, pkt);
            char const * const encoded_base64_buf = nDPIsrvd_get_token_value(sock, pkt);
            if (src_len == 0 || encoded_base64_buf == NULL)
            {
                logger(1, "Missing base64 packet data for packet id: %llu", pkt_id);
                goto callback_error;
            }

            unsigned char out_buf[8192];
            size_t out_len = sizeof(out_buf);
            if (nDPIsrvd_base64decode(encoded_base64_buf, src_len, out_buf, &out_len) != 0 || out_len == 0)
            {
                logger(1, "Decoding base64 packet data failed for packet id: %llu", pkt_id);
                logger(1, "Affected base64 packet data (%llu bytes): %.*s", src_len, (int)src_len, encoded_base64_buf);
                goto callback_error;
            }

            char base64_data[nDPId_PACKETS_PLEN_MAX * 4];
            size_t base64_data_len = sizeof(base64_data);
            if (base64_encode(out_buf, out_len, base64_data, &base64_data_len) != 0)
            {
                logger(1, "Encoding previously decoded base64 packet data failed for packet id: %llu", pkt_id);
                goto callback_error;
            }

            unsigned char test_buf[8192];
            size_t test_len = sizeof(test_buf);
            if (nDPIsrvd_base64decode(base64_data, base64_data_len, test_buf, &test_len) != 0 || test_len == 0)
            {
                logger(1, "Re-decoding base64 packet data failed for packet id: %llu", pkt_id);
                goto callback_error;
            }

            if (out_len != test_len || memcmp(out_buf, test_buf, out_len) != 0)
            {
                logger(1,
                       "Re-decoded base64 packet data differs from data decoded from JSON for packet id: %llu",
                       pkt_id);
                goto callback_error;
            }
        }
    }

    {
        struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");

        if (flow_event_name != NULL)
        {
            if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "new") != 0)
            {
                global_stats->cur_active_flows++;
                global_stats->flow_new_count++;
                if (sock->thread_user_data_size > 0)
                {
                    thread_stats->flow_new_count++;
                }

                unsigned int hash_count = HASH_COUNT(instance->flow_table);
                if (global_stats->options.do_hash_checks != 0 && hash_count != global_stats->cur_active_flows)
                {
                    logger(1,
                           "Amount of flows in the flow table not equal to current active flows counter: %u != %llu",
                           hash_count,
                           global_stats->cur_active_flows);
                    goto callback_error;
                }
            }
            if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "end") != 0)
            {
                global_stats->cur_active_flows--;
                global_stats->cur_idle_flows++;
                global_stats->flow_end_count++;
                if (sock->thread_user_data_size > 0)
                {
                    thread_stats->flow_end_count++;
                }

                if (update_flow_packets_processed(sock, flow_stats) != CALLBACK_OK ||
                    update_flow_l4_payload_len(sock, flow_stats) != CALLBACK_OK)
                {
                    goto callback_error;
                }
            }
            if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "idle") != 0)
            {
                global_stats->cur_active_flows--;
                global_stats->cur_idle_flows++;
                global_stats->flow_idle_count++;
                if (sock->thread_user_data_size > 0)
                {
                    thread_stats->flow_idle_count++;
                }

                if (update_flow_packets_processed(sock, flow_stats) != CALLBACK_OK ||
                    update_flow_l4_payload_len(sock, flow_stats) != CALLBACK_OK)
                {
                    goto callback_error;
                }
            }
            if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detected") != 0)
            {
                global_stats->flow_detected_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "guessed") != 0)
            {
                global_stats->flow_guessed_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "not-detected") != 0)
            {
                global_stats->flow_not_detected_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detection-update") != 0)
            {
                global_stats->flow_detection_update_count++;
            }
            if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "update") != 0)
            {
                global_stats->flow_update_count++;
            }

            struct nDPIsrvd_flow * current_flow;
            struct nDPIsrvd_flow * ftmp;
            size_t flow_count = 0;
            HASH_ITER(hh, instance->flow_table, current_flow, ftmp)
            {
                flow_count++;
            }
            if (global_stats->options.do_hash_checks != 0 &&
                flow_count != global_stats->cur_active_flows + global_stats->cur_idle_flows)
            {
                logger(1,
                       "Amount of flows in flow table not equal current active flows plus current idle flows: %llu != "
                       "%llu + %llu",
                       (unsigned long long int)flow_count,
                       global_stats->cur_active_flows,
                       global_stats->cur_idle_flows);
                goto callback_error;
            }
        }
    }

    return CALLBACK_OK;
callback_error:
    logger(1, "%s", "Distributor error..");
    return CALLBACK_ERROR;
}

static void distributor_instance_cleanup_callback(struct nDPIsrvd_socket * const sock,
                                                  struct nDPIsrvd_instance * const instance,
                                                  enum nDPIsrvd_cleanup_reason reason)
{
    struct distributor_global_user_data * const global_stats =
        (struct distributor_global_user_data *)sock->global_user_data;
    struct nDPIsrvd_thread_data * current_thread_data;
    struct nDPIsrvd_thread_data * ttmp;

    (void)reason;

    if (sock->global_user_data_size == 0 || sock->thread_user_data_size == 0 || sock->instance_user_data_size == 0)
    {
        return;
    }

    HASH_ITER(hh, instance->thread_data_table, current_thread_data, ttmp)
    {
        struct distributor_thread_user_data * const tud =
            (struct distributor_thread_user_data *)current_thread_data->thread_user_data;
        global_stats->thread_user_data.daemon_event_count += tud->daemon_event_count;
        global_stats->thread_user_data.flow_new_count += tud->flow_new_count;
        global_stats->thread_user_data.flow_end_count += tud->flow_end_count;
        global_stats->thread_user_data.flow_idle_count += tud->flow_idle_count;
    }
    global_stats->instance_user_data = *(struct distributor_instance_user_data *)instance->instance_user_data;
}

static void distributor_flow_cleanup_callback(struct nDPIsrvd_socket * const sock,
                                              struct nDPIsrvd_instance * const instance,
                                              struct nDPIsrvd_thread_data * const thread_data,
                                              struct nDPIsrvd_flow * const flow,
                                              enum nDPIsrvd_cleanup_reason reason)
{
    struct distributor_global_user_data * const global_stats =
        (struct distributor_global_user_data *)sock->global_user_data;
    struct distributor_flow_user_data * const flow_stats = (struct distributor_flow_user_data *)flow->flow_user_data;

    (void)thread_data;

    if (sock->instance_user_data_size > 0)
    {
        ((struct distributor_instance_user_data *)instance->instance_user_data)->flow_cleanup_count++;
    }

    switch (reason)
    {
        case CLEANUP_REASON_DAEMON_INIT:
        case CLEANUP_REASON_DAEMON_SHUTDOWN:
            /* If that happens, it is either a BUG or caused by other applications. */
            logger(1, "Invalid flow cleanup reason: %s", nDPIsrvd_enum_to_string(reason));
            global_stats->flow_cleanup_error = 1;
            break;

        case CLEANUP_REASON_FLOW_TIMEOUT:
            /*
             * Flow timeouts may happen. The cause is libpcap itself.
             * Unfortunately, libpcap does not provide retrieving the file descriptor if reading packets from a file.
             * Without a file descriptor select(), poll() or epoll() can not work.
             * As result all timestamps may have huge gaps depending on the recorded pcap file.
             * But those timestamps are necessary to make flow-updates work.
             */
            global_stats->total_flow_timeouts++;
            flow_stats->is_flow_timedout = 1;
            break;

        case CLEANUP_REASON_APP_SHUTDOWN:
        case CLEANUP_REASON_FLOW_END:
        case CLEANUP_REASON_FLOW_IDLE:
            break;

        case CLEANUP_REASON_LAST_ENUM_VALUE:
            break;
    }

    unsigned hash_count = HASH_COUNT(instance->flow_table);
    if (hash_count != global_stats->cur_active_flows + global_stats->cur_idle_flows)
    {
        logger(1,
               "Flow count is not equal to current active flows plus current idle flows plus current timedout flows: "
               "%u != %llu + %llu",
               hash_count,
               global_stats->cur_active_flows,
               global_stats->cur_idle_flows);
        global_stats->flow_cleanup_error = 1;
    }

    if (flow_stats->is_flow_timedout == 0)
    {
        global_stats->total_packets_processed += flow_stats->total_packets_processed;
        global_stats->total_l4_payload_len += flow_stats->flow_total_l4_data_len;
        global_stats->cur_idle_flows--;
    }
}

static enum nDPIsrvd_callback_return distributor_json_mock_buff_callback(
    struct nDPIsrvd_socket * const sock,
    struct nDPIsrvd_instance * const instance,
    struct nDPIsrvd_thread_data * const thread_data,
    struct nDPIsrvd_flow * const flow)
{
    return distributor_json_callback(sock, instance, thread_data, flow);
}

static enum nDPIsrvd_callback_return distributor_json_printer(struct nDPIsrvd_socket * const sock,
                                                              struct nDPIsrvd_instance * const instance,
                                                              struct nDPIsrvd_thread_data * const thread_data,
                                                              struct nDPIsrvd_flow * const flow)
{
    (void)instance;
    (void)thread_data;
    (void)flow;

    {
        struct nDPIsrvd_json_token const * const daemon_event_name = TOKEN_GET_SZ(sock, "daemon_event_name");

        if (daemon_event_name != NULL)
        {
            if (TOKEN_VALUE_EQUALS_SZ(sock, daemon_event_name, "shutdown") != 0)
            {
                logger(0, "%s", "Distributor received shutdown event..");
                int * const mock_null_shutdown_events = (int *)sock->global_user_data;
                (*mock_null_shutdown_events)++;
            }
        }
    }

    printf("%0" NETWORK_BUFFER_LENGTH_DIGITS_STR "llu%.*s",
           sock->buffer.json_string_length - NETWORK_BUFFER_LENGTH_DIGITS,
           nDPIsrvd_json_buffer_length(sock),
           nDPIsrvd_json_buffer_string(sock));
    return CALLBACK_OK;
}

static void * distributor_client_mainloop_thread(void * const arg)
{
    int dis_epollfd = create_evq();
    int signalfd = setup_signalfd(dis_epollfd);
    struct epoll_event events[32];
    size_t const events_size = sizeof(events) / sizeof(events[0]);
    struct distributor_return_value * const drv = (struct distributor_return_value *)arg;
    struct thread_return_value * const trv = &drv->thread_return_value;
    struct nDPIsrvd_socket * mock_sock = nDPIsrvd_socket_init(sizeof(struct distributor_global_user_data),
                                                              sizeof(struct distributor_instance_user_data),
                                                              sizeof(struct distributor_thread_user_data),
                                                              sizeof(struct distributor_flow_user_data),
                                                              distributor_json_callback,
                                                              distributor_instance_cleanup_callback,
                                                              distributor_flow_cleanup_callback);
    struct nDPIsrvd_socket * mock_buff = nDPIsrvd_socket_init(sizeof(struct distributor_global_user_data),
                                                              sizeof(struct distributor_instance_user_data),
                                                              sizeof(struct distributor_thread_user_data),
                                                              sizeof(struct distributor_flow_user_data),
                                                              distributor_json_mock_buff_callback,
                                                              distributor_instance_cleanup_callback,
                                                              distributor_flow_cleanup_callback);
    struct nDPIsrvd_socket * mock_null =
        nDPIsrvd_socket_init(sizeof(int), 0, 0, 0, distributor_json_printer, NULL, NULL);
    struct distributor_global_user_data * sock_stats;
    struct distributor_global_user_data * buff_stats;
    int * mock_null_shutdown_events;

    logger(0, "Distributor thread started, init..");

    if (thread_block_signals() != 0)
    {
        logger(1, "Distributor block signals failed: %s", strerror(errno));
    }

    errno = 0;
    if (mock_sock == NULL || mock_buff == NULL || mock_null == NULL)
    {
        THREAD_ERROR_GOTO(trv);
    }

    mock_sock->fd = mock_testfds[PIPE_TEST_READ];
    mock_buff->fd = mock_bufffds[PIPE_BUFFER_READ];
    mock_null->fd = mock_nullfds[PIPE_NULL_READ];

    if (dis_epollfd < 0 || signalfd < 0)
    {
        THREAD_ERROR_GOTO(trv);
    }

    errno = 0;
    if (add_in_event_fd(dis_epollfd, mock_testfds[PIPE_TEST_READ]) != 0)
    {
        THREAD_ERROR_GOTO(trv);
    }

    errno = 0;
    if (add_in_event_fd(dis_epollfd, mock_bufffds[PIPE_BUFFER_READ]) != 0)
    {
        THREAD_ERROR_GOTO(trv);
    }

    errno = 0;
    if (add_in_event_fd(dis_epollfd, mock_nullfds[PIPE_NULL_READ]) != 0)
    {
        THREAD_ERROR_GOTO(trv);
    }

    errno = 0;
    if (add_in_event_fd(dis_epollfd, mock_arpafds[PIPE_ARPA_READ]) != 0)
    {
        THREAD_ERROR_GOTO(trv);
    }

    sock_stats = (struct distributor_global_user_data *)mock_sock->global_user_data;
    sock_stats->json_string_len_min = (unsigned long long int)-1;
    sock_stats->options.do_hash_checks = 1;
    buff_stats = (struct distributor_global_user_data *)mock_buff->global_user_data;
    buff_stats->json_string_len_min = (unsigned long long int)-1;
    buff_stats->options.do_hash_checks = 0;
    mock_null_shutdown_events = (int *)mock_null->global_user_data;
    *mock_null_shutdown_events = 0;

    logger(0, "Distributor thread init done");
    thread_signal(&start_condition);
    thread_wait(&start_condition);

    while (sock_stats->shutdown_events == 0 || buff_stats->shutdown_events == 0 || *mock_null_shutdown_events == 0)
    {
        int nready = epoll_wait(dis_epollfd, events, events_size, -1);
        if (nready < 0 && errno != EINTR)
        {
            logger(1, "%s", "Distributor epoll wait failed.");
            THREAD_ERROR_GOTO(trv);
        }
        else if (nready < 0 && errno == EINTR)
        {
            continue;
        }

        for (int i = 0; i < nready; i++)
        {
            if ((events[i].events & EPOLLIN) == 0 && (events[i].events & EPOLLHUP) == 0)
            {
                logger(1, "Invalid epoll event received: %d", events[i].events & (~EPOLLIN & ~EPOLLHUP));
                THREAD_ERROR_GOTO(trv);
            }
            if ((events[i].events & EPOLLERR) != 0 || (events[i].events & EPOLLHUP) != 0)
            {
                logger(1, "Distributor disconnected: %d", events[i].data.fd);
                del_event(dis_epollfd, events[i].data.fd);
            }

            if (events[i].data.fd == mock_testfds[PIPE_TEST_READ])
            {
                switch (nDPIsrvd_read(mock_sock))
                {
                    case READ_OK:
                        break;
                    case READ_LAST_ENUM_VALUE:
                    case READ_ERROR:
                    case READ_TIMEOUT:
                        logger(1, "Read and verify fd returned an error: %s", strerror(errno));
                        THREAD_ERROR_GOTO(trv);
                    case READ_PEER_DISCONNECT:
                        break;
                }

                enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(mock_sock);
                if (parse_ret != PARSE_NEED_MORE_DATA)
                {
                    logger(1, "JSON parsing failed: %s", nDPIsrvd_enum_to_string(parse_ret));
                    logger(1,
                           "Problematic JSON string (mock sock, start: %zu, length: %llu, buffer usage: %zu): %.*s",
                           mock_sock->buffer.json_string_start,
                           mock_sock->buffer.json_string_length,
                           mock_sock->buffer.buf.used,
                           (int)mock_sock->buffer.json_string_length,
                           mock_sock->buffer.json_string);
                    THREAD_ERROR_GOTO(trv);
                }

                if (sock_stats->flow_cleanup_error != 0)
                {
                    logger(1, "%s", "Flow cleanup callback error'd");
                    THREAD_ERROR_GOTO(trv);
                }
            }
            else if (events[i].data.fd == mock_bufffds[PIPE_BUFFER_READ])
            {
                switch (nDPIsrvd_read(mock_buff))
                {
                    case READ_OK:
                        break;
                    case READ_LAST_ENUM_VALUE:
                    case READ_ERROR:
                    case READ_TIMEOUT:
                        logger(1, "Read and verify fd returned an error: %s", strerror(errno));
                        THREAD_ERROR_GOTO(trv);
                    case READ_PEER_DISCONNECT:
                        break;
                }

                enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(mock_buff);
                if (parse_ret != PARSE_NEED_MORE_DATA)
                {
                    logger(1, "JSON parsing failed: %s", nDPIsrvd_enum_to_string(parse_ret));
                    logger(1,
                           "Problematic JSON string (buff sock, start: %zu, length: %llu, buffer usage: %zu): %.*s",
                           mock_buff->buffer.json_string_start,
                           mock_buff->buffer.json_string_length,
                           mock_buff->buffer.buf.used,
                           (int)mock_buff->buffer.json_string_length,
                           mock_buff->buffer.json_string);
                    THREAD_ERROR_GOTO(trv);
                }

                if (buff_stats->flow_cleanup_error != 0)
                {
                    logger(1, "%s", "Flow cleanup callback error'd");
                    THREAD_ERROR_GOTO(trv);
                }
            }
            else if (events[i].data.fd == mock_nullfds[PIPE_NULL_READ])
            {
                switch (nDPIsrvd_read(mock_null))
                {
                    case READ_OK:
                        break;
                    case READ_LAST_ENUM_VALUE:
                    case READ_ERROR:
                    case READ_TIMEOUT:
                        logger(1, "Read and verify fd returned an error: %s", strerror(errno));
                        THREAD_ERROR_GOTO(trv);
                    case READ_PEER_DISCONNECT:
                        break;
                }

                enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(mock_null);
                if (parse_ret != PARSE_NEED_MORE_DATA)
                {
                    logger(1, "JSON parsing failed: %s", nDPIsrvd_enum_to_string(parse_ret));
                    logger(1,
                           "Problematic JSON string (buff sock, start: %zu, length: %llu, buffer usage: %zu): %.*s",
                           mock_null->buffer.json_string_start,
                           mock_null->buffer.json_string_length,
                           mock_null->buffer.buf.used,
                           (int)mock_null->buffer.json_string_length,
                           mock_null->buffer.json_string);
                    THREAD_ERROR_GOTO(trv);
                }
            }
            else if (events[i].data.fd == mock_arpafds[PIPE_ARPA_READ])
            {
                char buf[NETWORK_BUFFER_MAX_SIZE];
                ssize_t bytes_read = read(mock_arpafds[PIPE_ARPA_READ], buf, sizeof(buf));
                if (bytes_read < 0)
                {
                    logger(1, "Read fd returned an error: %s", strerror(errno));
                    THREAD_ERROR_GOTO(trv);
                }

                /*
                 * Nothing to do .. ?
                 * I am just here to trigger some IP code paths.
                 */
            }
            else if (events[i].data.fd == signalfd)
            {
                struct signalfd_siginfo fdsi;
                ssize_t s;

                errno = 0;
                s = read(signalfd, &fdsi, sizeof(struct signalfd_siginfo));
                if (s != sizeof(struct signalfd_siginfo))
                {
                    THREAD_ERROR(trv);
                }

                if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGQUIT)
                {
                    logger(1, "Got signal %d, abort.", fdsi.ssi_signo);
                    errno = 0;
                    THREAD_ERROR_GOTO(trv);
                }
            }
            else
            {
                logger(1,
                       "Distributor epoll returned unexpected event data: %d (%p)",
                       events[i].data.fd,
                       events[i].data.ptr);
                THREAD_ERROR_GOTO(trv);
            }
        }
    }

    struct nDPIsrvd_instance * current_instance;
    struct nDPIsrvd_instance * itmp;
    struct nDPIsrvd_flow * current_flow;
    struct nDPIsrvd_flow * ftmp;
    HASH_ITER(hh, mock_sock->instance_table, current_instance, itmp)
    {
        HASH_ITER(hh, current_instance->flow_table, current_flow, ftmp)
        {
            logger(1,
                   "[Mock Sock] Active flow found during client distributor shutdown with id: %llu",
                   current_flow->id_as_ull);
            errno = 0;
            THREAD_ERROR(trv);
        }

        nDPIsrvd_cleanup_instance(mock_sock, current_instance, CLEANUP_REASON_APP_SHUTDOWN);
    }
    HASH_ITER(hh, mock_buff->instance_table, current_instance, itmp)
    {
        HASH_ITER(hh, current_instance->flow_table, current_flow, ftmp)
        {
            logger(1,
                   "[Mock Buff] Active flow found during client distributor shutdown with id: %llu",
                   current_flow->id_as_ull);
            errno = 0;
            THREAD_ERROR(trv);
        }

        nDPIsrvd_cleanup_instance(mock_buff, current_instance, CLEANUP_REASON_APP_SHUTDOWN);
    }

    if (memcmp(sock_stats, buff_stats, sizeof(*sock_stats) - sizeof(sock_stats->options)) != 0)
    {
        logger(1,
               "Global statistics differ across different sockets! Events: %llu/%llu != %llu/%llu, Total Flows: "
               "%llu/%llu + %llu != %llu/%llu + %llu",
               buff_stats->total_events_serialized,
               buff_stats->total_events_deserialized,
               sock_stats->total_events_serialized,
               sock_stats->total_events_deserialized,
               buff_stats->flow_new_count,
               buff_stats->flow_end_count,
               buff_stats->flow_idle_count,
               sock_stats->flow_new_count,
               sock_stats->flow_end_count,
               sock_stats->flow_idle_count);
        errno = 0;
        THREAD_ERROR(trv);
    }
    drv->stats = *sock_stats;

    if (sock_stats->shutdown_events != 1 || buff_stats->shutdown_events != 1 || *mock_null_shutdown_events != 1)
    {
        logger(1,
               "Unexpected amount of shutdown events received, expected 1 per nDPIsrvd socket, got (Sock/Buff/NULL): "
               "%llu/%llu/%d",
               sock_stats->shutdown_events,
               buff_stats->shutdown_events,
               *mock_null_shutdown_events);
        errno = 0;
        THREAD_ERROR(trv);
    }

error:
    del_event(dis_epollfd, signalfd);
    del_event(dis_epollfd, mock_testfds[PIPE_TEST_READ]);
    del_event(dis_epollfd, mock_bufffds[PIPE_BUFFER_READ]);
    del_event(dis_epollfd, mock_nullfds[PIPE_NULL_READ]);
    del_event(dis_epollfd, mock_arpafds[PIPE_ARPA_READ]);
    close(mock_testfds[PIPE_TEST_READ]);
    close(mock_bufffds[PIPE_BUFFER_READ]);
    close(mock_nullfds[PIPE_NULL_READ]);
    close(mock_arpafds[PIPE_ARPA_READ]);
    close(dis_epollfd);
    close(signalfd);

    nDPIsrvd_socket_free(&mock_sock);
    nDPIsrvd_socket_free(&mock_buff);
    nDPIsrvd_socket_free(&mock_null);

    logger(0, "%s", "Distributor worker thread exits..");
    return NULL;
}

static void * nDPId_mainloop_thread(void * const arg)
{
    struct nDPId_return_value * const nrv = (struct nDPId_return_value *)arg;
    struct thread_return_value * const trr = &nrv->thread_return_value;

    logger(0, "nDPId thread started, init..");

    if (thread_block_signals() != 0)
    {
        logger(1, "nDPId block signals failed: %s", strerror(errno));
    }

    if (setup_reader_threads() != 0)
    {
        THREAD_ERROR(trr);
        goto error;
    }

    /* Replace nDPId JSON socket fd with the one in our pipe and hope that no socket specific code-path triggered. */
    reader_threads[0].collector_sockfd = mock_pipefds[PIPE_nDPId];
    reader_threads[0].collector_sock_last_errno = 0;
    if (set_collector_block(&reader_threads[0]) != 0)
    {
        goto error;
    }

    logger(0, "nDPId thread initialize done");
    thread_signal(&start_condition);
    thread_wait(&start_condition);

    jsonize_daemon(&reader_threads[0], DAEMON_EVENT_INIT);
    /* restore SIGPIPE to the default handler (Termination) */
    if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
    {
        goto error;
    }
    run_pcap_loop(&reader_threads[0]);
    process_remaining_flows();
    for (size_t i = 0; i < nDPId_options.reader_thread_count; ++i)
    {
        nrv->packets_captured += reader_threads[i].workflow->packets_captured;
        nrv->packets_processed += reader_threads[i].workflow->packets_processed;
        nrv->total_skipped_flows += reader_threads[i].workflow->total_skipped_flows;
        nrv->total_l4_payload_len += reader_threads[i].workflow->total_l4_payload_len;

        nrv->not_detected_flow_protocols += reader_threads[i].workflow->total_not_detected_flows;
        nrv->guessed_flow_protocols += reader_threads[i].workflow->total_guessed_flows;
        nrv->detected_flow_protocols += reader_threads[i].workflow->total_detected_flows;
        nrv->flow_detection_updates += reader_threads[i].workflow->total_flow_detection_updates;
        nrv->flow_updates += reader_threads[i].workflow->total_flow_updates;

        nrv->total_active_flows += reader_threads[i].workflow->total_active_flows;
        nrv->total_idle_flows += reader_threads[i].workflow->total_idle_flows;
        nrv->cur_active_flows += reader_threads[i].workflow->cur_active_flows;
        nrv->cur_idle_flows += reader_threads[i].workflow->cur_idle_flows;

#ifdef ENABLE_ZLIB
        nrv->total_compressions += reader_threads[i].workflow->total_compressions;
        nrv->total_compression_diff += reader_threads[i].workflow->total_compression_diff;
        nrv->current_compression_diff += reader_threads[i].workflow->current_compression_diff;
#endif

        nrv->total_events_serialized += reader_threads[i].workflow->total_events_serialized;
    }

error:
    free_reader_threads();
    close(mock_pipefds[PIPE_nDPId]);

    logger(0, "%s", "nDPId worker thread exits..");
    return NULL;
}

static void usage(char const * const arg0)
{
    fprintf(stderr, "usage: %s [path-to-pcap-file]\n", arg0);
}

static int thread_wait_for_termination(pthread_t thread, time_t wait_time_secs, struct thread_return_value * const trv)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
    {
        return -1;
    }

    ts.tv_sec += wait_time_secs;
    int err = pthread_timedjoin_np(thread, (void **)&trv, &ts);

    switch (err)
    {
        case EBUSY:
            return 0;
        case ETIMEDOUT:
            return 0;
    }

    return 1;
}

static int base64_selftest()
{
    const char encoded_buf[] =
        "YDjgxTWgeJS0JASgCABFABi9tLtAAG0G2Ic0qHBDwKgCZAG7qo4aJ6Tg8cI7hVAYCASApwAAFgMDGJACAABVAwNk4H0AwVcaoxmhfP+LwJ/"
        "ozXfcwVjP0gYb2nL2/TIuiiC0IwAA09uHhjDKb5jvbNMiEUTKv+mJ726ydLSPOT+wwcAwAAANAAUAAAAXAAD/"
        "AQABAAsAD8kAD8YACckwggnFMIIHraADAgECAhMzALaK/kHkK/"
        "0TofK4AAAAtor+"
        "MA0GCSqGSIb3DQEBDAUAMFkxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKjAoBgNVBAMTIU1pY3Jvc29mdC"
        "BBenVyZSBUTFMgSXNzdWluZyBDQSAwNjAeFw0yMzA2MDYxOTIwNTZaFw0yNDA1MzExOTIwNTZaMHIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJX"
        "QTEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSQwIgYDVQQDDBsqLmV2ZW50cy5kYXRhLm1pY3Jvc2"
        "9mdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdw/"
        "K44npKYmJOAyZRaA4KKVq2gRnM+Z3WtwG8k1fl8NJR4xR3lWGDnzhqdKB85o3WzvJS/2yXjM9ODdhWUz7iCPysNOoGq3jKntcoaaoWm/"
        "rUzG+G7r5LXeBrQMEAZ+f8+wqgzvbJN3z3WNV6CyqzaIsDnii0Ny6J3qN9cu0LabPZDpiybeNiOS2JUmSBUwQpYIAUoYb28D3nu+"
        "oDNSZD2ypYHIcU9NNEuMROEVlMRnGVYerMd93vq2DNb45Bxhyeu+10/upTNUeKARISgI1dFVh1hbwKGf/"
        "A2RCrxqtRJ5hg0bVwYB+"
        "tNaPCZrxnJiQGLhEDiks8UGEOpBu64la9AgMBAAGjggVrMIIFZzCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFnAHUAdv+IPwq2+"
        "5VRwmHM9Ye6NLSkzbsp3GhCCp/mZ0xaOnQAAAGIkjD4TAAABAMARjBEAiB7C4siVQQ8jtwsO0UGH6/"
        "iTflZhnk4YsHp2dt1vNbrEQIgUO2o0Xu2lMG7o047mAtOsozoGIxkDrs1nSzu3HjiEK0AdgDatr9rP7W2Ip+bwrtca+"
        "hwkXFsu1GEhTS9pD0wSNf7qwAAAYiSMPi2AAAEAwBHMEUCIGs7NBT/"
        "cxqu8lHHeofcUbjtsEyxdCSM+TZYuiGkkJc9AiEAkH5j20YlRriEKT2gf2XEl8kxmUm1w9b3x/"
        "ej7iEPQZ8AdgDuzdBk1dsazsVct520zROiModGfLzs3sNRSFlGcR+1mwAAAYiSMPhzAAAEAwBHMEUCIQDKNva6HXz8Y8j9EBs5ogB+"
        "kN6fmu0TVt4lyYHFPR8GIgIgdaaxL0rbxon3+jSXgQhL2T/"
        "Pm6rmwMzdSPK0dlXeQjEwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEFBQcDAjAKBggrBgEFBQcDATA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3F"
        "QiHvdcbgefrRoKBnS6O0AyH8NodXYKE5WmC86c+"
        "AgFkAgEmMIGuBggrBgEFBQcBAQSBoTCBnjBtBggrBgEFBQcwAoZhaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3"
        "NvZnQlMjBBenVyZSUyMFRMUyUyMElzc3VpbmclMjBDQSUyMDA2JTIwLSUyMHhzaWduLmNydDAtBggrBgEFBQcwAYYhaHR0cDovL29uZW9jc3Au"
        "bWljcm9zb2Z0LmNvbS9vY3NwMB0GA1UdDgQWBBSgrq/a22chE4wNaQLZexgsZwaT4DAOBgNVHQ8BAf8EBAMCBaAwggF/"
        "BgNVHREEggF2MIIBcoIbKi5ldmVudHMuZGF0YS5taWNyb3NvZnQuY29tghlldmVudHMuZGF0YS5taWNyb3NvZnQuY29tghkqLnBpcGUuYXJpYS"
        "5taWNyb3NvZnQuY29tgg5waXBlLnNreXBlLmNvbYIQKi5waXBlLnNreXBlLmNvbYIiKi5tb2JpbGUuZXZlbnRzLmRhdGEubWljcm9zb2Z0LmNv"
        "bYIgbW9iaWxlLmV2ZW50cy5kYXRhLm1pY3Jvc29mdC5jb22CFSouZXZlbnRzLmRhdGEubXNuLmNvbYITZXZlbnRzLmRhdGEubXNuLmNvbYIUKi"
        "5ldmVudHMuZGF0YS5tc24uY26CEmV2ZW50cy5kYXRhLm1zbi5jboIRb2NhLm1pY3Jvc29mdC5jb22CFHdhdHNvbi5taWNyb3NvZnQuY29tghsq"
        "LnZvcnRleC5kYXRhLm1pY3Jvc29mdC5jb22CGXZvcnRleC5kYXRhLm1pY3Jvc29mdC5jb20wDAYDVR0TAQH/"
        "BAIwADBkBgNVHR8EXTBbMFmgV6BVhlNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBBenVyZSUyMFRMUy"
        "UyMElzc3VpbmclMjBDQSUyMDA2LmNybDBmBgNVHSAEXzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jv"
        "c29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wCAYGZ4EMAQICMB8GA1UdIwQYMBaAFNXBZzrCo530d1JbWRI4KeZVaLulMB0GA1"
        "UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATANBgkqhkiG9w0BAQwFAAOCAgEAjx4AB+gsiOX0hu6puwc/"
        "6BMI1Oc9UDJvMrOKQ9BIUlGZSJCQHWnMs43FAEhWlNiSE41rwNzJkreSdI90IwNc1DMWs2bskVWvZ8pDVXpu12/"
        "xngr9yGw1HaKSbZoAcMa1o4qx2ctORe9kbOhYR+jEv7sle5xTEIKgYw7lDM91+/"
        "VCrLJPD1NJWQHWeWKm4c201ZuZtEMBPQps8AaOFSKteJoBsF+Mn/le89ibBwxv6X/"
        "OEPG+96YfStbK3VtsGIa6LGulS1lHtZYneQXUCRciQ4myDujQjBbPUPhHSwydUlgE4f/"
        "aF7WDun5fOOaogFUE9dHbXHi67Ap79FMc224AcdmLG32dzso2x1DWac8aV5M1nTP8NQ7xdlfzIYHegZo5G6/"
        "epEb+AKbXxYkXu1Pe2nvrt2rpuJ63qbuJ8HmcFYg/o/K5EFpTcaCuj80aLo6/JHUrMEWxsG3IEb9b7ULLmd7e8MMpZr/A5kV/"
        "ND3WIOqvvCrTnDh8tvMeZxRxfH+bG9Y+"
        "4a3elV5UH9OFCmZJd6FGlZW8MIzCgGGtEoQfD5rnc0WZhaWt3TfUp14pIYqdP2Xe5G2FSyKku0Br3W52c7bEqp8U3a9bUOeOieech3rRnqN/"
        "M5eeKrWlFRZ3fKpGVsaaZqt8pqHxZ+wdmsNzng73LaO+V0dap19CvNRvzXoABfcwggXzMIIE26ADAgECAhAC55Fx+4Ah6T/"
        "i2YODTFDAMA0GCSqGSIb3DQEBDAUAMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vyd"
        "C5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMB4XDTIwMDcyOTEyMzAwMFoXDTI0MDYyNzIzNTk1OVowWTELMAkGA1UEBhM"
        "CVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEqMCgGA1UEAxMhTWljcm9zb2Z0IEF6dXJlIFRMUyBJc3N1aW5nIENBIDA2MIICI"
        "jANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtUYBGXnpvHcoFRIa49zgfm6g0WQUfh7um9MLFGLiP/"
        "7P5dvCMTP7kKKkM6qPH3+NaOyQvl2Ts9pCTMi2J2wACcMJbWV5kE4iLrwt9/VuNN5mAxiLB1F3djf1v+VwamK4/"
        "Z3bdb3lgeQwxPwiVaixghfR/iRhvraumHJ+cCNhv/"
        "g5331OGeGUDEa1+9JtdwFUgoJh9mCpG9X7mVF5Sd3Vo2NFhXM86iJ+"
        "BLHZ9HLLX6k7VTNoww2cg4TvVtVhbQDWGvX3DuQ5vQqQlegAtMMOPW6RQQOpC4F8HFF4vmZeK7U7tYbS+"
        "W2DRVn9JnNy0Gx0GXHUGSZZgFbbrUpmAGK+uqXkQtMop3yqC0dwtADl+XokHRCCzlcNpZ6E3zoamzklbwCuMa2NxYAg/5fwJBpZ9oKe5GboGT/"
        "Tc9BaGB2LzirADSyxF8UnAdQ9M1KcTwSIZWTZ+u3S7w8bWnBJCwW40l9xggcS/W87M/u4Q64PJ2yYKOGXG6grafn/"
        "ZpVHcExO76nj6CXxqVegHJzIuaPcn89SCoPxIvl9MJR6Aax2Jr9JrrQ3ahXu9DXvCMw34tdrauOP9vhmVmBdWiMOYCMPAhF0NS6NC7RFWwmoUs"
        "zNIgemnYJmnuYiguvJJrLZhgG7tKI3Av3lfod7aRLx558EEePPBb/"
        "0XEaqvLnuLvVzZwMCAwEAAaOCAa0wggGpMB0GA1UdDgQWBBTVwWc6wqOd9HdSW1kSOCnmVWi7pTAfBgNVHSMEGDAWgBROIlQgGJXm427mD/"
        "r6uRLtBhePOTAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/"
        "wQIMAYBAf8CAQAwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA"
        "6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMi5jcnQwewYDVR0fBHQwcjA3oDWgM4YxaHR0cDovL2NybDMuZGlna"
        "WNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDA3oDWgM4YxaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9"
        "vdEcyLmNybDAdBgNVHSAEFjAUMAgGBmeBDAECATAIBgZngQwBAgIwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQEMBQADggEBAHahZz3d8"
        "Hx6xyL/x6yLGP743baZ6IYOOAX6sDYtQrkg5A6BxRJMYpKoX2Vh8DE+Ouo+MMJQ8cJRG/7bpp3k/"
        "8Fi1e1ua3Ela75xLkGEwM894beg9nBdEcEkUCRjg7gAXtEgABRboTMN+VSgMcq/"
        "zfM6I99gZykdz2yTEAicJ52TtBKBe8wBGOM6p1qSivbUNOY0hSi3GjyQe/mHBGUaEEnCmzp8RWLUG3S2ukz/fBjGWvjvdZI9QVk+A/"
        "WPnX2QulY4nzPT3DFrL4Gvb2Ks9wFi/"
        "QYxeUepOHLzLib8fJNB4jYgy8ytCfCo+lj6sshfK+"
        "Ija8ugj7jEoThGffxlnyYWAAb1AQAG8TCCBu0KAQCgggbmMIIG4gYJKwYBBQUHMAEBBIIG0zCCBs8wgcWiFgQU3kaDwuMF9+"
        "39W8asodx2uf1KakgYDzIwMjMwODEyMDI1MjQ3WjCBmTCBljBMMAkGBSsOAwIaBQAEFA3VWiJfjSNU4yV2Hu4NOGL0Op57BBTVwWc6wqOd9HdS"
        "W1kSOCnmVWi7pQITMwC2iv5B5Cv9E6HyuAAAALaK/"
        "oAAGA8yMDIzMDgxMjAxMDgyMlqgERgPMjAyMzA4MjAwMTI4MjJaoSAwHjAcBgkrBgEEAYI3FQQEDxcNMjMwODE2MDExODIyWjANBgkqhkiG9w0"
        "BAQsFAAOCAQEAXwyqYXuW7QmyjSg7VuAeStfNNygOSRsEa0bWdoZzlmwOKNLKr/"
        "h5Q214JapF5oHboYV6y1hXv84bjnwmvUtZxUhuZDuDw6bKIyaiA1OmJGDwWYvqDTcTOBtxHmblGwxYsvY4/"
        "Wlm5RaAgnP07coVKsyVB6MFSoG7wi94+UiQXUd5VQdEzy2HsMSKGg5WJL3uCDrQH8NASRCN9aYaS6AQBpxWZ6Fd4zVXgRew/"
        "DPCNHcNyRMRl4nWLIu627kh0szsP6l5jmrK1z7szWBx3t//"
        "Y5Q6haO749B95wg5xzxfVzV9tWd74Yx7vMYLMUt8NwPXMetwungUr7oWlHZocbUVlqCCBO8wggTrMIIE5zCCAs+"
        "gAwIBAgITMwDNSPseuGuzUqjVugAAAM1I+"
        "zANBgkqhkiG9w0BAQwFADBZMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSowKAYDVQQDEyFNaWNyb3NvZnQ"
        "gQXp1cmUgVExTIElzc3VpbmcgQ0EgMDYwHhcNMjMwODA5MTU1MDExWhcNMjMwOTA4MTU1MDExWjAeMRwwGgYDVQQDExNBenVyZUNBMDYgT0NTU"
        "CBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp4i1UI0MAqnYaqj8csYZZnf9iPNGvdAvBh7WQz9yyRrKzQH+"
        "fvA4V0mSvxjqjNLSGlUH3p60SwZjI08/M/2+mVGURGH3TzvOGIciE31VuIIUch5SBYYX9mFr6kLghPLM9y4SiA/"
        "rPgn2kboAxksa5fk9YX40taUdQ+CQlqjBY8F/RKxm3zQ0BTGCGzTVVzIAoRuDryudpUyK+V3dZES4XCY5e4NnCHf/jkt+VCKuw11i/"
        "rm48gGlqK1hXJ7yUPfzK8wjG0brfZxjaQyvlsZYy5HTbiN6vdhIIT3jO+cIy+jFAbyY5lC0LXg5zLhgUY8N3XVS4YZk8END+"
        "wabzF4qqQIDAQABo4HiMIHfMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwkwHQYDVR0OBBYEFN5Gg8LjBfft/"
        "VvGrKHcdrn9SmpIMB8GA1UdIwQYMBaAFNXBZzrCo530d1JbWRI4KeZVaLulMA4GA1UdDwEB/"
        "wQEAwIHgDA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiHvdcbgefrRoKBnS6O0AyH8NodXYPZ1yKB9N4fAgFkAgEXMBsGCSsGAQQBgjcVCgQ"
        "OMAwwCgYIKwYBBQUHAwkwDwYJKwYBBQUHMAEFBAIFADANBgkqhkiG9w0BAQwFAAOCAgEAXEMIVURXnLpA7paHXOGCvgLYv3NMRjGZ0ZpTJGJY5"
        "xFSuwGeeqGB/Ghv4/YQrMhnody2ZSWp4piBCW1cjPfWEHFekL8j8pUylAsDsVTCIztDE2jwemvH5IUlqUPuIuvclWHhBtT2yukU/GnWyLpj/"
        "hQNQb8X6BMSHTpbzo/W97x+QPNglYamPJn9hk2ePgjodFMApLNi1JEaGuuNEgMU2aniSkVJXQRmxgBTU0TJ8gITD/"
        "gVQmlSCkc613oPSWRe9PeReVV6N2tmPLkPrtDGD420cw8p10XWFLEBuV08p/"
        "jECRwlcP9QNcBkKSlwY5OKNTiqi3QESJbh+UrwPMnPiK2j+J8FWxTDAbXVomnvPG+"
        "B09j6NML5Q4Hq00uwud8v6ZxPP3N2j4lplSZO0RhLAfwh5XcICEWH1+KetbiZpVoYfITsgWK3T5DgTGE+"
        "f1n0x1CF48G59JTXHjfc9saHMEuQi7QelP4MokcI+oXQ1HFxvdJ6a+bg7f91WmQHcna1i2I0xHeahyBs7TT4n+rHxOl+"
        "xWcs7sT59q9jZLumRvRDVerSx6rYwUe/1spvo6979lj/"
        "oTu1PG6FVqPCU4kelQ7fxxlcIXd6HGqKRLIMjn7rfoqJjrMD6f+MuqOc6zhTtRiXVNt+"
        "I7QyDynWob9hXatr7lnV0PrL8khH77gzI2EMAAFpAwAYYQTecdNR1L5rxVVXMe7Djp2zNXzMwoqnJg/"
        "0hr4QS1hduMHTwKBXqjb4CGVJbxoc+S/7hjTHGDqWhHCpq9+4SQxcR6MVp65BVNMdGJRLMiHAkUWvivJW4DOanO//"
        "36RFuMQEAQEAUMabZOvBbAa1KSTcWbL5ZGc/YPxLofmSTDMxf+KmqSukiR3yVasPbv5J6Hx2zCATM9pR9VRArg==";

    size_t encoded_len = strlen(encoded_buf);
    unsigned char decoded_buf[nDPId_PACKETS_PLEN_MAX];
    size_t decoded_len = sizeof(decoded_buf);
    if (nDPIsrvd_base64decode(encoded_buf, encoded_len, decoded_buf, &decoded_len) != 0)
    {
        logger(1, "base64_selftest: Could not decode test buffer of size %zu bytes", encoded_len);
        return 1;
    }

    char base64_data[nDPId_PACKETS_PLEN_MAX * 4];
    size_t base64_data_len = sizeof(base64_data);
    if (base64_encode(decoded_buf, decoded_len, base64_data, &base64_data_len) != 0)
    {
        logger(1, "base64_selftest: Re-encoding base64 buffer failed");
        return 1;
    }

    if (base64_data_len != encoded_len)
    {
        logger(1,
               "base64_selftest: Re-encoded base64 buffer size differs: %zu bytes != %zu bytes",
               base64_data_len,
               encoded_len);
        return 1;
    }

    return strncmp(base64_data, encoded_buf, base64_data_len) != 0;
}

static int nio_selftest()
{
    struct nio io;

    nio_init(&io);

#ifdef ENABLE_EPOLL
    logger(0, "%s", "Using epoll for nio");
#else
    logger(0, "%s", "Using poll for nio");
#endif

#ifdef ENABLE_EPOLL
    if (nio_use_epoll(&io, 5) != NIO_ERROR_SUCCESS)
#else
    if (nio_use_poll(&io, 3) != NIO_ERROR_SUCCESS)
#endif
    {
        logger(1, "%s", "Could not use poll/epoll for nio");
        goto error;
    }

    int pipefds[2];
    int rv = pipe(pipefds);
    if (rv < 0)
    {
        logger(1, "Could not create a pipe: %s", strerror(errno));
        goto error;
    }

    if (nio_add_fd(&io, pipefds[1], NIO_EVENT_OUTPUT, NULL) != NIO_ERROR_SUCCESS ||
        nio_add_fd(&io, pipefds[0], NIO_EVENT_INPUT, NULL) != NIO_ERROR_SUCCESS)
    {
        logger(1, "%s", "Could not add pipe fds to nio");
        goto error;
    }

    if (fcntl_add_flags(pipefds[1], O_NONBLOCK) != 0 || fcntl_add_flags(pipefds[0], O_NONBLOCK) != 0)
    {
        logger(1, "%s", "Could not set pipe fds to O_NONBLOCK");
        goto error;
    }

    char const wbuf[] = "AAAA";
    size_t const wlen = strnlen(wbuf, sizeof(wbuf));
    write(pipefds[1], wbuf, wlen);

    if (nio_run(&io, 1000) != NIO_ERROR_SUCCESS)
    {
        logger(1, "%s", "Event notification failed");
        goto error;
    }

    if (nio_can_output(&io, 0) != NIO_ERROR_SUCCESS)
    {
        logger(1, "%s", "Pipe fd (write) can not output");
        goto error;
    }

    if (nio_has_input(&io, 1) != NIO_ERROR_SUCCESS)
    {
        logger(1, "%s", "Pipe fd (read) has no input");
        goto error;
    }

    if (nio_is_valid(&io, 0) != NIO_ERROR_SUCCESS || nio_is_valid(&io, 1) != NIO_ERROR_SUCCESS ||
        nio_has_error(&io, 0) == NIO_ERROR_SUCCESS || nio_has_error(&io, 1) == NIO_ERROR_SUCCESS)
    {
        logger(1, "%s", "Event validation failed");
        goto error;
    }

    char rbuf[4];
    if (read(pipefds[0], rbuf, sizeof(rbuf)) != sizeof(rbuf) || strncmp(rbuf, wbuf, wlen) != 0)
    {
        logger(1, "%s", "Buffer receive failed");
        goto error;
    }

    if (nio_run(&io, 1000) != NIO_ERROR_SUCCESS)
    {
        logger(1, "%s", "Event notification failed");
        goto error;
    }

    if (nio_can_output(&io, 0) != NIO_ERROR_SUCCESS)
    {
        logger(1, "%s", "Pipe fd (write) can not output");
        goto error;
    }

    if (nio_has_input(&io, 1) == NIO_ERROR_SUCCESS)
    {
        logger(1, "%s", "Pipe fd (read) has input");
        goto error;
    }

    if (nio_is_valid(&io, 0) != NIO_ERROR_SUCCESS || nio_is_valid(&io, 1) == NIO_ERROR_SUCCESS ||
        nio_has_error(&io, 0) == NIO_ERROR_SUCCESS || nio_has_error(&io, 1) == NIO_ERROR_SUCCESS)
    {
        logger(1, "%s", "Event validation failed");
        goto error;
    }

    nio_free(&io);
    return 0;
error:
    nio_free(&io);
    return 1;
}

#define THREADS_RETURNED_ERROR()                                                                                       \
    (nDPId_return.thread_return_value.val != 0 || nDPIsrvd_return.val != 0 ||                                          \
     distributor_return.thread_return_value.val != 0)
int main(int argc, char ** argv)
{
    if (argc != 1 && argc != 2)
    {
        usage(argv[0]);
        return 1;
    }

    init_logging("nDPId-test");
    log_app_info();

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
        return 1;
    }

    if (argc == 1)
    {
        int retval = 0;

        usage(argv[0]);
        logger(1, "%s", "No pcap file provided. Running selftest mode.");

        retval += base64_selftest();
        retval += nio_selftest();

        logger(1, "Selftest returned: %d", retval);
        return retval;
    }

    nDPIsrvd_options.max_write_buffers = 32;
    nDPId_options.enable_data_analysis = 1;
    nDPId_options.max_packets_per_flow_to_send = 5;
#ifdef ENABLE_ZLIB
    /*
     * zLib compression is forced enabled for testing.
     * Remember to compile nDPId with zlib enabled.
     * There will be diff's while running `test/run_tests.sh' otherwise.
     */
    nDPId_options.enable_zlib_compression = 1;
#endif
    nDPId_options.memory_profiling_log_interval = (unsigned long long int)-1;
    nDPId_options.reader_thread_count = 1; /* Please do not change this! Generating meaningful pcap diff's relies on a
                                              single reader thread! */
    set_cmdarg(&nDPId_options.instance_alias, "nDPId-test");
    if (access(argv[1], R_OK) != 0)
    {
        logger(1, "%s: pcap file `%s' does not exist or is not readable", argv[0], argv[1]);
        return 1;
    }
    set_cmdarg(&nDPId_options.pcap_file_or_interface, argv[1]);
    if (validate_options() != 0)
    {
        return 1;
    }

    if (setup_pipe(mock_pipefds) != 0 || setup_pipe(mock_testfds) != 0 || setup_pipe(mock_bufffds) != 0 ||
        setup_pipe(mock_nullfds) != 0 || setup_pipe(mock_arpafds) != 0)
    {
        return 1;
    }

    /* We do not have any sockets, any socket operation must fail! */
    collector_un_sockfd = -1;
    distributor_un_sockfd = -1;
    distributor_in_sockfd = -1;

    if (setup_remote_descriptors(MAX_REMOTE_DESCRIPTORS) != 0)
    {
        return 1;
    }

    pthread_t nDPId_thread;
    struct nDPId_return_value nDPId_return = {};
    if (pthread_create(&nDPId_thread, NULL, nDPId_mainloop_thread, &nDPId_return) != 0)
    {
        return 1;
    }

    pthread_t nDPIsrvd_thread;
    struct thread_return_value nDPIsrvd_return = {};
    if (pthread_create(&nDPIsrvd_thread, NULL, nDPIsrvd_mainloop_thread, &nDPIsrvd_return) != 0)
    {
        return 1;
    }

    pthread_t distributor_thread;
    struct distributor_return_value distributor_return = {};
    if (pthread_create(&distributor_thread, NULL, distributor_client_mainloop_thread, &distributor_return) != 0)
    {
        return 1;
    }

    /* Try to gracefully shutdown all threads. */
    while (thread_wait_for_termination(distributor_thread, 1, &distributor_return.thread_return_value) == 0)
    {
        if (THREADS_RETURNED_ERROR() != 0)
        {
            break;
        }
    }

    while (thread_wait_for_termination(nDPId_thread, 1, &nDPId_return.thread_return_value) == 0)
    {
        if (THREADS_RETURNED_ERROR() != 0)
        {
            break;
        }
    }

    while (thread_wait_for_termination(nDPIsrvd_thread, 1, &nDPIsrvd_return) == 0)
    {
        if (THREADS_RETURNED_ERROR() != 0)
        {
            break;
        }
    }

    logger(0, "%s", "All worker threads terminated..");

    if (THREADS_RETURNED_ERROR() != 0)
    {
        char const * which_thread = "Unknown";
        int thread_errno = 0;

        if (nDPId_return.thread_return_value.val != 0)
        {
            which_thread = "nDPId";
            thread_errno = nDPId_return.thread_return_value.val;
        }
        else if (nDPIsrvd_return.val != 0)
        {
            which_thread = "nDPIsrvd";
            thread_errno = nDPIsrvd_return.val;
        }
        else if (distributor_return.thread_return_value.val != 0)
        {
            which_thread = "Distributor";
            thread_errno = distributor_return.thread_return_value.val;
        }

        logger(1,
               "%s Thread returned a non zero value: %d (%s)",
               which_thread,
               thread_errno,
               (thread_errno < 0 ? strerror(thread_errno) : "Application specific error"));
        return 1;
    }

    {
        printf(
            "~~~~~~~~~~~~~~~~~~~~ SUMMARY ~~~~~~~~~~~~~~~~~~~~\n"
            "~~ packets captured/processed: %llu/%llu\n"
            "~~ skipped flows.............: %llu\n"
            "~~ total layer4 data length..: %llu bytes\n"
            "~~ total detected protocols..: %llu\n"
            "~~ total active/idle flows...: %llu/%llu\n"
            "~~ total timeout flows.......: %llu\n"
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
            nDPId_return.packets_captured,
            nDPId_return.packets_processed,
            nDPId_return.total_skipped_flows,
            nDPId_return.total_l4_payload_len,
            nDPId_return.detected_flow_protocols,
            nDPId_return.total_active_flows,
            nDPId_return.total_idle_flows,
            distributor_return.stats.total_flow_timeouts);

        unsigned long long int total_alloc_bytes =
#ifdef ENABLE_ZLIB
            (unsigned long long int)(MT_GET_AND_ADD(ndpi_memory_alloc_bytes, 0) -
                                     MT_GET_AND_ADD(zlib_compression_bytes, 0) -
                                     (MT_GET_AND_ADD(zlib_compressions, 0) * sizeof(struct nDPId_detection_data)));
#else
            (unsigned long long int)MT_GET_AND_ADD(ndpi_memory_alloc_bytes, 0);
#endif
        unsigned long long int total_free_bytes =
#ifdef ENABLE_ZLIB
            (unsigned long long int)(MT_GET_AND_ADD(ndpi_memory_free_bytes, 0) -
                                     MT_GET_AND_ADD(zlib_compression_bytes, 0) -
                                     (MT_GET_AND_ADD(zlib_compressions, 0) * sizeof(struct nDPId_detection_data)));
#else
            (unsigned long long int)MT_GET_AND_ADD(ndpi_memory_free_bytes, 0);
#endif

        unsigned long long int total_alloc_count =
#ifdef ENABLE_ZLIB
            (unsigned long long int)(MT_GET_AND_ADD(ndpi_memory_alloc_count, 0) -
                                     MT_GET_AND_ADD(zlib_compressions, 0) * 2);
#else
            (unsigned long long int)MT_GET_AND_ADD(ndpi_memory_alloc_count, 0);
#endif

        unsigned long long int total_free_count =
#ifdef ENABLE_ZLIB
            (unsigned long long int)(MT_GET_AND_ADD(ndpi_memory_free_count, 0) -
                                     MT_GET_AND_ADD(zlib_decompressions, 0) * 2);
#else
            (unsigned long long int)MT_GET_AND_ADD(ndpi_memory_free_count, 0);
#endif

        printf(
            "~~ total memory allocated....: %llu bytes\n"
            "~~ total memory freed........: %llu bytes\n"
            "~~ total allocations/frees...: %llu/%llu\n"
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
            total_alloc_bytes -
                sizeof(struct nDPId_workflow) *
                    nDPId_options.reader_thread_count /* We do not want to take the workflow into account. */,
            total_free_bytes -
                sizeof(struct nDPId_workflow) *
                    nDPId_options.reader_thread_count /* We do not want to take the workflow into account. */,
            total_alloc_count,
            total_free_count);

        printf(
            "~~ json string min len.......: %llu chars\n"
            "~~ json string max len.......: %llu chars\n"
            "~~ json string avg len.......: %llu chars\n",
            distributor_return.stats.json_string_len_min,
            distributor_return.stats.json_string_len_max,
            (unsigned long long int)distributor_return.stats.json_string_len_avg);
    }

    if (MT_GET_AND_ADD(ndpi_memory_alloc_bytes, 0) != MT_GET_AND_ADD(ndpi_memory_free_bytes, 0) ||
        MT_GET_AND_ADD(ndpi_memory_alloc_count, 0) != MT_GET_AND_ADD(ndpi_memory_free_count, 0) ||
        nDPId_return.total_active_flows != nDPId_return.total_idle_flows)
    {
        logger(1, "%s: %s", argv[0], "Memory / Flow leak detected.");
        logger(1,
               "%s: Allocated / Free'd bytes: %llu / %llu",
               argv[0],
               (unsigned long long int)MT_GET_AND_ADD(ndpi_memory_alloc_bytes, 0),
               (unsigned long long int)MT_GET_AND_ADD(ndpi_memory_free_bytes, 0));
        logger(1,
               "%s: Allocated / Free'd count: %llu / %llu",
               argv[0],
               (unsigned long long int)MT_GET_AND_ADD(ndpi_memory_alloc_count, 0),
               (unsigned long long int)MT_GET_AND_ADD(ndpi_memory_free_count, 0));
        logger(1,
               "%s: Total Active / Idle Flows: %llu / %llu",
               argv[0],
               nDPId_return.total_active_flows,
               nDPId_return.total_idle_flows);
        return 1;
    }

    if (nDPIsrvd_alloc_bytes != nDPIsrvd_free_bytes || nDPIsrvd_alloc_count != nDPIsrvd_free_count)
    {
        logger(1, "%s: %s", argv[0], "nDPIsrvd.h memory leak detected.");
        logger(1, "%s: Allocated / Free'd bytes: %llu / %llu", argv[0], nDPIsrvd_alloc_bytes, nDPIsrvd_free_bytes);
        logger(1, "%s: Allocated / Free'd count: %llu / %llu", argv[0], nDPIsrvd_alloc_count, nDPIsrvd_free_count);
        return 1;
    }

    if (nDPId_return.cur_active_flows != 0 || nDPId_return.cur_idle_flows != 0)
    {
        logger(1,
               "%s: %s [%llu / %llu]",
               argv[0],
               "Active / Idle inconsistency detected.",
               nDPId_return.cur_active_flows,
               nDPId_return.cur_idle_flows);
        return 1;
    }

    if (nDPId_return.total_skipped_flows != 0)
    {
        logger(1,
               "%s: %s [%llu]",
               argv[0],
               "Skipped flow detected, that should not happen.",
               nDPId_return.total_skipped_flows);
        return 1;
    }

    if (nDPId_return.total_events_serialized != distributor_return.stats.total_events_deserialized ||
        nDPId_return.total_events_serialized != distributor_return.stats.total_events_serialized)
    {
        logger(1,
               "%s: Event count of nDPId and distributor not equal: %llu != %llu",
               argv[0],
               nDPId_return.total_events_serialized,
               distributor_return.stats.total_events_deserialized);
        return 1;
    }

    if (nDPId_return.packets_processed != distributor_return.stats.total_packets_processed)
    {
        logger(1,
               "%s: Total nDPId and distributor packets processed not equal: %llu != %llu",
               argv[0],
               nDPId_return.packets_processed,
               distributor_return.stats.total_packets_processed);
        return 1;
    }

    if (nDPId_return.total_l4_payload_len != distributor_return.stats.total_l4_payload_len)
    {
        logger(1,
               "%s: Total processed layer4 payload length of nDPId and distributor not equal: %llu != %llu",
               argv[0],
               nDPId_return.total_l4_payload_len,
               distributor_return.stats.total_l4_payload_len);
        return 1;
    }

    if (distributor_return.stats.flow_new_count !=
        distributor_return.stats.flow_end_count + distributor_return.stats.flow_idle_count)
    {
        logger(1,
               "%s: Amount of flow 'new' events received is not equal to the amount of 'end' plus 'idle': %llu != "
               "%llu + %llu",
               argv[0],
               distributor_return.stats.flow_new_count,
               distributor_return.stats.flow_end_count,
               distributor_return.stats.flow_idle_count);
        return 1;
    }

    if (nDPId_return.total_active_flows !=
        distributor_return.stats.flow_end_count + distributor_return.stats.flow_idle_count)
    {
        logger(1,
               "%s: Amount of total active flows is not equal to the amount of received 'end' plus 'idle' events: "
               "%llu != %llu + %llu",
               argv[0],
               nDPId_return.total_active_flows,
               distributor_return.stats.flow_end_count,
               distributor_return.stats.flow_idle_count);
        return 1;
    }

    if (nDPId_return.total_idle_flows !=
        distributor_return.stats.flow_idle_count + distributor_return.stats.flow_end_count)
    {
        logger(1,
               "%s: Amount of total idle flows is not equal to the amount of received 'idle' events: %llu != %llu",
               argv[0],
               nDPId_return.total_idle_flows,
               distributor_return.stats.flow_idle_count);
        return 1;
    }

    if (nDPId_return.not_detected_flow_protocols != distributor_return.stats.flow_not_detected_count)
    {
        logger(1,
               "%s: Amount of total undetected flows is not equal to the amount of received 'not-detected' events: "
               "%llu != %llu",
               argv[0],
               nDPId_return.not_detected_flow_protocols,
               distributor_return.stats.flow_not_detected_count);
        return 1;
    }

    if (nDPId_return.guessed_flow_protocols != distributor_return.stats.flow_guessed_count)
    {
        logger(1,
               "%s: Amount of total guessed flows is not equal to the amount of received 'guessed' events: %llu != "
               "%llu",
               argv[0],
               nDPId_return.guessed_flow_protocols,
               distributor_return.stats.flow_guessed_count);
        return 1;
    }

    if (nDPId_return.detected_flow_protocols != distributor_return.stats.flow_detected_count)
    {
        logger(1,
               "%s: Amount of total detected flows not equal to the amount of received 'detected' events: %llu != "
               "%llu",
               argv[0],
               nDPId_return.detected_flow_protocols,
               distributor_return.stats.flow_detected_count);
        return 1;
    }

    if (nDPId_return.flow_detection_updates != distributor_return.stats.flow_detection_update_count)
    {
        logger(1,
               "%s: Amount of total detection updates is not equal to the amount of received 'detection-update' "
               "events: %llu != %llu",
               argv[0],
               nDPId_return.flow_detection_updates,
               distributor_return.stats.flow_detection_update_count);
        return 1;
    }

    if (nDPId_return.flow_updates != distributor_return.stats.flow_update_count)
    {
        logger(1,
               "%s: Amount of total flow updates is not equal to the amount of received 'update' events: %llu != "
               "%llu",
               argv[0],
               nDPId_return.flow_updates,
               distributor_return.stats.flow_update_count);
        return 1;
    }

    if (nDPId_return.total_active_flows > distributor_return.stats.flow_detected_count +
                                              distributor_return.stats.flow_guessed_count +
                                              distributor_return.stats.flow_not_detected_count)
    {
        logger(1,
               "%s: Amount of total active flows not equal to the amount of received 'detected', 'guessed and "
               "'not-detected' flow events: %llu != "
               "%llu + %llu + %llu",
               argv[0],
               nDPId_return.total_active_flows,
               distributor_return.stats.flow_detected_count,
               distributor_return.stats.flow_guessed_count,
               distributor_return.stats.flow_not_detected_count);
        return 1;
    }

    if (distributor_return.stats.instance_user_data.daemon_event_count !=
        distributor_return.stats.thread_user_data.daemon_event_count)
    {
        logger(1,
               "%s: Amount of received daemon events differs between instance and thread: %llu != %llu",
               argv[0],
               distributor_return.stats.instance_user_data.daemon_event_count,
               distributor_return.stats.thread_user_data.daemon_event_count);
        return 1;
    }

    if (distributor_return.stats.instance_user_data.flow_cleanup_count - distributor_return.stats.total_flow_timeouts !=
        distributor_return.stats.flow_end_count + distributor_return.stats.flow_idle_count)
    {
        logger(1,
               "%s: Amount of flow cleanup callback calls differs between received 'end' and 'idle' flow events: %llu "
               "!= %llu + %llu",
               argv[0],
               distributor_return.stats.instance_user_data.flow_cleanup_count -
                   distributor_return.stats.total_flow_timeouts,
               distributor_return.stats.flow_end_count,
               distributor_return.stats.flow_idle_count);
        return 1;
    }

    if (distributor_return.stats.flow_new_count != distributor_return.stats.thread_user_data.flow_new_count ||
        distributor_return.stats.flow_end_count != distributor_return.stats.thread_user_data.flow_end_count ||
        distributor_return.stats.flow_idle_count != distributor_return.stats.thread_user_data.flow_idle_count)
    {
        logger(1,
               "%s: Thread user data counters not equal to the global user data counters: %llu != %llu or %llu != %llu "
               "or %llu != %llu",
               argv[0],
               distributor_return.stats.flow_new_count,
               distributor_return.stats.thread_user_data.flow_new_count,
               distributor_return.stats.flow_end_count,
               distributor_return.stats.thread_user_data.flow_end_count,
               distributor_return.stats.flow_idle_count,
               distributor_return.stats.thread_user_data.flow_idle_count);
        return 1;
    }

#ifdef ENABLE_ZLIB
    if (MT_GET_AND_ADD(zlib_compressions, 0) != MT_GET_AND_ADD(zlib_decompressions, 0))
    {
        logger(1,
               "%s: %s (%llu != %llu)",
               argv[0],
               "ZLib compression / decompression inconsistency detected.",
               (unsigned long long int)MT_GET_AND_ADD(zlib_compressions, 0),
               (unsigned long long int)MT_GET_AND_ADD(zlib_decompressions, 0));
        return 1;
    }
    if (nDPId_return.current_compression_diff != 0)
    {
        logger(1,
               "%s: %s (%llu bytes)",
               argv[0],
               "ZLib compression inconsistency detected. It should be 0.",
               nDPId_return.current_compression_diff);
        return 1;
    }
    if (nDPId_return.total_compressions != MT_GET_AND_ADD(zlib_compressions, 0))
    {
        logger(1,
               "%s: %s (%llu != %llu)",
               argv[0],
               "ZLib global<->workflow compression / decompression inconsistency detected.",
               (unsigned long long int)MT_GET_AND_ADD(zlib_compressions, 0),
               nDPId_return.current_compression_diff);
        return 1;
    }
    if (nDPId_return.total_compression_diff != MT_GET_AND_ADD(zlib_compression_bytes, 0))
    {
        logger(1,
               "%s: %s (%llu bytes != %llu bytes)",
               argv[0],
               "ZLib global<->workflow compression / decompression inconsistency detected.",
               (unsigned long long int)MT_GET_AND_ADD(zlib_compression_bytes, 0),
               nDPId_return.total_compression_diff);
        return 1;
    }
#endif

    return 0;
}
