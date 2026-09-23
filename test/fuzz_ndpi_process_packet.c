#include <sys/mman.h> // memfd_create()

#define NO_MAIN 1
#include "../utils.c"
#include "../nio.c"
#include "../nDPId.c"
#ifdef ENABLE_PFRING
#include "../npfring.c"
#endif

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    if (reader_threads[0].workflow == NULL)
    {
        ndpi_set_memory_alloction_functions(ndpi_malloc_wrapper, ndpi_free_wrapper, ndpi_calloc_wrapper,
                                            ndpi_realloc_wrapper, NULL, NULL, NULL, NULL);

        init_logging("fuzz_ndpi_process_packet");
        log_app_info();
        enable_console_logger();

        set_cmdarg_string(&nDPId_options.instance_alias, "fuzz_ndpi_process_packet");
        set_cmdarg_ull(&nDPId_options.error_event_threshold_n, 0u);
        set_cmdarg_ull(&nDPId_options.error_event_threshold_time, 0u);
        set_cmdarg_ull(&nDPId_options.generic_max_idle_time, 5u);
        set_cmdarg_ull(&nDPId_options.icmp_max_idle_time, 2u);
        set_cmdarg_ull(&nDPId_options.tcp_max_idle_time, 5u);
        set_cmdarg_ull(&nDPId_options.udp_max_idle_time, 2u);
        set_cmdarg_ull(&nDPId_options.tcp_max_post_end_flow_time, 1u);
        set_cmdarg_ull(&nDPId_options.max_flows_per_thread, 65535);
        set_cmdarg_ull(&nDPId_options.max_idle_flows_per_thread, 1024);
        set_cmdarg_ull(&nDPId_options.reader_thread_count, 1);
        set_cmdarg_boolean(&nDPId_options.enable_data_analysis, 1);
        set_cmdarg_ull(&nDPId_options.max_packets_per_flow_to_send, 5);
#ifdef ENABLE_ZLIB
        set_cmdarg_boolean(&nDPId_options.enable_zlib_compression, 1);
#endif
#ifdef ENABLE_MEMORY_PROFILING
        set_cmdarg_ull(&nDPId_options.memory_profiling_log_interval, TIME_S_TO_US(60u));
#endif
#ifdef ENABLE_PFRING
        set_cmdarg_boolean(&nDPId_options.use_pfring, 0);
#endif

        struct nDPId_workflow * const workflow = (struct nDPId_workflow *)ndpi_calloc(1, sizeof(*workflow));
        if (workflow == NULL)
        {
            return 1;
        }
        workflow->max_idle_flows = GET_CMDARG_ULL(nDPId_options.max_idle_flows_per_thread);
        workflow->max_active_flows = GET_CMDARG_ULL(nDPId_options.max_flows_per_thread);
        workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
        workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
        reader_threads[0].collector_sockfd = memfd_create("collector", MFD_CLOEXEC);
        reader_threads[0].workflow = workflow;

        if (reader_threads[0].collector_sockfd < 0 ||
            set_collector_nonblock(&reader_threads[0]) != 0)
        {
            return 1;
        }

        if (workflow->ndpi_flows_idle == NULL || workflow->ndpi_flows_active == NULL)
        {
            return 1;
        }

        global_context = ndpi_global_init();
        if (global_context == NULL)
        {
            return 1;
        }

        workflow->ndpi_struct = ndpi_init_detection_module(global_context, NDPI_LICENSE_NOT_FOR_PROFIT_LGPL);
        if (workflow->ndpi_struct == NULL)
        {
            return 1;
        }
        ndpi_set_user_data(workflow->ndpi_struct, workflow);
        set_ndpi_debug_function(workflow->ndpi_struct, ndpi_debug_printf);
        ndpi_finalize_initialization(workflow->ndpi_struct);
    }

    struct pcap_pkthdr pcap_hdr = {.caplen = size, .len = size};
    if (size >= 8)
        pcap_hdr.ts.tv_sec = get_u_int64_t(data, 0);
    ndpi_process_packet((uint8_t *)&reader_threads[0], &pcap_hdr, data);

    char cbuf[BUFSIZ];
    ssize_t bytes_read = 0;
    while ((bytes_read = read(reader_threads[0].collector_sockfd, cbuf, sizeof(cbuf))) > 0)
    {
    }

    struct timeval tval;
    get_current_time(&tval);
    uint64_t tval_us = tval.tv_sec * 1000 * 1000 + tval.tv_usec;
    reader_threads[0].workflow->last_global_time += tval_us;

    return 0;
}
