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
        set_ndpi_malloc(ndpi_malloc_wrapper);
        set_ndpi_free(ndpi_free_wrapper);
        set_ndpi_flow_malloc(NULL);
        set_ndpi_flow_free(NULL);

        init_logging("fuzz_ndpi_process_packet");
        log_app_info();

        set_cmdarg_string(&nDPId_options.instance_alias, "fuzz_ndpi_process_packet");
        set_cmdarg_ull(&nDPId_options.max_flows_per_thread, 1024);
        set_cmdarg_ull(&nDPId_options.max_idle_flows_per_thread, 16);
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
        reader_threads[0].collector_sockfd = -1;
        reader_threads[0].workflow = workflow;

        if (workflow->ndpi_flows_idle == NULL || workflow->ndpi_flows_active == NULL)
        {
            return 1;
        }

        global_context = ndpi_global_init();
        if (global_context == NULL)
        {
            return 1;
        }

        workflow->ndpi_struct = ndpi_init_detection_module(global_context);
        if (workflow->ndpi_struct == NULL)
        {
            return 1;
        }
        ndpi_set_user_data(workflow->ndpi_struct, workflow);
        set_ndpi_debug_function(workflow->ndpi_struct, ndpi_debug_printf);
        ndpi_finalize_initialization(workflow->ndpi_struct);
    }

    struct pcap_pkthdr pcap_hdr = {.caplen = size, .len = size};
    gettimeofday(&pcap_hdr.ts, NULL); // not optimal; more difficult to reproduce via crash files
    ndpi_process_packet((uint8_t *)&reader_threads[0], &pcap_hdr, data);

    return 0;
}
