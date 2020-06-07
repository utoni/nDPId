#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <ndpi/ndpi_api.h>
#include <ndpi/ndpi_main.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum nDPId_l3_type {
    L3_IP, L3_IP6
};

struct nDPId_flow_info {
    uint32_t flow_id;
    uint64_t hashval;
    enum nDPId_l3_type l3_type;
    union {
        struct {
            uint32_t src;
            uint32_t dst;
        } v4;
        struct {
            uint64_t src[2];
            uint64_t dst[2];
        } v6;
    } ip_tuple;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t detection_completed, protocol, bidirectional, check_extra_packets;
    struct ndpi_flow_struct * ndpi_flow;
};

struct nDPId_workflow {
    pcap_t * pcap_handle;
    struct timeval last_packet_received;

    void ** ndpi_flows_root;
    size_t max_available_flows;
    size_t num_allocated_flows;
    struct ndpi_detection_module_struct * ndpi_struct;
};

struct nDPId_reader_thread {
    struct nDPId_workflow * workflow;
    pthread_t thread_id;
    int array_index;
};

#define MAX_READER_THREADS 8
static struct nDPId_reader_thread reader_threads[MAX_READER_THREADS] = {};
static int reader_thread_count = MAX_READER_THREADS;
static int main_thread_shutdown = 0;
static uint32_t flow_id = 0;

static struct nDPId_workflow * init_workflow(void)
{
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    struct nDPId_workflow * workflow = (struct nDPId_workflow *)ndpi_calloc(1, sizeof(*workflow));

    if (workflow == NULL) {
        return NULL;
    }

    workflow->pcap_handle = pcap_open_live("wifi0" /* "lo" */, /* 1536 */ 65535, 1, 250, pcap_error_buffer);
    if (workflow->pcap_handle == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", pcap_error_buffer);
        return NULL;
    }

    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (workflow->ndpi_struct == NULL) {
        return NULL;
    }

    workflow->num_allocated_flows = 0;
    workflow->max_available_flows = 1024;
    workflow->ndpi_flows_root = (void **)ndpi_calloc(workflow->max_available_flows, sizeof(void *));
    if (workflow->ndpi_flows_root == NULL) {
        return NULL;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
#if NDPI_MAJOR >= 3 && NDPI_MINOR >= 2
    ndpi_finalize_initalization(workflow->ndpi_struct);
#endif
    return workflow;
}

static void ndpi_flow_info_freer(void * const node)
{
    struct nDPId_flow_info * const flow = (struct nDPId_flow_info *)node;

    ndpi_flow_free(flow->ndpi_flow);
    ndpi_free(flow);
}

static void free_workflow(struct nDPId_workflow ** const workflow)
{
    struct nDPId_workflow * const w = *workflow;

    if (w == NULL) {
        return;
    }

    if (w->pcap_handle != NULL) {
        pcap_close(w->pcap_handle);
        w->pcap_handle = NULL;
    }

    if (w->ndpi_struct != NULL) {
        ndpi_exit_detection_module(w->ndpi_struct);
    }
    for(size_t i = 0; i < w->max_available_flows; i++) {
        ndpi_tdestroy(w->ndpi_flows_root[i], ndpi_flow_info_freer);
    }
    ndpi_free(w->ndpi_flows_root);
    ndpi_free(w);
    *workflow = NULL;
}

static int setup_reader_threads(void)
{
    if (reader_thread_count > MAX_READER_THREADS) {
        return 1;
    }

    for (int i = 0; i < reader_thread_count; ++i) {
        reader_threads[i].workflow = init_workflow();
        if (reader_threads[i].workflow == NULL)
        {
            return 1;
        }
    }

    return 0;
}

static void print_packet_info(int thread_array_index,
                              struct pcap_pkthdr const * const header,
                              uint16_t type, uint32_t l4_data_len,
                              struct nDPId_flow_info const * const flow)
{
    char src_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char dst_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char buf[256];
    int used = 0, ret;

    ret = snprintf(buf, sizeof(buf), "[%lu:%lu, ThreadID %d, %u bytes] ",
                   header->ts.tv_sec, header->ts.tv_usec, thread_array_index, header->caplen);
    if (ret > 0) {
        used += ret;
    }

    switch (type) {
        case ETH_P_IP:
            inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.src, src_addr_str, sizeof(src_addr_str));
            inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.dst, dst_addr_str, sizeof(dst_addr_str));
            ret = snprintf(buf + used, sizeof(buf) - used, "IP[%s -> %s]",
                           src_addr_str, dst_addr_str);
            break;
        case ETH_P_IPV6:
            inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0],
                      src_addr_str, sizeof(src_addr_str));
            inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0],
                      dst_addr_str, sizeof(dst_addr_str));
            ret = snprintf(buf + used, sizeof(buf) - used, "IP6[%s -> %s]",
                           src_addr_str, dst_addr_str);
            break;
        default:
            ret = snprintf(buf + used, sizeof(buf) - used, "Unknown[0x%X]", type);
            break;
    }
    if (ret > 0) {
        used += ret;
    }

    switch (flow->protocol) {
        case IPPROTO_UDP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> UDP[%u -> %u, %u bytes]",
                           flow->src_port, flow->dst_port, l4_data_len);
            break;
        case IPPROTO_TCP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> TCP[%u -> %u, %u bytes]",
                           flow->src_port, flow->dst_port, l4_data_len);
            break;
        case IPPROTO_ICMP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> ICMP");
            break;
        case IPPROTO_ICMPV6:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> ICMP6");
            break;
        case IPPROTO_HOPOPTS:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> ICMP6 Hop-By-Hop");
            break;
        default:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> Unknown[0x%X]", flow->protocol);
            break;
    }
    if (ret > 0) {
        used += ret;
    }

    printf("%.*s\n", used, buf);
}

static int ip_tuples_equal(struct nDPId_flow_info const * const A,
                           struct nDPId_flow_info const * const B)
{
    if (A->l3_type == L3_IP && B->l3_type == L3_IP6) {
        return A->ip_tuple.v4.src == B->ip_tuple.v4.src &&
               A->ip_tuple.v4.dst == B->ip_tuple.v4.dst;
    } else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
        return A->ip_tuple.v6.src[0] == B->ip_tuple.v6.src[0] &&
               A->ip_tuple.v6.src[1] == B->ip_tuple.v6.src[1] &&
               A->ip_tuple.v6.dst[0] == B->ip_tuple.v6.dst[0] &&
               A->ip_tuple.v6.dst[1] == B->ip_tuple.v6.dst[1];
    }
    return 0;
}

static int ip_tuples_compare(struct nDPId_flow_info const * const A,
                             struct nDPId_flow_info const * const B)
{
    if (A->l3_type == L3_IP && B->l3_type == L3_IP6) {
        if (A->ip_tuple.v4.src < B->ip_tuple.v4.src ||
            A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
        {
            return -1;
        }
        if (A->ip_tuple.v4.src > B->ip_tuple.v4.src ||
            A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
        {
            return 1;
        }
    } else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
        if ((A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] &&
             A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1]) ||
            (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] &&
             A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1]))
        {
            return -1;
        }
        if ((A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] &&
             A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1]) ||
            (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] &&
             A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1]))
        {
            return 1;
        }
    }
    if (A->src_port < B->src_port ||
        A->dst_port < B->dst_port)
    {
        return -1;
    } else if (A->src_port > B->src_port ||
               A->dst_port > B->dst_port)
    {
        return 1;
    }
    return 0;
}

#if 0
static void ndpi_workflow_node_walk(void const * const A, ndpi_VISIT which, int depth,
                                    void * const user_data)
{
    struct nDPId_flow_info const * const flow_info = (struct nDPId_flow_info *)A;

    (void)depth;
    (void)user_data;

    switch (which) {
        case ndpi_preorder:
            break;
        case ndpi_postorder:
            break;
        case ndpi_endorder:
            break;
        case ndpi_leaf:
            printf("PTR: %p\n", flow_info);
            break;
    }
}
#endif

static int ndpi_workflow_node_cmp(void const * const A, void const * const B) {
    struct nDPId_flow_info const * const flow_info_a = (struct nDPId_flow_info *)A;
    struct nDPId_flow_info const * const flow_info_b = (struct nDPId_flow_info *)B;

    if (flow_info_a->hashval < flow_info_b->hashval) {
        return(-1);
    } else if (flow_info_a->hashval > flow_info_b->hashval) {
        return(1);
    }

    /* Flows have the same hash */
    if (flow_info_a->protocol < flow_info_b->protocol) {
        return(-1);
    } else if (flow_info_a->protocol > flow_info_b->protocol) {
        return(1);
    }

    if (ip_tuples_equal(flow_info_a, flow_info_b) != 0 &&
        flow_info_a->src_port == flow_info_b->src_port &&
        flow_info_a->dst_port == flow_info_b->dst_port)
    {
        return(0);
    }

    return ip_tuples_compare(flow_info_a, flow_info_b);
}

static void ndpi_process_packet(uint8_t * const args,
                                struct pcap_pkthdr const * const header,
                                uint8_t const * const packet)
{
    struct nDPId_reader_thread * const reader_thread =
        (struct nDPId_reader_thread *)args;
    struct nDPId_workflow * workflow;
    struct nDPId_flow_info flow = {};
    void * tree_result;
    struct nDPId_flow_info * flow_to_process;
    size_t hashed_index;

    const struct ndpi_ethhdr * ethernet;
    const struct ndpi_iphdr * ip;
    const struct ndpi_ipv6hdr * ip6;

    const uint16_t eth_offset = 0;
    uint16_t ip_offset;
    uint16_t l4_offset;
    uint32_t l4_data_len = 0;
    uint16_t type;
    uint16_t frag_off = 0;
    int thread_index;

    if (reader_thread == NULL) {
        return;
    }
    workflow = reader_thread->workflow;

    if (workflow == NULL) {
        return;
    }
    workflow->last_packet_received = header->ts;

    switch (pcap_datalink(workflow->pcap_handle)) {
        case DLT_NULL:
            if (ntohl(*((uint32_t *)&packet[eth_offset])) == 0x00000002) {
                type = ETH_P_IP;
            } else {
                type = ETH_P_IPV6;
            }
            ip_offset = 4 + eth_offset;
            break;
        case DLT_EN10MB:
            if (header->len < sizeof(struct ndpi_ethhdr)) {
                fprintf(stderr, "Ethernet packet too short - skipping\n");
                return;
            }
            ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
            ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
            type = ntohs(ethernet->h_proto);
            switch (type) {
                case ETH_P_IP: /* IPv4 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                        fprintf(stderr, "IP packet too short - skipping\n");
                        return;
                    }
                    break;
                case ETH_P_IPV6: /* IPV6 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                        fprintf(stderr, "IP6 packet too short - skipping\n");
                        return;
                    }
                    break;
                case ETH_P_ARP: /* ARP */
                    printf("%s\n", "ARP - skipping");
                    return;
                default:
                    fprintf(stderr, "Unknown Ethernet packet with type 0x%X - skipping\n", type);
                    return;
            }
            break;
        default:
            fprintf(stderr, "Captured non IP/Ethernet packet with datalink type 0x%X - skipping\n",
                    pcap_datalink(workflow->pcap_handle));
            return;
    }

    if (type == ETH_P_IP) {
        ip = (struct ndpi_iphdr *)&packet[ip_offset];
        ip6 = NULL;
    } else if (type == ETH_P_IPV6) {
        ip = NULL;
        ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    } else {
        fprintf(stderr, "Captured non IPv4/IPv6 packet with type 0x%X - skipping\n", type);
        return;
    }

    if (type == ETH_P_IP && header->len >= ip_offset) {
        frag_off = ntohs(ip->frag_off);
        if (header->caplen < header->len) {
            fprintf(stderr, "Captured packet size is smaller than packet size: %u < %u\n",
                    header->caplen, header->len);
        }
    }

    if (ip != NULL && ip->version == 4) {
        flow.l3_type = L3_IP;
        flow.protocol = ip->protocol;
        l4_offset = ip_offset + sizeof(*ip);

        if ((frag_off & 0x1FFF) != 0) {
            fprintf(stderr, "IP fragments are not handled by this demo (nDPI supports them)\n");
            return;
        }

        flow.ip_tuple.v4.src = ip->saddr;
        flow.ip_tuple.v4.dst = ip->daddr;
        uint32_t min_addr = (flow.ip_tuple.v4.src > flow.ip_tuple.v4.dst ?
                             flow.ip_tuple.v4.dst : flow.ip_tuple.v4.src);
        thread_index = min_addr % reader_thread_count;
    } else if (ip6 != NULL) {
        if (ip6->ip6_hdr.ip6_un1_plen < header->len - ip_offset - sizeof(ip6->ip6_hdr)) {
            fprintf(stderr, "IP6 payload length smaller than packet size: %u < %lu\n",
                    ip6->ip6_hdr.ip6_un1_plen, header->len - ip_offset + sizeof(ip6->ip6_hdr));
        }

        flow.l3_type = L3_IP6;
        flow.protocol = ip6->ip6_hdr.ip6_un1_nxt;
        l4_offset = ip_offset + sizeof(ip6->ip6_hdr);

        flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
        uint64_t min_addr[2];
        if (flow.ip_tuple.v6.src[0] > flow.ip_tuple.v6.dst[0] &&
            flow.ip_tuple.v6.src[1] > flow.ip_tuple.v6.dst[1])
        {
            min_addr[0] = flow.ip_tuple.v6.dst[0];
            min_addr[1] = flow.ip_tuple.v6.dst[0];
        } else {
            min_addr[0] = flow.ip_tuple.v6.src[0];
            min_addr[1] = flow.ip_tuple.v6.src[0];
        }
        thread_index = min_addr[0] + min_addr[1];
        thread_index %= reader_thread_count;
    } else {
        fprintf(stderr, "Non IP/IPv6 protocol detected: 0x%X\n", type);
        return;
    }

    if (thread_index != reader_thread->array_index) {
        return;
    }

    if (flow.protocol == IPPROTO_TCP) {
        const struct ndpi_tcphdr * tcp;

        if (header->len < l4_offset + sizeof(struct ndpi_tcphdr)) {
            fprintf(stderr, "Malformed TCP packet, packet size smaller than expected: %u < %zu\n",
                            header->len, l4_offset + sizeof(struct ndpi_tcphdr));
            return;
        }
        tcp = (struct ndpi_tcphdr *)&packet[l4_offset];
        flow.src_port = ntohs(tcp->source);
        flow.dst_port = ntohs(tcp->dest);
        l4_data_len = header->len - l4_offset - sizeof(struct ndpi_tcphdr);
    } else if (flow.protocol == IPPROTO_UDP) {
        const struct ndpi_udphdr * udp;

        if (header->len < l4_offset + sizeof(struct ndpi_udphdr)) {
            fprintf(stderr, "Malformed UDP packet, packet size smaller than expected: %u < %zu\n",
                            header->len, l4_offset + sizeof(struct ndpi_udphdr));
            return;
        }
        udp = (struct ndpi_udphdr *)&packet[l4_offset];
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);
        l4_data_len = header->len - l4_offset - sizeof(struct ndpi_udphdr);
    }

    print_packet_info(reader_thread->array_index, header, type, l4_data_len, &flow);

    if (flow.l3_type == L3_IP) {
        flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst;
    } else if (flow.l3_type == L3_IP6) {
        flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
        flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
    }
    flow.hashval += flow.protocol + flow.src_port + flow.dst_port;

    hashed_index = flow.hashval % workflow->max_available_flows;
    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_root[hashed_index], ndpi_workflow_node_cmp);
    if (tree_result == NULL) {
        uint64_t orig_src_ip[2] = { flow.ip_tuple.v6.src[0], flow.ip_tuple.v6.src[1] };
        uint64_t orig_dst_ip[2] = { flow.ip_tuple.v6.dst[0], flow.ip_tuple.v6.dst[1] };
        uint16_t orig_src_port = flow.src_port;
        uint16_t orig_dst_port = flow.dst_port;

        flow.ip_tuple.v6.src[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.src[1] = orig_dst_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_src_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_src_ip[1];
        flow.src_port = orig_dst_port;
        flow.dst_port = orig_src_port;

        tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_root[hashed_index], ndpi_workflow_node_cmp);
        flow.ip_tuple.v6.src[0] = orig_src_ip[0];
        flow.ip_tuple.v6.src[1] = orig_src_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_dst_ip[1];
        flow.src_port = orig_src_port;
        flow.dst_port = orig_dst_port;
    }

    if (tree_result == NULL) {
        if (workflow->num_allocated_flows == workflow->max_available_flows) {
            fprintf(stderr, "Max flows to track reached: %zu\n", workflow->max_available_flows);
            return;
        }

        flow_to_process = (struct nDPId_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
        if (flow_to_process == NULL) {
            fprintf(stderr, "Not enough memory for flow info\n");
            return;
        }

        workflow->num_allocated_flows++;
        memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
        flow_to_process->flow_id = flow_id++;

        flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
        if (flow_to_process->ndpi_flow == NULL) {
            fprintf(stderr, "Not enough memory for flow struct\n");
            return;
        }
        memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

        printf("New flow with id %u\n", flow_to_process->flow_id);
        ndpi_tsearch(flow_to_process, &workflow->ndpi_flows_root[hashed_index], ndpi_workflow_node_cmp); /* Add */
    } else {
        flow_to_process = *(struct nDPId_flow_info **)tree_result;
    }
}

static void run_pcap_loop(struct nDPId_reader_thread const * const reader_thread)
{
    if (reader_thread->workflow != NULL &&
        reader_thread->workflow->pcap_handle != NULL) {

        if (pcap_loop(reader_thread->workflow->pcap_handle, -1,
            &ndpi_process_packet, (uint8_t *)reader_thread) == PCAP_ERROR) {

            printf("Error while reading pcap file: '%s'\n",
                   pcap_geterr(reader_thread->workflow->pcap_handle));
        }
    }
}

static void break_pcap_loop(struct nDPId_reader_thread * const reader_thread)
{
    if (reader_thread->workflow != NULL &&
        reader_thread->workflow->pcap_handle != NULL)
    {
        pcap_breakloop(reader_thread->workflow->pcap_handle);
    }
}

static void * processing_thread(void * const ndpi_thread_arg)
{
    struct nDPId_reader_thread const * const reader_thread =
        (struct nDPId_reader_thread *)ndpi_thread_arg;

    printf("Starting ThreadID %d\n", reader_thread->array_index);
    run_pcap_loop(reader_thread);
    return NULL;
}

static int start_reader_threads(void)
{
    sigset_t thread_signal_set, old_signal_set;

    sigfillset(&thread_signal_set);
    sigdelset(&thread_signal_set, SIGINT);
    sigdelset(&thread_signal_set, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &thread_signal_set, &old_signal_set) != 0) {
        fprintf(stderr, "pthread_sigmask: %s\n", strerror(errno));
        return 1;
    }

    for (int i = 0; i < reader_thread_count; ++i) {
        reader_threads[i].array_index = i;

        if (reader_threads[i].workflow == NULL) {
            /* no more threads should be started */
            break;
        }

        if (pthread_create(&reader_threads[i].thread_id, NULL,
            processing_thread, &reader_threads[i]) != 0)
        {
            fprintf(stderr, "pthread_create: %s\n", strerror(errno));
            return 1;
        }
    }

    if (pthread_sigmask(SIG_BLOCK, &old_signal_set, NULL) != 0) {
        fprintf(stderr, "pthread_sigmask: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}

static int stop_reader_threads(void)
{
    for (int i = 0; i < reader_thread_count; ++i) {
        break_pcap_loop(&reader_threads[i]);
    }

    for (int i = 0; i < reader_thread_count; ++i) {
        if (reader_threads[i].workflow == NULL) {
            continue;
        }

        printf("Stopping ThreadID %d\n", reader_threads[i].array_index);
    }

    for (int i = 0; i < reader_thread_count; ++i) {
        if (reader_threads[i].workflow == NULL) {
            continue;
        }

        if (pthread_join(reader_threads[i].thread_id, NULL) != 0) {
            fprintf(stderr, "pthread_join: %s\n", strerror(errno));
        }

        free_workflow(&reader_threads[i].workflow);
    }

    return 0;
}

static void sighandler(int signum)
{
    fprintf(stderr, "Got a %d\n", signum);

    if (main_thread_shutdown == 0) {
        main_thread_shutdown = 1;
        if (stop_reader_threads() != 0) {
            fprintf(stderr, "Failed to stop reader threads!\n");
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "Reader threads are already shutting down, please be patient.\n");
    }
}

int main(int argc, char ** argv)
{
    if (argc == 0) {
        return 1;
    }

    if (setup_reader_threads() != 0) {
        fprintf(stderr, "%s: setup_reader_threads failed\n", argv[0]);
        return 1;
    }

    if (start_reader_threads() != 0) {
        fprintf(stderr, "%s: start_reader_threads\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    while (main_thread_shutdown == 0) {
        sleep(1);
    }

    if (stop_reader_threads() != 0) {
        fprintf(stderr, "%s: stop_reader_threads\n", argv[0]);
        return 1;
    }

    return 0;
}
