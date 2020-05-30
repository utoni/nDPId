#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <ndpi/ndpi_main.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct nDPId_workflow {
    pcap_t * pcap_handle;
    struct timeval last_packet_received;

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

static struct nDPId_workflow * init_workflow(void)
{
    struct nDPId_workflow * workflow = (struct nDPId_workflow *)ndpi_calloc(1, sizeof(*workflow));

    if (workflow == NULL) {
        return NULL;
    }

    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (workflow->ndpi_struct == NULL) {
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

static void free_workflow(struct nDPId_workflow ** const workflow)
{
    if (*workflow == NULL) {
        return;
    }

    if ((*workflow)->ndpi_struct != NULL) {
        ndpi_exit_detection_module((*workflow)->ndpi_struct);
    }
    ndpi_free(*workflow);
    *workflow = NULL;
}

static int setup_detection(struct nDPId_workflow * const workflow)
{
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    if (workflow == NULL) {
        return 1;
    }

    workflow->pcap_handle = pcap_open_live("wifi0" /* "lo" */, /* 1536 */ 65535, 1, 250, pcap_error_buffer);
    if (workflow->pcap_handle == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", pcap_error_buffer);
        return 1;
    }

    return 0;
}

static void free_detection(struct nDPId_workflow * const workflow)
{
    if (workflow == NULL) {
        return;
    }

    if (workflow->pcap_handle != NULL) {
        pcap_close(workflow->pcap_handle);
        workflow->pcap_handle = NULL;
    }
}

static int setup_reader_threads(void)
{
    if (reader_thread_count > MAX_READER_THREADS) {
        return 1;
    }

    for (int i = 0; i < reader_thread_count; ++i) {
        reader_threads[i].workflow = init_workflow();
        if (reader_threads[i].workflow == NULL ||
            setup_detection(reader_threads[i].workflow) != 0)
        {
            return 1;
        }
    }

    return 0;
}

static void print_packet_info(int thread_array_index,
                              const struct pcap_pkthdr * const header,
                              uint16_t type, uint8_t proto,
                              const char * const src_addr,
                              const char * const dst_addr)
{
    char buf[256];
    int used = 0, ret;

    ret = snprintf(buf, sizeof(buf), "[%lu:%lu, ThreadID %d, %u bytes] ",
                   header->ts.tv_sec, header->ts.tv_usec, thread_array_index, header->caplen);
    if (ret > 0) {
        used += ret;
    }

    switch (type) {
        case ETH_P_IP:
            ret = snprintf(buf + used, sizeof(buf) - used, "IP[%s -> %s]",
                           src_addr, dst_addr);
            break;
        case ETH_P_IPV6:
            ret = snprintf(buf + used, sizeof(buf) - used, "IP6[%s -> %s]",
                           src_addr, dst_addr);
            break;
        default:
            ret = snprintf(buf + used, sizeof(buf) - used, "Unknown[0x%X]", type);
            break;
    }
    if (ret > 0) {
        used += ret;
    }

    switch (proto) {
        case IPPROTO_UDP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> UDP");
            break;
        case IPPROTO_TCP:
            ret = snprintf(buf + used, sizeof(buf) - used, " -> TCP");
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
            ret = snprintf(buf + used, sizeof(buf) - used, " -> Unknown[0x%X]", proto);
            break;
    }
    if (ret > 0) {
        used += ret;
    }

    printf("%.*s\n", used, buf);
}

static void ndpi_process_packet(uint8_t * const args,
                                const struct pcap_pkthdr * const header,
                                const u_char * const packet)
{
    struct nDPId_reader_thread * const reader_thread =
        (struct nDPId_reader_thread *)args;
    struct nDPId_workflow * workflow;

    const struct ndpi_ethhdr * ethernet;
    const struct ndpi_iphdr * ip;
    const struct ndpi_ipv6hdr * ip6;
    const uint16_t eth_offset = 0;
    uint16_t ip_offset;
    uint16_t type;
    uint16_t frag_off = 0;
    uint8_t proto;
    int thread_index;
    char src_addr_str[INET6_ADDRSTRLEN+1] = {0};
    char dst_addr_str[INET6_ADDRSTRLEN+1] = {0};

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
            if (ntohl(*((u_int32_t*)&packet[eth_offset])) == 2) {
                type = ETH_P_IP;
            } else {
                type = ETH_P_IPV6;
            }
            ip_offset = 4 + eth_offset;
            break;
        case DLT_EN10MB:
            if (header->caplen < sizeof(struct ndpi_ethhdr)) {
                fprintf(stderr, "Ethernet packet too short - skipping\n");
                return;
            }
            ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
            ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
            type = ntohs(ethernet->h_proto);
            switch (type) {
                case ETH_P_IP: /* IPv4 */
                    if (header->caplen < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                        fprintf(stderr, "IP packet too short - skipping\n");
                        return;
                    }
                    break;
                case ETH_P_IPV6: /* IPV6 */
                    if (header->caplen < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                        fprintf(stderr, "IPv6 packet too short - skipping\n");
                        return;
                    }
                    break;
                case ETH_P_ARP: /* ARP */
                    printf("%s\n", "ARP - skipping");
                    return;
                default:
                    fprintf(stderr, "Invalid Ethernet packet with type 0x%X - skipping\n", type);
                    return;
            }
            break;
        default:
            fprintf(stderr, "Received non IP/Ethernet packet with datalink type 0x%X - skipping\n",
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
        fprintf(stderr, "Received non IP packet with type 0x%X - skipping\n", type);
        return;
    }

    /* just work on Ethernet packets that contain IP */
    if (type == ETH_P_IP && header->caplen >= ip_offset) {
        frag_off = ntohs(ip->frag_off);
        if (header->caplen < header->len) {
            fprintf(stderr, "Captured packet size is smaller than packet size: %u < %u\n",
                    header->caplen, header->len);
        }
    }

    if (ip != NULL && ip->version == 4) {
        proto = ip->protocol;

        if ((frag_off & 0x1FFF) != 0) {
            fprintf(stderr, "IPv4 fragments are not handled by this demo (nDPI supports them)\n");
            return;
        }

        uint32_t min_addr = (ip->saddr > ip->daddr ? ip->daddr : ip->saddr);
        thread_index = min_addr % reader_thread_count;

        uint32_t src_addr = ip->saddr;
        uint32_t dst_addr = ip->daddr;
        inet_ntop(AF_INET, (struct sockaddr_in *)&src_addr, src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET, (struct sockaddr_in *)&dst_addr, dst_addr_str, sizeof(dst_addr_str));
    } else if (ip6 != NULL && ip6->ip6_hdr.ip6_un1_flow == 0x60) {
        proto = ip6->ip6_hdr.ip6_un1_nxt;

        uint32_t min_addr[4];
        if (ip6->ip6_src.u6_addr.u6_addr64[0] > ip6->ip6_dst.u6_addr.u6_addr64[0] &&
            ip6->ip6_src.u6_addr.u6_addr64[1] > ip6->ip6_dst.u6_addr.u6_addr64[1])
        {
            min_addr[0] = ip6->ip6_dst.u6_addr.u6_addr32[0];
            min_addr[1] = ip6->ip6_dst.u6_addr.u6_addr32[1];
            min_addr[2] = ip6->ip6_dst.u6_addr.u6_addr32[2];
            min_addr[3] = ip6->ip6_dst.u6_addr.u6_addr32[3];
        } else {
            min_addr[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
            min_addr[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
            min_addr[2] = ip6->ip6_src.u6_addr.u6_addr32[2];
            min_addr[3] = ip6->ip6_src.u6_addr.u6_addr32[3];
        }
        thread_index = min_addr[0] + min_addr[1] + min_addr[2] + min_addr[3];
        thread_index %= reader_thread_count;

        inet_ntop(AF_INET6, (struct sockaddr_in6 *)&ip6->ip6_src.u6_addr.u6_addr8[0],
                  src_addr_str, sizeof(src_addr_str));
        inet_ntop(AF_INET6, (struct sockaddr_in6 *)&ip6->ip6_dst.u6_addr.u6_addr8[0],
                  dst_addr_str, sizeof(dst_addr_str));
    } else {
        return;
    }

    if (thread_index != reader_thread->array_index) {
        return;
    }

    print_packet_info(reader_thread->array_index, header, type, proto,
                      src_addr_str, dst_addr_str);
}

static void run_pcap_loop(struct nDPId_reader_thread * const reader_thread)
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
    struct nDPId_reader_thread * const reader_thread =
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
            continue;;
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

        free_detection(reader_threads[i].workflow);
        free_workflow(&reader_threads[i].workflow);
    }

    return 0;
}

void sighandler(int signum)
{
    fprintf(stderr, "Got a %d\n", signum);
    main_thread_shutdown = 1;
    if (stop_reader_threads() != 0) {
        fprintf(stderr, "Failed to stop reader threads!\n");
        exit(EXIT_FAILURE);
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
