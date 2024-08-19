#include <pfring.h>
#include <sched.h>

#include "npfring.h"
#include "utils.h"

void npfring_print_version(FILE * const out)
{
    uint32_t pfring_version;

    pfring_version_noring(&pfring_version);
    fprintf(out,
            "PF_RING version: %d.%d.%d\n",
            (pfring_version & 0xFFFF0000) >> 16,
            (pfring_version & 0x0000FF00) >> 8,
            (pfring_version & 0x000000FF));
}

int npfring_init(char const * device_name, uint32_t caplen, struct npfring * result)
{
    pfring * pd = pfring_open(device_name, caplen, PF_RING_REENTRANT | PF_RING_PROMISC);

    if (pd == NULL)
    {
        return -1;
    }

    pfring_set_application_name(pd, "nDPId");
    logger_early(0, "PF_RING RX channels: %d", pfring_get_num_rx_channels(pd));
    result->pfring_desc = pd;

    int rc;
    if ((rc = pfring_set_socket_mode(pd, recv_only_mode)) != 0)
    {
        logger_early(1, "pfring_set_sock_moode returned: %d", rc);
        return -1;
    }

    return 0;
}

void npfring_close(struct npfring * npf)
{
    if (npf->pfring_desc != NULL)
    {
        pfring_close(npf->pfring_desc);
        npf->pfring_desc = NULL;
    }
}

int npfring_set_bpf(struct npfring * npf, char const * bpf_filter)
{
    char buf[BUFSIZ];

    if (npf->pfring_desc == NULL)
    {
        return -1;
    }

    // pfring_set_bpf_filter expects a char*
    snprintf(buf, sizeof(buf), "%s", bpf_filter);
    return pfring_set_bpf_filter(npf->pfring_desc, buf);
}

int npfring_datalink(struct npfring * npf)
{
    if (npf->pfring_desc != NULL)
    {
        return pfring_get_link_type(npf->pfring_desc);
    }

    return -1;
}

int npfring_enable(struct npfring * npf)
{
    if (npf->pfring_desc == NULL)
    {
        return -1;
    }

    return pfring_enable_ring(npf->pfring_desc);
}

int npfring_get_selectable_fd(struct npfring * npf)
{
    if (npf->pfring_desc == NULL)
    {
        return -1;
    }

    return pfring_get_selectable_fd(npf->pfring_desc);
}

int npfring_recv(struct npfring * npf, struct pcap_pkthdr * pcap_hdr)
{
    int rc;

    if (npf->pfring_desc == NULL || pcap_hdr == NULL)
    {
        return -1;
    }

    unsigned char * buf = &npf->pfring_buffer[0];
    struct pfring_pkthdr pfring_pkthdr;
    rc = pfring_recv(npf->pfring_desc, &buf, PFRING_BUFFER_SIZE, &pfring_pkthdr, 0);
    if (rc > 0)
    {
        pcap_hdr->ts = pfring_pkthdr.ts;
        pcap_hdr->caplen = pfring_pkthdr.caplen;
        pcap_hdr->len = pfring_pkthdr.len;
    }
    else
    {
        pcap_hdr->ts.tv_sec = 0;
        pcap_hdr->ts.tv_usec = 0;
        pcap_hdr->caplen = 0;
        pcap_hdr->len = 0;
    }

    return rc;
}

int npfring_stats(struct npfring * npf, struct npfring_stats * stats)
{
    int rc;

    if (npf->pfring_desc == NULL)
    {
        return -1;
    }

    pfring_stat pstats;
    rc = pfring_stats(npf->pfring_desc, &pstats);
    if (rc == 0)
    {
        stats->recv = pstats.recv;
        stats->drop = pstats.drop;
        stats->shunt = pstats.shunt;
    }
    else
    {
        stats->drop = 0;
        stats->recv = 0;
        stats->shunt = 0;
    }

    return rc;
}
