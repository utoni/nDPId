#ifndef PFRING_H
#define PFRING_H 1

#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"

struct npfring
{
    void * pfring_desc;
    uint8_t pfring_buffer[PFRING_BUFFER_SIZE];
};

struct npfring_stats
{
    uint64_t recv;
    uint64_t drop;
    uint64_t shunt;
};

void npfring_print_version(FILE * const out);

int npfring_init(char const * device_name, uint32_t caplen, struct npfring * result);

void npfring_close(struct npfring * npf);

int npfring_set_bpf(struct npfring * npf, char const * bpf_filter);

int npfring_datalink(struct npfring * npf);

int npfring_enable(struct npfring * npf);

int npfring_get_selectable_fd(struct npfring * npf);

int npfring_recv(struct npfring * npf, struct pcap_pkthdr * pf_hdr);

int npfring_stats(struct npfring * npf, struct npfring_stats * stats);

#endif
