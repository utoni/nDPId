#ifndef NEPAN_H
#define NEPAN_H 1

#include <ndpi_api.h>
#include <pcap/pcap.h>
#include <stdint.h>

#define NEPAN_KEY_MAX (64ull)
#define NEPAN_VAL_MAX (8192ull * 2ull)

struct nepan_worker
{
    int ipc_fd;
    pid_t pid;
};

struct nepan_ctx
{
    struct nepan_worker epan_worker;
    char keybuf[NEPAN_KEY_MAX];
    char valbuf[NEPAN_VAL_MAX];
};

void nepan_set_arg0(char const * const arg0);

int nepan_init(struct nepan_ctx * const ctx);

void nepan_cleanup(struct nepan_ctx * const ctx);

const char * nepan_get_version(void);

void nepan_jsonize(struct nepan_ctx * const ctx,
                   ndpi_serializer * serializer,
                   int wtap_encap,
                   struct pcap_pkthdr const * header,
                   uint8_t const * packet);

int nepan_worker_run_if_requested(int argc, char ** argv);

#endif /* NEPAN_H */
