#ifndef NEPAN_H
#define NEPAN_H 1

#include <ndpi_api.h>
#include <pcap/pcap.h>
#include <stdint.h>

int nepan_init(void);

void nepan_cleanup(void);

const char * nepan_get_version(void);

void nepan_jsonize(ndpi_serializer * serializer,
                   int wtap_encap,
                   struct pcap_pkthdr const * header,
                   uint8_t const * packet);

#endif /* NEPAN_H */
