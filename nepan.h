#ifndef NEPAN_H
#define NEPAN_H 1

#include <ndpi_api.h>
#include <pcap/pcap.h>
#include <stdint.h>

/*
 * Initialize the Wireshark EPAN library.
 * Must be called once before any other nepan_* function.
 * Returns 0 on success, 1 on failure.
 */
int nepan_init(void);

/*
 * Release all resources held by the EPAN library.
 * Must be called after all threads have finished dissecting.
 */
void nepan_cleanup(void);

/*
 * Return the Wireshark library version string.
 */
const char * nepan_get_version(void);

/*
 * Dissect a raw packet and serialize the results into @serializer.
 *
 * @serializer   nDPI JSON serializer to write fields into.
 * @wtap_encap   Wiretap encapsulation type (from wtap_pcap_encap_to_wtap_encap()).
 * @header       libpcap packet header (timestamp, caplen, len).
 * @packet       Raw packet bytes.
 *
 * The function appends the following fields to the serializer:
 *   "epan_proto_stack"  – colon-separated list of top-level protocol names
 *                         (e.g. "eth:ip:tcp:http").
 *   "epan_fields"       – JSON object containing notable field abbreviation /
 *                         value pairs extracted from the dissected tree
 *                         (e.g. "ip.src", "tcp.dstport", "http.host", …).
 */
void nepan_jsonize(ndpi_serializer * serializer,
                   int wtap_encap,
                   struct pcap_pkthdr const * header,
                   uint8_t const * packet);

#endif /* NEPAN_H */
