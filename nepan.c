#include "nepan.h"

#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/expert.h>
#include <epan/frame_data.h>
#include <epan/ftypes/ftypes.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/addr_resolv.h>
#include <epan/wmem_scopes.h>
#include <wiretap/wtap.h>
#include <wiretap/pcap-encap.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>

#include <pthread.h>
#include <string.h>

#include "utils.h"

static epan_t *               nepan_session       = NULL;
static pthread_mutex_t        nepan_mutex         = PTHREAD_MUTEX_INITIALIZER;
static guint32                nepan_frame_num     = 0;
static guint32                nepan_cum_bytes     = 0;
static nstime_t               nepan_elapsed_time  = NSTIME_INIT_ZERO;
static frame_data             nepan_first_fdata;
static const frame_data *     nepan_frame_ref     = NULL;
static int                    nepan_provider_ctx  = 0;

static const nstime_t * nepan_provider_get_frame_ts(struct packet_provider_data * prov,
                                                    guint32 frame_num)
{
    (void)prov;
    (void)frame_num;
    return NULL;
}

static const char * nepan_provider_get_interface_name(struct packet_provider_data * prov,
                                                      uint32_t interface_id,
                                                      unsigned section_number)
{
    (void)prov;
    (void)interface_id;
    (void)section_number;
    return "nDPId";
}

static const char * nepan_provider_get_interface_description(struct packet_provider_data * prov,
                                                             uint32_t interface_id,
                                                             unsigned section_number)
{
    (void)prov;
    (void)interface_id;
    (void)section_number;
    return NULL;
}

static wtap_block_t nepan_provider_get_modified_block(struct packet_provider_data * prov,
                                                      const frame_data * fd)
{
    (void)prov;
    (void)fd;
    return NULL;
}

static const struct packet_provider_funcs nepan_provider_funcs = {
    .get_frame_ts = nepan_provider_get_frame_ts,
    .get_interface_name = nepan_provider_get_interface_name,
    .get_interface_description = nepan_provider_get_interface_description,
    .get_modified_block = nepan_provider_get_modified_block,
};

static void nepan_log(const char *fmt, va_list ap)
{
    vlogger(1, fmt, ap);
}

int nepan_init(void)
{
    init_process_policies();
    ws_log_init("nDPId", nepan_log);
    wtap_init(false);

    if (epan_init(NULL, NULL, FALSE) == FALSE)
    {
        return 1;
    }

    nepan_session = epan_new((struct packet_provider_data *)&nepan_provider_ctx,
                             &nepan_provider_funcs);
    if (nepan_session == NULL)
    {
        return 1;
    }

    gbl_resolv_flags.maxmind_geoip         = FALSE;
    gbl_resolv_flags.mac_name              = FALSE;
    gbl_resolv_flags.network_name          = FALSE;
    gbl_resolv_flags.transport_name        = FALSE;
    gbl_resolv_flags.dns_pkt_addr_resolution = FALSE;

    return 0;
}

void nepan_cleanup(void)
{
    if (nepan_session != NULL)
    {
        epan_free(nepan_session);
        nepan_session = NULL;
    }
    epan_cleanup();
    wtap_cleanup();
    pthread_mutex_destroy(&nepan_mutex);
}

const char * nepan_get_version(void)
{
    return epan_get_version();
}

static int build_proto_stack(proto_node const * tree_root,
                              char * buf,
                              int buf_size)
{
    int len = 0;

    for (proto_node const * child = tree_root->first_child;
         child != NULL;
         child = child->next)
    {
        field_info const * const fi = PNODE_FINFO(child);
        if (fi == NULL || fi->hfinfo == NULL || fi->hfinfo->abbrev == NULL ||
            fi->hfinfo->abbrev[0] == '\0')
        {
            continue;
        }

        int const abbrev_len = (int)strlen(fi->hfinfo->abbrev);
        int const needed = (len > 0 ? 1 : 0) + abbrev_len + 1;
        if (len + needed > buf_size)
        {
            break;
        }

        if (len > 0)
        {
            buf[len++] = ':';
        }
        memcpy(buf + len, fi->hfinfo->abbrev, (size_t)abbrev_len);
        len += abbrev_len;
    }

    buf[len] = '\0';
    return len;
}

#define NEPAN_FIELD_MAX_DEPTH 8

static void serialize_fields(ndpi_serializer * const serializer,
                             wmem_allocator_t * const pool,
                             proto_node const * node,
                             int depth)
{
    if (depth > NEPAN_FIELD_MAX_DEPTH || node == NULL)
    {
        return;
    }

    for (; node != NULL; node = node->next)
    {
        field_info const * const fi = PNODE_FINFO(node);

        if (fi != NULL && fi->hfinfo != NULL && fi->hfinfo->abbrev != NULL &&
            fi->hfinfo->abbrev[0] != '\0' && fi->value != NULL)
        {
            int skip = 0;

            ftenum_t val_type = fvalue_type_ftenum(fi->value);
            switch (val_type) {
                case FT_BYTES:
                    if (strcmp(fi->hfinfo->abbrev, "udp.payload") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "tcp.payload") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "data.data") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "ssh.encrypted_packet") == 0)
                    {
                        skip = 1;
                    }
                    break;
                case FT_STRING:
                    if (strcmp(fi->hfinfo->abbrev, "tcp.completeness.str") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "tcp.flags.str") == 0)
                    {
                        skip = 1;
                    }
                    break;
                default:
                    break;
            }

            if (skip != 0) {
                continue;
            }

            char * val_str = fvalue_to_string_repr(pool,
                                                   fi->value,
                                                   FTREPR_DISPLAY,
                                                   fi->hfinfo->display);
            if (val_str != NULL && val_str[0] != '\0')
            {
                ndpi_serialize_string_string(serializer,
                                             fi->hfinfo->abbrev,
                                             val_str);
            }
        }

        if (node->first_child != NULL)
        {
            serialize_fields(serializer, pool, node->first_child, depth + 1);
        }
    }
}

void nepan_jsonize(ndpi_serializer * const serializer,
                   int wtap_encap,
                   struct pcap_pkthdr const * const header,
                   uint8_t const * const packet)
{
    if (nepan_session == NULL)
    {
        return;
    }

    wtap_rec rec;
    frame_data fd;
    epan_dissect_t * edt;

    memset(&rec, 0, sizeof(rec));
    rec.rec_type                           = REC_TYPE_PACKET;
    rec.presence_flags                     = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    rec.ts.secs                            = header->ts.tv_sec;
    rec.ts.nsecs                           = (int)(header->ts.tv_usec * 1000);
    rec.tsprec                             = WTAP_TSPREC_USEC;
    rec.rec_header.packet_header.caplen    = header->caplen;
    rec.rec_header.packet_header.len       = header->len;
    rec.rec_header.packet_header.pkt_encap = wtap_encap;

    pthread_mutex_lock(&nepan_mutex);

    nepan_frame_num++;
    frame_data_init(&fd, nepan_frame_num, &rec, 0, nepan_cum_bytes);
    frame_data_set_before_dissect(&fd, &nepan_elapsed_time, &nepan_frame_ref, NULL);

    if (nepan_frame_num == 1)
    {
        nepan_first_fdata                   = fd;
        nepan_first_fdata.pfd               = NULL;
        nepan_first_fdata.dependent_frames  = NULL;
        nepan_frame_ref                     = &nepan_first_fdata;
    }

    tvbuff_t * const tvb = tvb_new_real_data(packet, header->caplen, header->len);
    edt = epan_dissect_new(nepan_session, TRUE, TRUE);
    epan_dissect_run(edt, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, &rec, tvb, &fd, NULL);

    if (edt->tree != NULL)
    {
        char proto_stack[256];
        int  proto_stack_len = build_proto_stack(edt->tree, proto_stack, (int)sizeof(proto_stack));

        if (proto_stack_len > 0)
        {
            ndpi_serialize_string_string(serializer, "epan_proto_stack", proto_stack);
        }

        if (edt->tree->first_child != NULL)
        {
            ndpi_serialize_start_of_block(serializer, "epan_fields");
            serialize_fields(serializer, edt->pi.pool, edt->tree->first_child, 0);
            ndpi_serialize_end_of_block(serializer);
        }
    }

    frame_data_set_after_dissect(&fd, &nepan_cum_bytes);
    epan_dissect_free(edt);
    frame_data_destroy(&fd);

    pthread_mutex_unlock(&nepan_mutex);
}
