#include "nepan.h"

#include <epan/epan.h>
#include <epan/epan_dissect.h>
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

/* --------------------------------------------------------------------------
 * Module-private global state
 * All accesses to these variables must be protected by nepan_mutex.
 * Wireshark EPAN shares global wmem scopes and is NOT thread-safe.
 * -------------------------------------------------------------------------- */

static epan_t *               nepan_session       = NULL;
static pthread_mutex_t        nepan_mutex         = PTHREAD_MUTEX_INITIALIZER;
static guint32                nepan_frame_num     = 0;
static guint32                nepan_cum_bytes     = 0;
static nstime_t               nepan_elapsed_time  = NSTIME_INIT_ZERO;
static frame_data             nepan_first_fdata;
static const frame_data *     nepan_frame_ref     = NULL;
/* Opaque context token passed to the packet provider callbacks (never read). */
static int                    nepan_provider_ctx  = 0;

/* --------------------------------------------------------------------------
 * Packet-provider callbacks required by epan_new()
 * -------------------------------------------------------------------------- */

static const nstime_t * nepan_provider_get_frame_ts(struct packet_provider_data * prov,
                                                     guint32 frame_num)
{
    (void)prov;
    (void)frame_num;
    return NULL;
}

static const char * nepan_provider_get_interface_name(struct packet_provider_data * prov,
                                                       guint32 interface_id)
{
    (void)prov;
    (void)interface_id;
    return "nDPId";
}

static const char * nepan_provider_get_interface_description(struct packet_provider_data * prov,
                                                              guint32 interface_id)
{
    (void)prov;
    (void)interface_id;
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
    nepan_provider_get_frame_ts,
    nepan_provider_get_interface_name,
    nepan_provider_get_interface_description,
    nepan_provider_get_modified_block,
};

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int nepan_init(void)
{
    init_process_policies();
    ws_log_init("nDPId", NULL);
    wtap_init(FALSE);

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

    /* Disable address-resolution features that crash without their databases. */
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

/* --------------------------------------------------------------------------
 * Tree-walking helpers
 * -------------------------------------------------------------------------- */

/*
 * Build a colon-separated proto abbreviation stack by iterating over the
 * immediate children of the root dissection tree node (each child represents
 * one top-level protocol layer).
 *
 * Returns the number of bytes written to @buf (excluding the NUL terminator),
 * or 0 if the tree is empty.  @buf is always NUL-terminated.
 */
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
        /* Need space for separator (if not first), abbrev, and NUL. */
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

/*
 * Recurse into the dissection tree and serialize field abbreviation / display
 * value pairs into @serializer using the nDPI JSON serializer.
 *
 * Only nodes that carry a real value (fi->value != NULL) are emitted; pure
 * structural nodes (sub-trees without a value) are skipped but their children
 * are still visited.
 *
 * @node    Current tree node (call with edt->tree->first_child initially).
 * @depth   Current recursion depth; capped at NEPAN_FIELD_MAX_DEPTH to avoid
 *          unbounded recursion on pathological captures.
 */
#define NEPAN_FIELD_MAX_DEPTH 8

static void serialize_fields(ndpi_serializer * const serializer,
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
            /*
             * fvalue_to_string_repr() allocates from wmem_packet_scope().
             * That memory is automatically released when epan_dissect_free()
             * is called at the end of nepan_jsonize(), so val_str must not
             * be stored beyond that point.  The ndpi_serialize_string_string()
             * call below copies the string immediately, so this is safe.
             */
            char * val_str = fvalue_to_string_repr(wmem_packet_scope(),
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

        /* Recurse into children. */
        if (node->first_child != NULL)
        {
            serialize_fields(serializer, node->first_child, depth + 1);
        }
    }
}

/* --------------------------------------------------------------------------
 * Main dissection entry point
 * -------------------------------------------------------------------------- */

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

    /*
     * Wireshark EPAN shares global wmem scopes and is not thread-safe.
     * All dissections must be serialized via nepan_mutex.
     */
    pthread_mutex_lock(&nepan_mutex);

    nepan_frame_num++;
    frame_data_init(&fd, nepan_frame_num, &rec, 0, nepan_cum_bytes);
    frame_data_set_before_dissect(&fd, &nepan_elapsed_time, &nepan_frame_ref, NULL);

    if (nepan_frame_num == 1)
    {
        nepan_first_fdata = fd;
        nepan_frame_ref   = &nepan_first_fdata;
    }

    tvbuff_t * const tvb = tvb_new_real_data(packet, header->caplen, header->len);
    edt = epan_dissect_new(nepan_session, TRUE, TRUE);
    epan_dissect_run(edt, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, &rec, tvb, &fd, NULL);

    if (edt->tree != NULL)
    {
        /* 1. Serialize the colon-separated protocol-name stack. */
        char proto_stack[256];
        int  proto_stack_len = build_proto_stack(edt->tree, proto_stack, (int)sizeof(proto_stack));

        if (proto_stack_len > 0)
        {
            ndpi_serialize_string_string(serializer, "epan_proto_stack", proto_stack);
        }

        /* 2. Serialize extracted field values as a nested JSON object. */
        if (edt->tree->first_child != NULL)
        {
            ndpi_serialize_start_of_block(serializer, "epan_fields");
            serialize_fields(serializer, edt->tree->first_child, 0);
            ndpi_serialize_end_of_block(serializer);
        }
    }

    frame_data_set_after_dissect(&fd, &nepan_cum_bytes);
    /*
     * epan_dissect_free() frees the tvbuff_t chain (the tvb struct and its
     * internal state).  The underlying raw packet bytes passed via
     * tvb_new_real_data() are *not* owned by the tvb and remain the caller's
     * responsibility; they are not freed here.
     */
    epan_dissect_free(edt);
    frame_data_destroy(&fd);

    pthread_mutex_unlock(&nepan_mutex);
}
