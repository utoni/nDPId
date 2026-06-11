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
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "utils.h"

#ifndef NEPAN_RECYCLE_EVERY
#define NEPAN_RECYCLE_EVERY 50000u // Restart worker every N packets (cleanup Wireshark memory impossible atm)
#endif

#define NEPAN_FIELD_MAX_DEPTH 8            // Max depth of the Wireshark protocol tree
#define NEPAN_MAX_PKT_SIZE (1u << 20)      // IPC: Max size of a captured packet
#define NEPAN_RESP_MAX (1u << 20)          // IPC EPAN --> nDPId: Max size of a single response packet
#define NEPAN_MAX_STRING_LENGTH (1u << 20) // Max length of a seriialized string as part of a response packet
#define NEPAN_WORKER_ARG "--nepan-worker"
#define NEPAN_FD_ARG "--fd"

#define NEPAN_TAG_END 0u
#define NEPAN_TAG_PROTOSTACK 1u
#define NEPAN_TAG_FIELD 2u

struct nepan_req_hdr
{
    int32_t wtap_encap;
    uint32_t caplen;
    uint32_t len;
    int64_t ts_sec;
    int64_t ts_usec;
};

static char * initial_arg0 = NULL;
static int nepan_ipc_fd = -1;
static pid_t nepan_worker_pid = -1;
static pthread_mutex_t nepan_mutex = PTHREAD_MUTEX_INITIALIZER;

void nepan_set_arg0(char const * const arg0)
{
    initial_arg0 = strdup(arg0);
}

static int read_full(int fd, void * buf, size_t n)
{
    uint8_t * p = buf;
    size_t off = 0;
    while (off < n)
    {
        ssize_t r = recv(fd, p + off, n - off, 0);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return 0; /* peer closed */
        off += (size_t)r;
    }
    return 1;
}

static int write_full(int fd, const void * buf, size_t n)
{
    const uint8_t * p = buf;
    size_t off = 0;
    while (off < n)
    {
        ssize_t w = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (w < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 1;
}

static epan_t * w_session = NULL;
static guint32 w_frame_num = 0;
static guint32 w_cum_bytes = 0;
static nstime_t w_elapsed_time = NSTIME_INIT_ZERO;
static frame_data w_first_fdata;
static const frame_data * w_frame_ref = NULL;
static int w_provider_ctx = 0;

static uint8_t w_resp[NEPAN_RESP_MAX];
static size_t w_resp_len;

static void w_report_open_failure(const char * filename, int err, bool for_writing)
{
    logger(
        0, "Wireshark EPAN: Could not %s \"%s\": %s", for_writing ? "open/create" : "open", filename, g_strerror(err));
}
static void w_report_read_failure(const char * filename, int err)
{
    logger(0, "Wireshark EPAN: Could not read \"%s\": %s", filename, g_strerror(err));
}
static void w_report_write_failure(const char * filename, int err)
{
    logger(0, "Could not write \"%s\": %s", filename, g_strerror(err));
}
static void w_report_failure(const char * fmt, va_list ap)
{
    vlogger(1, fmt, ap);
}
static void w_report_warning(const char * fmt, va_list ap)
{
    vlogger(0, fmt, ap);
}

static const struct report_message_routines w_report_routines = {
    .vreport_failure = w_report_failure,
    .vreport_warning = w_report_warning,
    .report_open_failure = w_report_open_failure,
    .report_read_failure = w_report_read_failure,
    .report_write_failure = w_report_write_failure,
};

static const nstime_t * w_get_frame_ts(struct packet_provider_data * prov, guint32 frame_num)
{
    (void)prov;
    (void)frame_num;
    return NULL;
}
static const char * w_get_interface_name(struct packet_provider_data * prov,
                                         uint32_t interface_id,
                                         unsigned section_number)
{
    (void)prov;
    (void)interface_id;
    (void)section_number;
    return "nDPId";
}
static const char * w_get_interface_description(struct packet_provider_data * prov,
                                                uint32_t interface_id,
                                                unsigned section_number)
{
    (void)prov;
    (void)interface_id;
    (void)section_number;
    return NULL;
}
static wtap_block_t w_get_modified_block(struct packet_provider_data * prov, const frame_data * fd)
{
    (void)prov;
    (void)fd;
    return NULL;
}
static const struct packet_provider_funcs w_provider_funcs = {
    .get_frame_ts = w_get_frame_ts,
    .get_interface_name = w_get_interface_name,
    .get_interface_description = w_get_interface_description,
    .get_modified_block = w_get_modified_block,
};

static void w_log(const char * fmt, va_list ap)
{
    vlogger(1, fmt, ap);
}

static int worker_init_epan(void)
{
    init_process_policies();
    ws_log_init("nDPId", w_log);
    init_report_message("nDPId", &w_report_routines);
    wtap_init(false);

    if (epan_init(NULL, NULL, FALSE) == FALSE)
    {
        return 1;
    }

    {
        char buf[64];
        char * errmsg = NULL;

        snprintf(buf, sizeof(buf), "tcp.desegment_tcp_streams:FALSE");
        prefs_set_pref(buf, &errmsg);
        if (errmsg != NULL)
        {
            logger(1, "Wireshark EPAN: Setting `tcp.desegment_tcp_streams:FALSE' failed with: %s", errmsg);
            g_free(errmsg);
            errmsg = NULL;
        }

        snprintf(buf, sizeof(buf), "ip.defragment:FALSE");
        prefs_set_pref(buf, &errmsg);
        if (errmsg != NULL)
        {
            logger(1, "Wireshark EPAN: Setting `ip.defragment:FALSE' failed with: %s", errmsg);
            g_free(errmsg);
            errmsg = NULL;
        }

        prefs_apply_all();
    }

    w_session = epan_new((struct packet_provider_data *)&w_provider_ctx, &w_provider_funcs);
    if (w_session == NULL)
    {
        return 1;
    }

    gbl_resolv_flags.maxmind_geoip = FALSE;
    gbl_resolv_flags.mac_name = FALSE;
    gbl_resolv_flags.network_name = FALSE;
    gbl_resolv_flags.transport_name = FALSE;
    gbl_resolv_flags.dns_pkt_addr_resolution = FALSE;
    gbl_resolv_flags.use_external_net_name_resolver = FALSE;
    gbl_resolv_flags.vlan_name = FALSE;

    return 0;
}

static void wb_reset(void)
{
    w_resp_len = 0;
}

static int wb_put(const void * p, size_t n)
{
    if (w_resp_len + n > sizeof(w_resp) - 1)
    {
        return -1;
    }
    memcpy(w_resp + w_resp_len, p, n);
    w_resp_len += n;
    return 0;
}
static int wb_u8(uint8_t v)
{
    return wb_put(&v, 1);
}
static int wb_u32(uint32_t v)
{
    return wb_put(&v, 4);
}
static int wb_str(const char * s)
{
    uint32_t n = (uint32_t)strlen(s);
    if (wb_u32(n) != 0)
        return -1;
    return wb_put(s, n);
}

static int build_proto_stack(proto_node const * tree_root, char * buf, int buf_size)
{
    int len = 0;

    for (proto_node const * child = tree_root->first_child; child != NULL; child = child->next)
    {
        field_info const * const fi = PNODE_FINFO(child);
        if (fi == NULL || fi->hfinfo == NULL || fi->hfinfo->abbrev == NULL || fi->hfinfo->abbrev[0] == '\0')
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

static void worker_walk_fields(wmem_allocator_t * const pool, proto_node const * node, int depth)
{
    if (depth > NEPAN_FIELD_MAX_DEPTH || node == NULL)
    {
        return;
    }

    for (; node != NULL; node = node->next)
    {
        field_info const * const fi = PNODE_FINFO(node);

        if (fi != NULL && fi->hfinfo != NULL && fi->hfinfo->abbrev != NULL && fi->hfinfo->abbrev[0] != '\0' &&
            fi->value != NULL)
        {
            int skip = 0;

            ftenum_t val_type = fvalue_type_ftenum(fi->value);
            switch (val_type)
            {
                case FT_BOOLEAN:
                    if (strcmp(fi->hfinfo->abbrev, "frame.marked") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "frame.ignored") == 0)
                    {
                        skip = 1;
                    }
                    break;
                case FT_FLOAT:
                case FT_DOUBLE:
                case FT_RELATIVE_TIME:
                case FT_ABSOLUTE_TIME:
                    if (strcmp(fi->hfinfo->abbrev, "frame.offset_shift") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "frame.time_delta") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "frame.time_delta_displayed") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "frame.time_relative") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "frame.time_epoch") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "frame.time") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "frame.time_utc") == 0)
                    {
                        skip = 1;
                    }
                    break;
                case FT_BYTES:
                    if (strcmp(fi->hfinfo->abbrev, "udp.payload") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "tcp.payload") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "data.data") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "ssh.encrypted_packet") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "tls.app_data") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "tcp.segment_data") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "tcp.reassembled.data") == 0 ||
                        strcmp(fi->hfinfo->abbrev, "quic.remaining_payload") == 0)
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

            if (skip == 0)
            {
                char * val_str = fvalue_to_string_repr(pool, fi->value, FTREPR_DISPLAY, fi->hfinfo->display);
                if (val_str != NULL && val_str[0] != '\0')
                {
                    size_t saved = w_resp_len;
                    if (wb_u8(NEPAN_TAG_FIELD) != 0 || wb_str(fi->hfinfo->abbrev) != 0 || wb_str(val_str) != 0)
                    {
                        w_resp_len = saved;
                    }
                }
            }
        }

        if (node->first_child != NULL)
        {
            worker_walk_fields(pool, node->first_child, depth + 1);
        }
    }
}

static int worker_handle_packet(int fd, struct nepan_req_hdr const * h, uint8_t const * packet)
{
    wtap_rec rec;
    frame_data fd_data;
    epan_dissect_t * edt;

    memset(&rec, 0, sizeof(rec));
    rec.rec_type = REC_TYPE_PACKET;
    rec.presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    rec.ts.secs = (time_t)h->ts_sec;
    rec.ts.nsecs = (int)(h->ts_usec * 1000);
    rec.tsprec = WTAP_TSPREC_USEC;
    rec.rec_header.packet_header.caplen = h->caplen;
    rec.rec_header.packet_header.len = h->len;
    rec.rec_header.packet_header.pkt_encap = h->wtap_encap;

    w_frame_num++;
    frame_data_init(&fd_data, w_frame_num, &rec, 0, w_cum_bytes);
    frame_data_set_before_dissect(&fd_data, &w_elapsed_time, &w_frame_ref, NULL);

    if (w_frame_num == 1)
    {
        w_first_fdata = fd_data;
        w_first_fdata.pfd = NULL;
        w_first_fdata.dependent_frames = NULL;
        w_frame_ref = &w_first_fdata;
    }

    tvbuff_t * const tvb = tvb_new_real_data(packet, h->caplen, h->len);
    edt = epan_dissect_new(w_session, TRUE, TRUE);
    epan_dissect_run(edt, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN, &rec, tvb, &fd_data, NULL);

    wb_reset();

    if (edt->tree != NULL)
    {
        char proto_stack[256];
        int proto_stack_len = build_proto_stack(edt->tree, proto_stack, (int)sizeof(proto_stack));

        if (proto_stack_len > 0)
        {
            size_t saved = w_resp_len;
            if (wb_u8(NEPAN_TAG_PROTOSTACK) != 0 || wb_str(proto_stack) != 0)
            {
                w_resp_len = saved;
            }
        }

        if (edt->tree->first_child != NULL)
        {
            worker_walk_fields(edt->pi.pool, edt->tree->first_child, 0);
        }
    }

    wb_u8(NEPAN_TAG_END);

    frame_data_set_after_dissect(&fd_data, &w_cum_bytes);
    epan_dissect_free(edt);
    frame_data_destroy(&fd_data);

    return write_full(fd, w_resp, w_resp_len) <= 0 ? -1 : 0;
}

static void setup_env(char * argv[5], int fd)
{
    char fdbuf[16];

    snprintf(fdbuf, sizeof(fdbuf), "%d", fd);
    argv[0] = initial_arg0;
    argv[1] = strdup(NEPAN_WORKER_ARG);
    argv[2] = strdup(NEPAN_FD_ARG);
    argv[3] = fdbuf;
    argv[4] = NULL;
}

static void worker_reexec(int fd)
{
    char * argv[5];

    setup_env(argv, fd);
    execv("/proc/self/exe", argv);
    logger(1, "nepan worker: re-exec failed: %s", g_strerror(errno));
}

static int nepan_worker_main(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0)
    {
        fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
    }

    if (initial_arg0 == NULL)
    {
        logger(1, "nepan worker: not started within nDPId");
        _exit(2);
    }

    if (worker_init_epan() != 0)
    {
        logger(1, "nepan worker: EPAN init failed");
        _exit(2);
    }

    uint32_t handled = 0;

    for (;;)
    {
        struct nepan_req_hdr h;
        int r = read_full(fd, &h, sizeof(h));
        if (r <= 0)
        {
            _exit(0);
        }
        if (h.caplen > NEPAN_MAX_PKT_SIZE || h.caplen == 0)
        {
            _exit(3);
        }

        uint8_t * pkt = malloc(h.caplen);
        if (pkt == NULL)
        {
            _exit(4);
        }
        if (read_full(fd, pkt, h.caplen) <= 0)
        {
            free(pkt);
            _exit(0);
        }

        int rc = worker_handle_packet(fd, &h, pkt);
        free(pkt);
        if (rc != 0)
        {
            _exit(0);
        }

        if (++handled >= NEPAN_RECYCLE_EVERY)
        {
            worker_reexec(fd);
            handled = 0;
        }
    }
}

int nepan_worker_run_if_requested(int argc, char ** argv)
{
    if (argc >= 4 && argv[1] != NULL && strcmp(argv[1], NEPAN_WORKER_ARG) == 0 && argv[2] != NULL &&
        strcmp(argv[2], NEPAN_FD_ARG) == 0)
    {
        nepan_set_arg0(argv[0]);
        return nepan_worker_main(atoi(argv[3]));
    }
    return 0;
}

static int spawn_worker(void)
{
    int sv[2];
    pid_t pid;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
    {
        logger(1, "nepan: socketpair failed: %s", g_strerror(errno));
        return -1;
    }

    pid = fork();
    if (pid < 0)
    {
        logger(1, "nepan: fork failed: %s", g_strerror(errno));
        close(sv[0]);
        close(sv[1]);
        return -1;
    }

    if (pid == 0)
    {
        char * argv[5];

        close(sv[0]);
        setup_env(argv, sv[1]);
        execv("/proc/self/exe", argv);
        _exit(127);
    }

    close(sv[1]);
    fcntl(sv[0], F_SETFD, FD_CLOEXEC);

    nepan_ipc_fd = sv[0];
    nepan_worker_pid = pid;
    return 0;
}

static void reap_worker(void)
{
    if (nepan_worker_pid > 0)
    {
        kill(nepan_worker_pid, SIGKILL);
        waitpid(nepan_worker_pid, NULL, 0);
        nepan_worker_pid = -1;
    }
    if (nepan_ipc_fd >= 0)
    {
        close(nepan_ipc_fd);
        nepan_ipc_fd = -1;
    }
}

static int respawn_worker(void)
{
    reap_worker();
    return spawn_worker();
}

static int read_lp_string(int fd, char ** bufp, size_t * capp)
{
    uint32_t n;
    if (read_full(fd, &n, sizeof(n)) <= 0)
    {
        return -1;
    }
    if (n > NEPAN_MAX_STRING_LENGTH)
    {
        return -1;
    }
    if ((size_t)n + 1 > *capp)
    {
        char * t = realloc(*bufp, (size_t)n + 1);
        if (t == NULL)
        {
            return -1;
        }
        *bufp = t;
        *capp = (size_t)n + 1;
    }
    if (n > 0 && read_full(fd, *bufp, n) <= 0)
    {
        return -1;
    }
    (*bufp)[n] = '\0';
    return 0;
}

static int parse_response(int fd, ndpi_serializer * const serializer)
{
    static char * kbuf = NULL;
    static size_t kcap = 0;
    static char * vbuf = NULL;
    static size_t vcap = 0;

    int block_open = 0;

    for (;;)
    {
        uint8_t tag;
        int r = read_full(fd, &tag, 1);
        if (r <= 0)
        {
            if (block_open)
                ndpi_serialize_end_of_block(serializer);
            return -1;
        }

        if (tag == NEPAN_TAG_END)
        {
            break;
        }
        else if (tag == NEPAN_TAG_PROTOSTACK)
        {
            if (read_lp_string(fd, &vbuf, &vcap) != 0)
            {
                if (block_open)
                    ndpi_serialize_end_of_block(serializer);
                return -1;
            }
            ndpi_serialize_string_string(serializer, "epan_proto_stack", vbuf);
        }
        else if (tag == NEPAN_TAG_FIELD)
        {
            if (read_lp_string(fd, &kbuf, &kcap) != 0 || read_lp_string(fd, &vbuf, &vcap) != 0)
            {
                if (block_open)
                    ndpi_serialize_end_of_block(serializer);
                return -1;
            }
            if (block_open == 0)
            {
                ndpi_serialize_start_of_block(serializer, "epan_fields");
                block_open = 1;
            }
            ndpi_serialize_string_string(serializer, kbuf, vbuf);
        }
        else
        {
            if (block_open)
                ndpi_serialize_end_of_block(serializer);
            return -1; /* unknown tag */
        }
    }

    if (block_open)
    {
        ndpi_serialize_end_of_block(serializer);
    }
    return 0;
}

int nepan_init(void)
{
    return spawn_worker() == 0 ? 0 : 1;
}

void nepan_cleanup(void)
{
    pthread_mutex_lock(&nepan_mutex);
    reap_worker();
    pthread_mutex_unlock(&nepan_mutex);
    pthread_mutex_destroy(&nepan_mutex);
}

const char * nepan_get_version(void)
{
    return epan_get_version();
}

void nepan_jsonize(ndpi_serializer * const serializer,
                   int wtap_encap,
                   struct pcap_pkthdr const * const header,
                   uint8_t const * const packet)
{
    struct nepan_req_hdr h;

    if (header == NULL || packet == NULL || header->caplen == 0 || header->caplen > NEPAN_MAX_PKT_SIZE)
    {
        return;
    }

    h.wtap_encap = wtap_encap;
    h.caplen = header->caplen;
    h.len = header->len;
    h.ts_sec = (int64_t)header->ts.tv_sec;
    h.ts_usec = (int64_t)header->ts.tv_usec;

    pthread_mutex_lock(&nepan_mutex);

    if (nepan_ipc_fd < 0 && respawn_worker() != 0)
    {
        pthread_mutex_unlock(&nepan_mutex);
        return;
    }

    if (write_full(nepan_ipc_fd, &h, sizeof(h)) <= 0 || write_full(nepan_ipc_fd, packet, h.caplen) <= 0)
    {
        respawn_worker();
        pthread_mutex_unlock(&nepan_mutex);
        return;
    }

    if (parse_response(nepan_ipc_fd, serializer) != 0)
    {
        respawn_worker();
    }

    pthread_mutex_unlock(&nepan_mutex);
}
