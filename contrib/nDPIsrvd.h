#ifndef NDPISRVD_H
#define NDPISRVD_H 1

struct nDPIsrvd_socket
{
    int fd;
    union {
        struct {
            char const * dst_ip;
            unsigned short dst_port;
        } ip;
        struct {
            char * path;
        } unix;
    } address;
};

#endif
