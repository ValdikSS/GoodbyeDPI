#ifndef _DNSREDIR_H
#define _DNSREDIR_H
#include <stdint.h>

typedef struct conntrack_info {
    uint8_t  is_ipv6;
    uint32_t srcip[4];
    uint16_t srcport;
    uint32_t dstip[4];
    uint16_t dstport;
} conntrack_info_t;

inline static void ipv4_copy_addr(uint32_t dst[4], const uint32_t src[4]) {
    dst[0] = src[0];
    dst[1] = 0;
    dst[2] = 0;
    dst[3] = 0;
}

inline static void ipv6_copy_addr(uint32_t dst[4], const uint32_t src[4]) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

int dns_handle_incoming(const uint32_t srcip[4], const uint16_t srcport,
                        const char *packet_data, const UINT packet_dataLen,
                        conntrack_info_t *conn_info, const uint8_t is_ipv6);

int dns_handle_outgoing(const uint32_t srcip[4], const uint16_t srcport,
                        const uint32_t dstip[4], const uint16_t dstport,
                        const char *packet_data, const UINT packet_dataLen,
                        const uint8_t is_ipv6
                       );

void flush_dns_cache();
int dns_is_dns_packet(const char *packet_data, const UINT packet_dataLen, const int outgoing);
#endif
