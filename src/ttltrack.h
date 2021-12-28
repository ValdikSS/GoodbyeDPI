#ifndef _TTLTRACK_H
#define _TTLTRACK_H
#include <stdint.h>
#include "dnsredir.h"

typedef struct tcp_conntrack_info {
    uint8_t  is_ipv6;
    uint8_t  ttl;
    uint32_t srcip[4];
    uint16_t srcport;
    uint32_t dstip[4];
    uint16_t dstport;
} tcp_conntrack_info_t;

int tcp_handle_incoming(uint32_t srcip[4], uint32_t dstip[4],
                        uint16_t srcport, uint16_t dstport,
                        uint8_t is_ipv6, uint8_t ttl);

int tcp_handle_outgoing(uint32_t srcip[4], uint32_t dstip[4],
                        uint16_t srcport, uint16_t dstport,
                        tcp_conntrack_info_t *conn_info,
                        uint8_t is_ipv6);

int tcp_get_auto_ttl(const uint8_t ttl, const uint8_t autottl1,
                     const uint8_t autottl2, const uint8_t minhops,
                     const uint8_t maxttl);
#endif
