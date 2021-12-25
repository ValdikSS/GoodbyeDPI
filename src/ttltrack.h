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

int tcp_handle_incoming(const uint32_t srcip[4], const uint32_t dstip[4],
                        const uint16_t srcport, const uint16_t dstport,
                        const uint8_t is_ipv6, const uint8_t ttl);

int tcp_handle_outgoing(const uint32_t srcip[4], const uint32_t dstip[4],
                        const uint16_t srcport, const uint16_t dstport,
                        tcp_conntrack_info_t *conn_info,
                        const uint8_t is_ipv6);

int tcp_get_auto_ttl(const uint8_t ttl, const uint8_t decrease_for);
#endif
