#include <stdint.h>

typedef struct conntrack_info {
    uint32_t srcip;
    uint16_t srcport;
    uint32_t dstip;
    uint16_t dstport;
} conntrack_info_t;

int dns_handle_incoming(const uint32_t srcip, const uint16_t srcport,
                        const uint32_t dstip, const uint16_t dstport,
                        const char *packet_data, const UINT packet_dataLen,
                        conntrack_info_t *conn_info);

int dns_handle_outgoing(const uint32_t srcip, const uint16_t srcport,
                        const uint32_t dstip, const uint16_t dstport,
                        const char *packet_data, const UINT packet_dataLen);
