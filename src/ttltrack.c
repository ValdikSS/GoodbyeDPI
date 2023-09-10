/**
 * TCP (TTL) Connection Tracker for GoodbyeDPI
 *
 * Monitors SYN/ACK only, to extract the TTL value of the remote server.
 *
 */

#include <windows.h>
#include <time.h>
#include <stdio.h>
#include <math.h>
#include "goodbyedpi.h"
#include "ttltrack.h"
#include "utils/uthash.h"


/* key ('4' for IPv4 or '6' for IPv6 + srcip[16] + dstip[16] + srcport[2] + dstport[2]) */
#define TCP_CONNRECORD_KEY_LEN 37

#define TCP_CLEANUP_INTERVAL_SEC 30

/* HACK!
 * uthash uses strlen() for HASH_FIND_STR.
 * We have null bytes in our key, so we can't use strlen()
 * And since it's always TCP_CONNRECORD_KEY_LEN bytes long,
 * we don't need to use any string function to determine length.
 */
#undef uthash_strlen
#define uthash_strlen(s) TCP_CONNRECORD_KEY_LEN

typedef struct tcp_connrecord {
    /* key ('4' for IPv4 or '6' for IPv6 + srcip[16] + dstip[16] + srcport[2] + dstport[2]) */
    char key[TCP_CONNRECORD_KEY_LEN];
    time_t time;         /* time when this record was added */
    uint16_t ttl;
    UT_hash_handle hh;   /* makes this structure hashable */
} tcp_connrecord_t;

static time_t last_cleanup = 0;
static tcp_connrecord_t *conntrack = NULL;

inline static void fill_key_data(char *key, const uint8_t is_ipv6, const uint32_t srcip[4],
                    const uint32_t dstip[4], const uint16_t srcport, const uint16_t dstport)
{
    unsigned int offset = 0;

    if (is_ipv6) {
        *(uint8_t*)(key) = '6';
        offset += sizeof(uint8_t);
        ipv6_copy_addr((uint32_t*)(key + offset), srcip);
        offset += sizeof(uint32_t) * 4;
        ipv6_copy_addr((uint32_t*)(key + offset), dstip);
        offset += sizeof(uint32_t) * 4;
    }
    else {
        *(uint8_t*)(key) = '4';
        offset += sizeof(uint8_t);
        ipv4_copy_addr((uint32_t*)(key + offset), srcip);
        offset += sizeof(uint32_t) * 4;
        ipv4_copy_addr((uint32_t*)(key + offset), dstip);
        offset += sizeof(uint32_t) * 4;
    }

    *(uint16_t*)(key + offset) = srcport;
    offset += sizeof(srcport);
    *(uint16_t*)(key + offset) = dstport;
    offset += sizeof(dstport);
}

inline static void fill_data_from_key(uint8_t *is_ipv6, uint32_t srcip[4], uint32_t dstip[4],
                                     uint16_t *srcport, uint16_t *dstport, const char *key)
{
    unsigned int offset = 0;

    if (key[0] == '6') {
        *is_ipv6 = 1;
        offset += sizeof(uint8_t);
        ipv6_copy_addr(srcip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
        ipv6_copy_addr(dstip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
    }
    else {
        *is_ipv6 = 0;
        offset += sizeof(uint8_t);
        ipv4_copy_addr(srcip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
        ipv4_copy_addr(dstip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
    }
    *srcport = *(uint16_t*)(key + offset);
    offset += sizeof(*srcport);
    *dstport = *(uint16_t*)(key + offset);
    offset += sizeof(*dstport);
}

inline static void construct_key(const uint32_t srcip[4], const uint32_t dstip[4],
                                 const uint16_t srcport, const uint16_t dstport,
                                 char *key, const uint8_t is_ipv6)
{
    debug("Construct key enter\n");
    if (key) {
        debug("Constructing key\n");
        fill_key_data(key, is_ipv6, srcip, dstip, srcport, dstport);
    }
    debug("Construct key end\n");
}

inline static void deconstruct_key(const char *key, const tcp_connrecord_t *connrecord,
                                   tcp_conntrack_info_t *conn_info)
{
    debug("Deconstruct key enter\n");
    if (key && conn_info) {
        debug("Deconstructing key\n");
        fill_data_from_key(&conn_info->is_ipv6,
                           conn_info->srcip, conn_info->dstip,
                           &conn_info->srcport, &conn_info->dstport,
                           key);

        conn_info->ttl = connrecord->ttl;
    }
    debug("Deconstruct key end\n");
}

static int check_get_tcp_conntrack_key(const char *key, tcp_connrecord_t **connrecord) {
    tcp_connrecord_t *tmp_connrecord = NULL;
    if (!conntrack) return FALSE;

    HASH_FIND_STR(conntrack, key, tmp_connrecord);
    if (tmp_connrecord) {
        if (connrecord)
            *connrecord = tmp_connrecord;
        debug("check_get_tcp_conntrack_key found key\n");
        return TRUE;
    }
    debug("check_get_tcp_conntrack_key key not found\n");
    return FALSE;
}

static int add_tcp_conntrack(const uint32_t srcip[4], const uint32_t dstip[4],
                             const uint16_t srcport, const uint16_t dstport,
                             const uint8_t is_ipv6, const uint8_t ttl
                            )
{
    if (!(srcip && srcport && dstip && dstport))
        return FALSE;

    tcp_connrecord_t *tmp_connrecord = malloc(sizeof(tcp_connrecord_t));
    construct_key(srcip, dstip, srcport, dstport, tmp_connrecord->key, is_ipv6);

    if (!check_get_tcp_conntrack_key(tmp_connrecord->key, NULL)) {
        tmp_connrecord->time = time(NULL);
        tmp_connrecord->ttl = ttl;
        HASH_ADD_STR(conntrack, key, tmp_connrecord);
        debug("Added TCP conntrack %u:%hu - %u:%hu\n", srcip[0], ntohs(srcport), dstip[0], ntohs(dstport));
        return TRUE;
    }
    debug("Not added TCP conntrack %u:%hu - %u:%hu\n", srcip[0], ntohs(srcport), dstip[0], ntohs(dstport));
    free(tmp_connrecord);
    return FALSE;
}

static void tcp_cleanup() {
    tcp_connrecord_t *tmp_connrecord, *tmp_connrecord2 = NULL;

    if (last_cleanup == 0) {
        last_cleanup = time(NULL);
        return;
    }

    if (difftime(time(NULL), last_cleanup) >= TCP_CLEANUP_INTERVAL_SEC) {
        last_cleanup = time(NULL);

        HASH_ITER(hh, conntrack, tmp_connrecord, tmp_connrecord2) {
            if (difftime(last_cleanup, tmp_connrecord->time) >= TCP_CLEANUP_INTERVAL_SEC) {
                HASH_DEL(conntrack, tmp_connrecord);
                free(tmp_connrecord);
            }
        }
    }
}

int tcp_handle_incoming(uint32_t srcip[4], uint32_t dstip[4],
                        uint16_t srcport, uint16_t dstport,
                        uint8_t is_ipv6, uint8_t ttl)
{
    tcp_cleanup();

    debug("trying to add TCP srcport = %hu, dstport = %hu\n", ntohs(srcport), ntohs(dstport));
    return add_tcp_conntrack(srcip, dstip, srcport, dstport, is_ipv6, ttl);

    debug("____tcp_handle_incoming FALSE: srcport = %hu, dstport = %hu\n", ntohs(srcport), ntohs(dstport));
    return FALSE;
}

int tcp_handle_outgoing(uint32_t srcip[4], uint32_t dstip[4],
                        uint16_t srcport, uint16_t dstport,
                        tcp_conntrack_info_t *conn_info,
                        uint8_t is_ipv6)
{
    char key[TCP_CONNRECORD_KEY_LEN];
    tcp_connrecord_t *tmp_connrecord = NULL;

    if (!conn_info)
        return FALSE;

    tcp_cleanup();
    construct_key(dstip, srcip, dstport, srcport, key, is_ipv6);
    if (check_get_tcp_conntrack_key(key, &tmp_connrecord) && tmp_connrecord) {
        /* Connection exists in conntrack, moving on */
        deconstruct_key(key, tmp_connrecord, conn_info);
        HASH_DEL(conntrack, tmp_connrecord);
        free(tmp_connrecord);
        debug("____tcp_handle_outgoing TRUE: srcport = %hu\n", ntohs(srcport));
        return TRUE;
    }

    debug("____tcp_handle_outgoing FALSE: srcport = %hu\n", ntohs(srcport));
    return FALSE;
}

int tcp_get_auto_ttl(const uint8_t ttl, const uint8_t autottl1,
                     const uint8_t autottl2, const uint8_t minhops,
                     const uint8_t maxttl) {
    uint8_t nhops = 0;
    uint8_t ttl_of_fake_packet = 0;

    if (ttl > 98 && ttl < 128) {
        nhops = 128 - ttl;
    }
    else if (ttl > 34 && ttl < 64) {
        nhops = 64 - ttl;
    }
    else {
        return 0;
    }

    if (nhops <= autottl1 || nhops < minhops) {
        return 0;
    }

    ttl_of_fake_packet = nhops - autottl2;
    if (ttl_of_fake_packet < autottl2 && nhops <= 9) {
        ttl_of_fake_packet = nhops - autottl1 - trunc((autottl2 - autottl1) * ((float)nhops/10));
    }

    if (maxttl && ttl_of_fake_packet > maxttl) {
        ttl_of_fake_packet = maxttl;
    }

    return ttl_of_fake_packet;
}