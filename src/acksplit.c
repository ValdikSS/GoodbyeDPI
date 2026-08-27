#include <windows.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "goodbyedpi.h"
#include "acksplit.h"
#include "dnsredir.h"
#include "utils/uthash.h"

#define ACK_KEY_LEN 37
#define ACK_CLEANUP_INTERVAL_SEC 60

#undef uthash_strlen
#define uthash_strlen(s) ACK_KEY_LEN

ack_mode_t     ack_mode        = ACK_OFF;
unsigned short ack_step_size   = 40;
unsigned int   ack_limit_bytes = 16384;
int            ack_zero_wscale = 1;
int            ack_drop_stack_ack = 1;
int            ack_sack_max    = 2;   /* < 3, чтобы не ловить fast retransmit */

typedef struct ack_conn {
    char key[ACK_KEY_LEN];
    time_t time;
    uint32_t last_ack;   /* последний ACK, отправленный нами */
    uint32_t bytes;      /* обработано байт полезной нагрузки */
    uint8_t  have_ack;
    uint8_t  done;
    UT_hash_handle hh;
} ack_conn_t;

static ack_conn_t *conns = NULL;
static time_t last_cleanup = 0;

/* fill_key_data() скопирована из ttltrack.c для автономности модуля */
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

inline static void construct_key(const uint32_t srcip[4], const uint32_t dstip[4],
                                 const uint16_t srcport, const uint16_t dstport,
                                 char *key, const uint8_t is_ipv6)
{
    fill_key_data(key, is_ipv6, srcip, dstip, srcport, dstport);
}

static void ack_cleanup(void) {
    ack_conn_t *c, *tmp;
    if (!last_cleanup) { last_cleanup = time(NULL); return; }
    if (difftime(time(NULL), last_cleanup) < ACK_CLEANUP_INTERVAL_SEC) return;
    last_cleanup = time(NULL);
    HASH_ITER(hh, conns, c, tmp) {
        if (difftime(last_cleanup, c->time) >= ACK_CLEANUP_INTERVAL_SEC) {
            HASH_DEL(conns, c);
            free(c);
        }
    }
}

static ack_conn_t *ack_find(const char *key) {
    ack_conn_t *c = NULL;
    if (!conns) return NULL;
    HASH_FIND_STR(conns, key, c);
    if (c) c->time = time(NULL);
    return c;
}

/* Обнуление Window Scale в нашем SYN — обязательный шаг */
static int tcp_zero_wscale(PWINDIVERT_TCPHDR tcp) {
    uint8_t *o = (uint8_t*)tcp + sizeof(WINDIVERT_TCPHDR);
    int len = (int)(tcp->HdrLength * 4) - (int)sizeof(WINDIVERT_TCPHDR);
    int i = 0, changed = 0;

    while (i < len) {
        uint8_t kind = o[i], olen;
        if (kind == 0) break;              /* EOL */
        if (kind == 1) { i++; continue; }  /* NOP */
        if (i + 1 >= len) break;
        olen = o[i + 1];
        if (olen < 2 || i + olen > len) break;
        if (kind == 3 && olen == 3 && o[i + 2] != 0) {
            o[i + 2] = 0;                  /* shift.cnt = 0 */
            changed = 1;
        }
        i += olen;
    }
    return changed;
}

/* Генерация собственного ACK (с опциональными SACK-блоками) */
static void send_ack_packet(HANDLE w_filter, const WINDIVERT_ADDRESS *inaddr,
                            PWINDIVERT_IPHDR ip4, PWINDIVERT_IPV6HDR ip6,
                            PWINDIVERT_TCPHDR tcp,
                            uint32_t ack_num, uint16_t window,
                            const uint32_t sack[][2], int sack_blocks)
{
    char pkt[128];
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_TCPHDR t;
    UINT pktlen, tcplen, optlen = 0;
    int i;

    if (sack_blocks > 3) sack_blocks = 3;          /* 4 + 8*3 = 28 <= 40 байт опций */
    if (sack_blocks > 0) optlen = 4 + 8u * (unsigned)sack_blocks;

    memset(pkt, 0, sizeof(pkt));

    if (!ip6) {
        PWINDIVERT_IPHDR h = (PWINDIVERT_IPHDR)pkt;
        t       = (PWINDIVERT_TCPHDR)(pkt + sizeof(WINDIVERT_IPHDR));
        tcplen  = sizeof(WINDIVERT_TCPHDR) + optlen;
        pktlen  = sizeof(WINDIVERT_IPHDR) + tcplen;

        h->Version   = 4;
        h->HdrLength = sizeof(WINDIVERT_IPHDR) / 4;
        h->TOS       = ip4->TOS;
        h->Length    = htons((u_short)pktlen);
        h->TTL       = 128;                        /* мимикрия под стек Windows */
        h->Protocol  = IPPROTO_TCP;
        h->SrcAddr   = ip4->DstAddr;
        h->DstAddr   = ip4->SrcAddr;
    }
    else {
        PWINDIVERT_IPV6HDR h = (PWINDIVERT_IPV6HDR)pkt;
        t       = (PWINDIVERT_TCPHDR)(pkt + sizeof(WINDIVERT_IPV6HDR));
        tcplen  = sizeof(WINDIVERT_TCPHDR) + optlen;
        pktlen  = sizeof(WINDIVERT_IPV6HDR) + tcplen;

        h->Version  = 6;
        h->Length   = htons((u_short)tcplen);
        h->NextHdr  = IPPROTO_TCP;
        h->HopLimit = 128;
        ipv6_copy_addr(h->SrcAddr, ip6->DstAddr);
        ipv6_copy_addr(h->DstAddr, ip6->SrcAddr);
    }

    t->SrcPort   = tcp->DstPort;
    t->DstPort   = tcp->SrcPort;
    t->SeqNum    = tcp->AckNum;
    t->AckNum    = htonl(ack_num);
    t->HdrLength = tcplen / 4;
    t->Ack       = 1;
    t->Window    = htons(window);

    if (sack_blocks > 0) {
        uint8_t *opt = (uint8_t*)t + sizeof(WINDIVERT_TCPHDR);
        *opt++ = 1; *opt++ = 1;                    /* NOP, NOP — выравнивание */
        *opt++ = 5;                                /* kind = SACK */
        *opt++ = (uint8_t)(2 + 8 * sack_blocks);
        for (i = 0; i < sack_blocks; i++) {
            uint32_t l = htonl(sack[i][0]), r = htonl(sack[i][1]);
            memcpy(opt, &l, 4); opt += 4;
            memcpy(opt, &r, 4); opt += 4;
        }
    }

    memcpy(&addr, inaddr, sizeof(addr));
    addr.Outbound    = 1;
    addr.Impostor    = 0;
    addr.IPChecksum  = 0;
    addr.TCPChecksum = 0;

    WinDivertHelperCalcChecksums(pkt, pktlen, &addr, 0);
    WinDivertSend(w_filter, pkt, pktlen, NULL, &addr);
}

void acksplit_in_data(HANDLE w_filter, const WINDIVERT_ADDRESS *addr,
                      PWINDIVERT_IPHDR ip4, PWINDIVERT_IPV6HDR ip6,
                      PWINDIVERT_TCPHDR tcp, UINT datalen)
{
    char key[ACK_KEY_LEN];
    ack_conn_t *c;
    uint32_t seq, end, a;

    if (ack_mode == ACK_OFF || !datalen || !ack_step_size) return;

    ack_cleanup();
    if (ip6) construct_key(ip6->DstAddr, ip6->SrcAddr, tcp->DstPort, tcp->SrcPort, key, 1);
    else     construct_key((uint32_t*)&ip4->DstAddr, (uint32_t*)&ip4->SrcAddr,
                           tcp->DstPort, tcp->SrcPort, key, 0);

    c = ack_find(key);
    if (!c || c->done) return;

    seq = ntohl(tcp->SeqNum);
    end = seq + datalen;

    if (!c->have_ack) { c->last_ack = seq; c->have_ack = 1; }
    if ((int32_t)(end - c->last_ack) <= 0) return;   /* ретрансмит/старьё */

    if (ack_mode == ACK_PLAIN) {
        /* Каждый шаг ack_step_size подтверждается отдельным ACK */
        a = c->last_ack;
        while ((int32_t)(end - a) > 0) {
            uint32_t step = ack_step_size;
            if ((uint32_t)(end - a) < step) step = end - a;
            a += step;
            send_ack_packet(w_filter, addr, ip4, ip6, tcp, a, ack_step_size, NULL, 0);
        }
        c->last_ack = a;
    }
    else { /* ACK_SACK */
        uint32_t left = c->last_ack;
        uint32_t s;
        int sent = 0;
        for (s = seq; (int32_t)(end - s) > 0 && sent < ack_sack_max; s += ack_step_size) {
            uint32_t e = s + ack_step_size;
            uint32_t blk[1][2];
            if ((int32_t)(e - end) > 0) e = end;
            blk[0][0] = s; blk[0][1] = e;
            /* кумулятивный ACK придержан на left, шаг подтверждён SACK-блоком */
            send_ack_packet(w_filter, addr, ip4, ip6, tcp, left, ack_step_size, blk, 1);
            sent++;
        }
        /* закрываем дырку кумулятивно, чтобы сервер не ушёл в fast retransmit */
        send_ack_packet(w_filter, addr, ip4, ip6, tcp, end, ack_step_size, NULL, 0);
        c->last_ack = end;
    }

    c->bytes += datalen;
    if (ack_limit_bytes && c->bytes >= ack_limit_bytes) c->done = 1;
}

void acksplit_out_syn(PWINDIVERT_TCPHDR tcp, uint32_t srcip[4], uint32_t dstip[4],
                      uint8_t is_ipv6, int *recalc)
{
    ack_conn_t *c;
    char key[ACK_KEY_LEN];

    if (ack_mode == ACK_OFF) return;
    ack_cleanup();
    construct_key(srcip, dstip, tcp->SrcPort, tcp->DstPort, key, is_ipv6);

    c = ack_find(key);
    if (!c) {
        c = calloc(1, sizeof(*c));
        if (!c) return;
        memcpy(c->key, key, ACK_KEY_LEN);
        HASH_ADD_STR(conns, key, c);
    }
    c->time = time(NULL);
    c->have_ack = c->done = 0;
    c->bytes = 0;

    if (ack_zero_wscale && tcp_zero_wscale(tcp)) *recalc = 1;
    if (ntohs(tcp->Window) > ack_step_size) {
        tcp->Window = htons(ack_step_size);
        *recalc = 1;
    }
}

int acksplit_out(PWINDIVERT_TCPHDR tcp, uint32_t srcip[4], uint32_t dstip[4],
                 uint8_t is_ipv6, UINT datalen, int *recalc)
{
    ack_conn_t *c;
    char key[ACK_KEY_LEN];

    if (ack_mode == ACK_OFF) return 1;
    construct_key(srcip, dstip, tcp->SrcPort, tcp->DstPort, key, is_ipv6);
    c = ack_find(key);
    if (!c) return 1;

    if (tcp->Fin || tcp->Rst) { HASH_DEL(conns, c); free(c); return 1; }
    if (c->done) return 1;

    if (ack_drop_stack_ack && !datalen && tcp->Ack && !tcp->Syn && c->have_ack &&
        (int32_t)(ntohl(tcp->AckNum) - c->last_ack) <= 0)
    {
        return 0;   /* это мы уже подтвердили сами — не реинжектим */
    }

    if (ntohs(tcp->Window) > ack_step_size) {
        tcp->Window = htons(ack_step_size);
        *recalc = 1;
    }
    return 1;
}
