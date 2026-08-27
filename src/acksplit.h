#ifndef _ACKSPLIT_H
#define _ACKSPLIT_H

#include <stdint.h>
#include <windows.h>
#include "windivert.h"

typedef enum {
    ACK_OFF = 0,
    ACK_PLAIN,   /* --ack-split      : кумулятивные ACK шагами */
    ACK_SACK     /* --ack-split-sack : шаги подтверждаются SACK-блоками */
} ack_mode_t;

extern ack_mode_t     ack_mode;
extern unsigned short ack_step_size;      /* размер шага и анонсируемого окна, байт */
extern unsigned int   ack_limit_bytes;    /* обрабатывать первые N байт ответа, 0 = всё */
extern int            ack_zero_wscale;    /* обнулять Window Scale в исходящем SYN */
extern int            ack_drop_stack_ack; /* давить лишние ACK стека */
extern int            ack_sack_max;       /* макс. SACK-ACK за один входящий сегмент */

void acksplit_out_syn(PWINDIVERT_TCPHDR tcp, uint32_t srcip[4], uint32_t dstip[4],
                      uint8_t is_ipv6, int *recalc);
int  acksplit_out(PWINDIVERT_TCPHDR tcp, uint32_t srcip[4], uint32_t dstip[4],
                  uint8_t is_ipv6, UINT datalen, int *recalc);
void acksplit_in_data(HANDLE w_filter, const WINDIVERT_ADDRESS *addr,
                      PWINDIVERT_IPHDR ip4, PWINDIVERT_IPV6HDR ip6,
                      PWINDIVERT_TCPHDR tcp, UINT datalen);
#endif
