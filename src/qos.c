#include <windows.h>
#include "goodbyedpi.h"
#include "qos.h"
#include "windivert.h"

#define QOS_FILTER   "outbound and !loopback and !impostor and (ip or ipv6)"
#define QOS_PRIORITY (-1000)

static HANDLE qos_handle = NULL, qos_thread = NULL;
static volatile LONG qos_run = 0;
static uint8_t qos_dscp_value = 46;   /* EF */

static DWORD WINAPI qos_proc(LPVOID unused) {
    char packet[MAX_PACKET_SIZE];
    UINT packetLen;
    WINDIVERT_ADDRESS addr;
    (void)unused;

    while (qos_run) {
        if (!WinDivertRecv(qos_handle, packet, sizeof(packet), &packetLen, &addr)) {
            if (GetLastError() == ERROR_NO_DATA) break;
            continue;
        }
        if (!addr.IPv6 && packetLen >= sizeof(WINDIVERT_IPHDR)) {
            PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)packet;
            uint8_t newtos = (uint8_t)((qos_dscp_value << 2) | (ip->TOS & 0x03)); /* ECN сохраняем */
            if (ip->TOS != newtos) {
                ip->TOS = newtos;
                addr.IPChecksum = 0;
                /* меняется только IP-заголовок: транспортные суммы не трогаем */
                WinDivertHelperCalcChecksums(packet, packetLen, &addr,
                    WINDIVERT_HELPER_NO_TCP_CHECKSUM  |
                    WINDIVERT_HELPER_NO_UDP_CHECKSUM  |
                    WINDIVERT_HELPER_NO_ICMP_CHECKSUM |
                    WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM);
            }
        }
        else if (addr.IPv6 && packetLen >= sizeof(WINDIVERT_IPV6HDR)) {
            uint8_t *p = (uint8_t*)packet;
            uint8_t tc  = (uint8_t)(((p[0] & 0x0F) << 4) | (p[1] >> 4));
            uint8_t ntc = (uint8_t)((qos_dscp_value << 2) | (tc & 0x03));
            p[0] = (uint8_t)((p[0] & 0xF0) | (ntc >> 4));
            p[1] = (uint8_t)((p[1] & 0x0F) | ((ntc & 0x0F) << 4));
            /* в IPv6 нет контрольной суммы заголовка */
        }
        WinDivertSend(qos_handle, packet, packetLen, NULL, &addr);
    }
    return 0;
}

int qos_start(uint8_t dscp) {
    if (qos_handle) return TRUE;
    qos_dscp_value = dscp & 0x3F;
    qos_handle = WinDivertOpen(QOS_FILTER, WINDIVERT_LAYER_NETWORK, QOS_PRIORITY, 0);
    if (qos_handle == INVALID_HANDLE_VALUE) { qos_handle = NULL; return FALSE; }
    WinDivertSetParam(qos_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
    WinDivertSetParam(qos_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);
    qos_run = 1;
    qos_thread = CreateThread(NULL, 0, qos_proc, NULL, 0, NULL);
    return qos_thread != NULL;
}

void qos_stop(void) {
    if (!qos_handle) return;
    qos_run = 0;
    WinDivertShutdown(qos_handle, WINDIVERT_SHUTDOWN_BOTH);
    if (qos_thread) { WaitForSingleObject(qos_thread, 2000); CloseHandle(qos_thread); }
    WinDivertClose(qos_handle);
    qos_handle = NULL; qos_thread = NULL;
}
