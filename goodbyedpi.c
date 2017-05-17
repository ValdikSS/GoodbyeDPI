/*
 * GoodbyeDPI — Passive DPI blocker and Active DPI circumvention utility.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <winsock2.h>
#include "windivert.h"

#define die() do { printf("Something went wrong!\n" \
    "Make sure you're running this program with administrator privileges\n"); \
    sleep(10); exit(EXIT_FAILURE); } while (0)

#define MAX_FILTERS 4
#define MAX_PACKET_SIZE 1516
#define IPV4_HDR_LEN 20
#define TCP_HDR_LEN 20
#define IPV4_TOTALLEN_OFFSET 2
#define TCP_WINDOWSIZE_OFFSET 14
    
static HANDLE filters[MAX_FILTERS];
static int filter_num = 0;
static const char *http_redirect_10 = "HTTP/1.0 30";
static const char *http_redirect_11 = "HTTP/1.1 30";
static const char *http_host_find = "\r\nHost: ";
static const char *http_host_replace = "\r\nhoSt: ";
/*static const char *blocklist[] = {
    "warning.rt.ru",
};*/

static char* dumb_memmem(char* haystack, int hlen, char* needle, int nlen) {
    // naive implementation
    if (nlen > hlen) return 0;
    int i;
    for (i=0; i<hlen-nlen+1; i++) {
        if (memcmp(haystack+i,needle,nlen)==0) {
            return haystack+i;
        }
    }
    return NULL;
}

static HANDLE init(char *filter, UINT64 flags) {
    filter = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);
    if (filter != INVALID_HANDLE_VALUE)
        return filter;
    return NULL;
}

static int deinit(HANDLE handle) {
    if (handle) {
        WinDivertClose(handle);
        return 1;
    }
    return 0;
}

static void deinit_all() {
    for (int i = 0; i < filter_num; i++) {
        deinit(filters[i]);
    }
}

static void sigint_handler(int sig) {
    deinit_all();
    exit(EXIT_SUCCESS);
}

static int find_passivedpi_redirect(char *pktdata) {
    if (memcmp(pktdata, http_redirect_11, strlen(http_redirect_11)) == 0
        || memcmp(pktdata, http_redirect_10, strlen(http_redirect_10)) == 0) {
        return 1;
    }
    return 0;
}

/* Finds Host header with \r\n before it */
static PVOID find_host_header(char *pktdata, int pktlen) {
    return dumb_memmem(pktdata, pktlen,
                (char*)http_host_find, strlen(http_host_find));
}

static void change_window_size(char *pkt) {
    *(pkt + IPV4_HDR_LEN + TCP_WINDOWSIZE_OFFSET) = 0x00;
    *(pkt + IPV4_HDR_LEN + TCP_WINDOWSIZE_OFFSET + 1) = 0x02;
}

int main(int argc, char *argv[]) {
    int i, should_reinject = 0;
    HANDLE w_filter = NULL;
    WINDIVERT_ADDRESS addr;
    char packet[MAX_PACKET_SIZE];
    PVOID packet_data;
    UINT packetLen;
    UINT packet_dataLen;
    PWINDIVERT_IPHDR ppIpHdr;
    PWINDIVERT_TCPHDR ppTcpHdr;

    int do_passivedpi, do_fragment, do_host, do_host_removespace;
    int temp;
    char *data_addr, *data_addr_rn, *host_addr = NULL;
    int host_len, fromhost_uptoend_len;

    printf("GoodbyeDPI: Passive DPI blocker and Active DPI circumvention utility\n\n");

    if (argc == 2) {
        temp = atoi(argv[1]);
        do_passivedpi = !!(temp & 1);
        do_fragment = !!(temp & 2);
        do_host = !!(temp & 4);
        do_host_removespace = !!(temp & 8);

        printf("Block passive: %d, Fragment: %d, hoSt: %d, Host no space: %d\n",
               do_passivedpi, do_fragment, do_host, do_host_removespace);
    }
    else {
        printf("goodbyedpi.exe [1: block passive DPI, 2: fragment outbound, "
               "4: replace Host with hoSt, 8: remove space between host header and value]\n");
        printf("Default: 15 (all enabled)\n");

        do_passivedpi = 1;
        do_fragment = 1;
        do_host = 1;
        do_host_removespace = 1;
    }

    printf("Opening filter\n");
    filter_num = 0;

    if (do_passivedpi) {
        /* Filter for inbound RST packets with ID = 0 or 1 */
        filters[filter_num] = init("inbound and (ip.Id == 0x0001 or ip.Id == 0x0000) and "
                        "(tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst",
                        WINDIVERT_FLAG_DROP);
        filter_num++;
    }

    /* 
     * Filter for inbound HTTP redirection packets and
     * active DPI circumvention
     */
    filters[filter_num] = init("(inbound and (ip.Id == 0x0001 or ip.Id == 0x0000) and tcp.SrcPort == 80 and tcp.Ack) "
                      "or (inbound and (tcp.SrcPort == 80 or tcp.SrcPort == 443) and tcp.Ack and tcp.Syn) "
                      "or (outbound and (tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.Ack)",
                      0);

    w_filter = filters[filter_num];
    filter_num++;

    for (i = 0; i < filter_num; i++) {
        if (filters[i] == NULL)
            die();
    }

    printf("Filter activated!\n");
    signal(SIGINT, sigint_handler);

    while (1) {
        if (WinDivertRecv(w_filter, packet, sizeof(packet), &addr, &packetLen)) {
            //printf("Got %s packet, len=%d!\n", addr.Direction ? "inbound" : "outbound",
            //       packetLen);
            should_reinject = 1;

            if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
                NULL, NULL, NULL, &ppTcpHdr, NULL, &packet_data, &packet_dataLen)) {
                //printf("Got parsed packet, len=%d!\n", packet_dataLen);
                /* Got a packet WITH DATA */

                /* Handle INBOUND packet with data and find HTTP REDIRECT in there */
                if (addr.Direction == WINDIVERT_DIRECTION_INBOUND && packet_dataLen > 16) {
                    /* If INBOUND packet with DATA (tcp.Ack) */

                    /* Drop packets from blocklist */
                    /* for (i = 0; i < sizeof(blocklist) / sizeof(*blocklist); i++) {
                        if (dumb_memmem(packet_data, packet_dataLen, (char*)blocklist[i],
                            strlen(blocklist[i])) != NULL) {
                                printf("Dropping packet!\n");
                                dropped = 1;
                                break;
                        }
                    } */

                    /* Drop packets from filter with HTTP 30x Redirect */
                    if (do_passivedpi && find_passivedpi_redirect(packet_data)) {
                        //printf("Dropping HTTP Redirect packet!\n");
                        should_reinject = 0;
                    }
                }
                /* Handle OUTBOUND packet, search for Host header */
                else if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND && 
                         packet_dataLen > 16 && ppTcpHdr->DstPort == htons(80)) {
                    if (do_host || do_host_removespace) {
                        data_addr = find_host_header(packet_data, packet_dataLen);
                    }

                    if (do_host && data_addr) {
                        /* Replace "Host: " with "hoSt: " */
                        memcpy(data_addr, http_host_replace, strlen(http_host_replace));
                        //printf("Replaced Host header!\n");
                    }

                    if (do_host_removespace && data_addr) {
                        host_addr = data_addr + strlen(http_host_find);

                        data_addr_rn = dumb_memmem(host_addr,
                                                    packet_dataLen - ((PVOID)host_addr - packet_data),
                                                    "\r\n", 2);
                        if (data_addr_rn) {
                            host_len = data_addr_rn - host_addr;
                            fromhost_uptoend_len = packet_dataLen - ((PVOID)host_addr - packet_data);
                            if (host_len <= 64) {
                                /* Move memory left by 1 byte and reduce packet size for 1 byte */
                                memmove(host_addr - 1, host_addr, fromhost_uptoend_len);
                                /* Reduce "Total Length" in IP header by 1 byte */
                                *(uint16_t*)(packet + IPV4_TOTALLEN_OFFSET) = ntohs(
                                     htons(*(uint16_t*)(packet + IPV4_TOTALLEN_OFFSET)) - 1);
                                /* Reduce packetLen by 1 byte */
                                packetLen--;
                                //printf("Replaced Host header!\n");
                            }
                        }
                    }
                    if (do_host || do_host_removespace) {
                        WinDivertHelperCalcChecksums(packet, packetLen, 0);
                    }
                }
            }
            /* Else if we got TCP packet without data */
            else if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
                NULL, NULL, NULL, &ppTcpHdr, NULL, NULL, NULL)) {
                /* If we got SYN+ACK packet */
                if (addr.Direction == WINDIVERT_DIRECTION_INBOUND && 
                    ppTcpHdr->Syn == 1) {
                    if (do_fragment) {
                        //printf("Changing Window Size!\n");
                        change_window_size(packet);
                        WinDivertHelperCalcChecksums(packet, packetLen, 0);
                    }
                }
            }

            if (should_reinject) {
                //printf("Re-injecting!\n");
                WinDivertSend(w_filter, packet, packetLen, &addr, NULL);
            }
        }
        else {
            // error, ignore
            printf("Error receiving packet!\n");
            break;
        }
    }
}
