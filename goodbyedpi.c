/*
 * GoodbyeDPI — Passive DPI blocker and Active DPI circumvention utility.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <winsock2.h>
#include "windivert.h"

#define die() do { printf("Something went wrong!\n" \
    "Make sure you're running this program with administrator privileges\n"); \
    sleep(10); exit(EXIT_FAILURE); } while (0)

#define MAX_FILTERS 4
#define MAX_PACKET_SIZE 9016
#define IPV4_HDR_LEN 20
#define TCP_HDR_LEN 20
#define IPV4_TOTALLEN_OFFSET 2
#define TCP_WINDOWSIZE_OFFSET 14

#define DIVERT_NO_LOCALNETS_DST "(" \
                   "(ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and " \
                   "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and " \
                   "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and " \
                   "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and " \
                   "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)" \
                   ")"
#define DIVERT_NO_LOCALNETS_SRC "(" \
                   "(ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and " \
                   "(ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and " \
                   "(ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and " \
                   "(ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and " \
                   "(ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255)" \
                   ")"
    
static HANDLE filters[MAX_FILTERS];
static int filter_num = 0;
static const char *http10_redirect_302 = "HTTP/1.0 302 ";
static const char *http11_redirect_302 = "HTTP/1.1 302 ";
static const char *http_host_find = "\r\nHost: ";
static const char *http_host_replace = "\r\nhoSt: ";
static const char *http_useragent_find = "\r\nUser-Agent: ";
static const char *location_http = "\r\nLocation: http://";
static const char *connection_close = "\r\nConnection: close";
static const char *http_methods[] = {
    "GET ",
    "HEAD ",
    "POST ",
    "PUT ",
    "DELETE ",
    "CONNECT ",
    "OPTIONS ",
};

static char* dumb_memmem(const char* haystack, int hlen, const char* needle, int nlen) {
    // naive implementation
    if (nlen > hlen) return NULL;
    int i;
    for (i=0; i<hlen-nlen+1; i++) {
        if (memcmp(haystack+i,needle,nlen)==0) {
            return (char*)(haystack+i);
        }
    }
    return NULL;
}

static HANDLE init(char *filter, UINT64 flags) {
    LPTSTR errormessage = NULL;
    filter = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);
    if (filter != INVALID_HANDLE_VALUE)
        return filter;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, GetLastError(), MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                  (LPTSTR)&errormessage, 0, NULL);
    printf("%s", errormessage);
    return NULL;
}

static int deinit(HANDLE handle) {
    if (handle) {
        WinDivertClose(handle);
        return TRUE;
    }
    return FALSE;
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

static void mix_case(char *pktdata, int pktlen) {
    int i;

    if (pktlen <= 0) return;
    for (i = 0; i < pktlen; i++) {
        if (i % 2) {
            pktdata[i] = toupper(pktdata[i]);
        }
    }
}

static int is_passivedpi_redirect(const char *pktdata, int pktlen) {
    /* First check if this is HTTP 302 redirect */
    if (memcmp(pktdata, http11_redirect_302, strlen(http11_redirect_302)) == 0 ||
        memcmp(pktdata, http10_redirect_302, strlen(http10_redirect_302)) == 0)
    {
        /* Then check if this is a redirect to new http site with Connection: close */
        if (dumb_memmem(pktdata, pktlen, location_http, strlen(location_http)) &&
            dumb_memmem(pktdata, pktlen, connection_close, strlen(connection_close))) {
            return TRUE;
        }
    }
    return FALSE;
}

static int find_header_and_get_info(const char *pktdata, int pktlen,
                const char *hdrname,
                char **hdrnameaddr,
                char **hdrvalueaddr, int *hdrvaluelen) {
    char *data_addr_rn;
    char *hdr_begin;

    *hdrvaluelen = 0;
    *hdrnameaddr = NULL;
    *hdrvalueaddr = NULL;

    /* Search for the header */
    hdr_begin = dumb_memmem(pktdata, pktlen,
                hdrname, strlen(hdrname));
    if (!hdr_begin) return FALSE;
    if ((PVOID)pktdata > (PVOID)hdr_begin) return FALSE;

    /* Set header address */
    *hdrnameaddr = hdr_begin;
    *hdrvalueaddr = (PVOID)hdr_begin + strlen(hdrname);

    /* Search for header end (\r\n) */
    data_addr_rn = dumb_memmem(*hdrvalueaddr,
                        pktlen - ((PVOID)*hdrvalueaddr - (PVOID)pktdata),
                        "\r\n", 2);
    if (data_addr_rn) {
        *hdrvaluelen = (PVOID)data_addr_rn - (PVOID)*hdrvalueaddr;
        if (*hdrvaluelen > 0 && *hdrvaluelen <= 512)
            return TRUE;
    }
    return FALSE;
}

static void change_window_size(const char *pkt, int size) {
    if (size >= 1 && size <= 65535) {
        *(uint16_t*)(pkt + IPV4_HDR_LEN + TCP_WINDOWSIZE_OFFSET) = htons(size);
    }
}

/* HTTP method end without trailing space */
static PVOID find_http_method_end(const char *pkt, int offset) {
    int i;
    for (i = 0; i<(sizeof(http_methods) / sizeof(*http_methods)); i++) {
        if (memcmp(pkt, http_methods[i], strlen(http_methods[i])) == 0) {
            return (char*)pkt + strlen(http_methods[i]) - 1;
        }
        /* Try to find HTTP method in a second part of fragmented packet */
        if ((offset == 1 || offset == 2) &&
            memcmp(pkt, http_methods[i] + offset,
                   strlen(http_methods[i]) - offset) == 0
           )
        {
            return (char*)pkt + strlen(http_methods[i]) - offset - 1;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    static const char fragment_size_message[] =
                "Fragment size should be in range [0 - 65535]\n";
    int i, should_reinject, should_recalc_checksum = 0;
    int opt;
    HANDLE w_filter = NULL;
    WINDIVERT_ADDRESS addr;
    char packet[MAX_PACKET_SIZE];
    PVOID packet_data;
    UINT packetLen;
    UINT packet_dataLen;
    PWINDIVERT_IPHDR ppIpHdr;
    PWINDIVERT_TCPHDR ppTcpHdr;

    int do_passivedpi = 0, do_fragment_http = 0,
        do_fragment_https = 0, do_host = 0,
        do_host_removespace = 0, do_additional_space = 0,
        do_host_mixedcase = 0;
    int http_fragment_size = 2;
    int https_fragment_size = 2;
    char *host_addr, *useragent_addr, *method_addr;
    int host_len, useragent_len;

    char *hdr_name_addr = NULL, *hdr_value_addr = NULL;
    int hdr_value_len;

    printf("GoodbyeDPI: Passive DPI blocker and Active DPI circumvention utility\n");

    if (argc == 1) {
        /* enable mode -1 by default */
        do_passivedpi = do_host = do_host_removespace \
            = do_fragment_http = do_fragment_https = 1;
    }

    while ((opt = getopt(argc, argv, "1234prsaf:e:m")) != -1) {
        switch (opt) {
            case '1':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https = 1;
                break;
            case '2':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https = 1;
                https_fragment_size = 40;
                break;
            case '3':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_https = 1;
                https_fragment_size = 40;
            case '4':
                do_passivedpi = do_host = do_host_removespace = 1;
                break;
            case 'p':
                do_passivedpi = 1;
                break;
            case 'r':
                do_host = 1;
                break;
            case 's':
                do_host_removespace = 1;
                break;
            case 'a':
                do_additional_space = 1;
                do_host_removespace = 1;
                break;
            case 'm':
                do_host_mixedcase = 1;
                break;
            case 'f':
                do_fragment_http = 1;
                http_fragment_size = atoi(optarg);
                if (http_fragment_size <= 0 || http_fragment_size > 65535) {
                    printf(fragment_size_message);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'e':
                do_fragment_https = 1;
                https_fragment_size = atoi(optarg);
                if (https_fragment_size <= 0 || https_fragment_size > 65535) {
                    printf(fragment_size_message);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                printf("Usage: goodbyedpi.exe [OPTION...]\n"
                " -p          block passive DPI\n"
                " -r          replace Host with hoSt\n"
                " -s          remove space between host header and its value\n"
                " -a          additional space between Method and Request-URI (enables -s, may break sites)\n"
                " -m          mix Host header case (test.com -> tEsT.cOm)\n"
                " -f [value]  set HTTP fragmentation to value\n"
                " -e [value]  set HTTPS fragmentation to value\n"
                "\n"
                " -1          -p -r -s -f 2 -e 2 (most compatible mode, default)\n"
                " -2          -p -r -s -f 2 -e 40 (better speed yet still compatible)\n"
                " -3          -p -r -s -e 40 (even better speed)\n"
                " -4          -p -r -s (best speed)\n");
                exit(EXIT_FAILURE);
        }
    }

    printf("Block passive: %d, Fragment HTTP: %d, Fragment HTTPS: %d, "
           "hoSt: %d, Host no space: %d, Additional space: %d, Mix Host: %d\n",
           do_passivedpi, (do_fragment_http ? http_fragment_size : 0),
           (do_fragment_https ? https_fragment_size : 0),
           do_host, do_host_removespace, do_additional_space, do_host_mixedcase);

    if (do_fragment_http && http_fragment_size > 2) {
        printf("WARNING: HTTP fragmentation values > 2 are not fully compatible "
               "with other options. Please use values <= 2 or disable HTTP fragmentation "
               "completely.\n");
    }

    printf("\nOpening filter\n");
    filter_num = 0;

    if (do_passivedpi) {
        /* IPv4 filter for inbound RST packets with ID = 0 or 1 */
        filters[filter_num] = init(
            "inbound and ip and tcp and "
            "(ip.Id == 0x0001 or ip.Id == 0x0000) and "
            "(tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst and "
            DIVERT_NO_LOCALNETS_SRC,
            WINDIVERT_FLAG_DROP);
        filter_num++;
    }

    /* 
     * IPv4 filter for inbound HTTP redirection packets and
     * active DPI circumvention
     */
    filters[filter_num] = init("ip and tcp and "
        "(inbound and (("
         "((ip.Id == 0x0001 or ip.Id == 0x0000) and tcp.SrcPort == 80 and tcp.Ack) or "
         "((tcp.SrcPort == 80 or tcp.SrcPort == 443) and tcp.Ack and tcp.Syn)"
         ") and " DIVERT_NO_LOCALNETS_SRC ") or "
        "(outbound and "
         "(tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.Ack and "
         DIVERT_NO_LOCALNETS_DST ")"
        ")",
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
            should_recalc_checksum = 0;

            if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
                NULL, NULL, NULL, &ppTcpHdr, NULL, &packet_data, &packet_dataLen)) {
                //printf("Got parsed packet, len=%d!\n", packet_dataLen);
                /* Got a packet WITH DATA */

                /* Handle INBOUND packet with data and find HTTP REDIRECT in there */
                if (addr.Direction == WINDIVERT_DIRECTION_INBOUND && packet_dataLen > 16) {
                    /* If INBOUND packet with DATA (tcp.Ack) */

                    /* Drop packets from filter with HTTP 30x Redirect */
                    if (do_passivedpi && is_passivedpi_redirect(packet_data, packet_dataLen)) {
                        //printf("Dropping HTTP Redirect packet!\n");
                        should_reinject = 0;
                    }
                }
                /* Handle OUTBOUND packet on port 80, search for Host header */
                else if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND && 
                        packet_dataLen > 16 && ppTcpHdr->DstPort == htons(80) &&
                        find_http_method_end(packet_data,
                                             (do_fragment_http ? http_fragment_size : 0)) &&
                        (do_host || do_host_removespace || do_host_mixedcase))
                {

                    /* Find Host header */
                    if (find_header_and_get_info(packet_data, packet_dataLen,
                        http_host_find, &hdr_name_addr, &hdr_value_addr, &hdr_value_len)) {
                        host_addr = hdr_value_addr;
                        host_len = hdr_value_len;

                        if (do_host_mixedcase && host_len > 0 && host_len <= 253) {
                            mix_case(host_addr, host_len);
                            should_recalc_checksum = 1;
                        }

                        if (do_host) {
                            /* Replace "Host: " with "hoSt: " */
                            memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
                            should_recalc_checksum = 1;
                            //printf("Replaced Host header!\n");
                        }

                        /* If removing space between host header and its value
                         * and adding additional space between Method and Request-URI */
                        if (do_additional_space && do_host_removespace) {
                            /* End of "Host:" without trailing space */
                            method_addr = find_http_method_end(packet_data,
                                                            (do_fragment_http ? http_fragment_size : 0));

                            if (method_addr) {
                                memmove(method_addr + 1, method_addr,
                                        (PVOID)host_addr - (PVOID)method_addr - 1);
                                should_recalc_checksum = 1;
                            }
                        }
                        /* If just removing space between host header and its value */
                        else if (do_host_removespace) {
                            if (find_header_and_get_info(packet_data, packet_dataLen,
                                                        http_useragent_find, &hdr_name_addr,
                                                         &hdr_value_addr, &hdr_value_len))
                            {
                                useragent_addr = hdr_value_addr;
                                useragent_len = hdr_value_len;

                                /* We move Host header value by one byte to the left and then
                                 * "insert" stolen space to the end of User-Agent value because
                                 * some web servers are not tolerant to additional space in the
                                 * end of Host header.
                                 *
                                 * Nothing is done if User-Agent header is missing.
                                 */
                                if (host_len > 0 && host_len <= 253 &&
                                    useragent_addr && useragent_len > 0) {
                                    /* useragent_addr is in the beginning of User-Agent value */

                                    if (useragent_addr > host_addr) {
                                        /* Move one byte to the LEFT from "Host:"
                                        * to the end of User-Agent
                                        */
                                        memmove(host_addr - 1, host_addr, useragent_len);
                                        host_addr -= 1;
                                        /* Put space in the end of User-Agent header */
                                        *(char*)((PVOID)useragent_addr + useragent_len - 1) = ' ';
                                        should_recalc_checksum = 1;
                                        //printf("Replaced Host header!\n");
                                    }
                                    else {
                                        /* User-Agent goes BEFORE Host header */

                                        /* Move one byte to the RIGHT from the end of User-Agent
                                        * to the "Host:"
                                        */
                                        memmove((PVOID)useragent_addr + useragent_len + 1,
                                                (PVOID)useragent_addr + useragent_len,
                                                useragent_len - 1);
                                        /* Put space in the end of User-Agent header */
                                        *(char*)((PVOID)useragent_addr + useragent_len) = ' ';
                                        should_recalc_checksum = 1;
                                        //printf("Replaced Host header!\n");
                                    }
                                } /* if (host_len <= 253 && useragent_addr) */
                            } /* if (find_header_and_get_info http_useragent) */
                        } /* else if (do_host_removespace) */
                    } /* if (find_header_and_get_info http_host) */
                } /* Handle OUTBOUND packet with data */
            } /* Handle packet with data */

            /* Else if we got TCP packet without data */
            else if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
                NULL, NULL, NULL, &ppTcpHdr, NULL, NULL, NULL)) {
                /* If we got INBOUND SYN+ACK packet */
                if (addr.Direction == WINDIVERT_DIRECTION_INBOUND && 
                    ppTcpHdr->Syn == 1 && ppTcpHdr->Ack == 1) {
                    //printf("Changing Window Size!\n");
                    if (do_fragment_http && ppTcpHdr->SrcPort == htons(80)) {
                        change_window_size(packet, http_fragment_size);
                        should_recalc_checksum = 1;
                    }
                    else if (do_fragment_https && ppTcpHdr->SrcPort != htons(80)) {
                        change_window_size(packet, https_fragment_size);
                        should_recalc_checksum = 1;
                    }
                }
            }

            if (should_reinject) {
                //printf("Re-injecting!\n");
                if (should_recalc_checksum) {
                    WinDivertHelperCalcChecksums(packet, packetLen, 0);
                }
                else {
                    WinDivertHelperCalcChecksums(packet, packetLen,
                                                 WINDIVERT_HELPER_NO_REPLACE);
                }
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
