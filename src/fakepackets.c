#include <stdio.h>
#define _CRT_RAND_S
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <in6addr.h>
#include <ws2tcpip.h>
#include "windivert.h"
#include "goodbyedpi.h"

struct fake_t {
    const unsigned char* data;
    size_t size;
};

static struct fake_t *fakes[30] = {0};
int fakes_count = 0;
int fakes_resend = 1;

static const unsigned char fake_http_request[] = "GET / HTTP/1.1\r\nHost: www.w3.org\r\n"
                                                 "User-Agent: curl/7.65.3\r\nAccept: */*\r\n"
                                                 "Accept-Encoding: deflate, gzip, br\r\n\r\n";
static const unsigned char fake_https_request[] = {
    0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x9a, 0x8f, 0xa7, 0x6a, 0x5d,
    0x57, 0xf3, 0x62, 0x19, 0xbe, 0x46, 0x82, 0x45, 0xe2, 0x59, 0x5c, 0xb4, 0x48, 0x31, 0x12, 0x15,
    0x14, 0x79, 0x2c, 0xaa, 0xcd, 0xea, 0xda, 0xf0, 0xe1, 0xfd, 0xbb, 0x20, 0xf4, 0x83, 0x2a, 0x94,
    0xf1, 0x48, 0x3b, 0x9d, 0xb6, 0x74, 0xba, 0x3c, 0x81, 0x63, 0xbc, 0x18, 0xcc, 0x14, 0x45, 0x57,
    0x6c, 0x80, 0xf9, 0x25, 0xcf, 0x9c, 0x86, 0x60, 0x50, 0x31, 0x2e, 0xe9, 0x00, 0x22, 0x13, 0x01,
    0x13, 0x03, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30,
    0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x33, 0x00, 0x39, 0x00, 0x2f, 0x00, 0x35,
    0x01, 0x00, 0x01, 0x91, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x77, 0x77, 0x77,
    0x2e, 0x77, 0x33, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x0a, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00,
    0x01, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e,
    0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05,
    0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x1d, 0x00,
    0x20, 0xb0, 0xe4, 0xda, 0x34, 0xb4, 0x29, 0x8d, 0xd3, 0x5c, 0x70, 0xd3, 0xbe, 0xe8, 0xa7, 0x2a,
    0x6b, 0xe4, 0x11, 0x19, 0x8b, 0x18, 0x9d, 0x83, 0x9a, 0x49, 0x7c, 0x83, 0x7f, 0xa9, 0x03, 0x8c,
    0x3c, 0x00, 0x17, 0x00, 0x41, 0x04, 0x4c, 0x04, 0xa4, 0x71, 0x4c, 0x49, 0x75, 0x55, 0xd1, 0x18,
    0x1e, 0x22, 0x62, 0x19, 0x53, 0x00, 0xde, 0x74, 0x2f, 0xb3, 0xde, 0x13, 0x54, 0xe6, 0x78, 0x07,
    0x94, 0x55, 0x0e, 0xb2, 0x6c, 0xb0, 0x03, 0xee, 0x79, 0xa9, 0x96, 0x1e, 0x0e, 0x98, 0x17, 0x78,
    0x24, 0x44, 0x0c, 0x88, 0x80, 0x06, 0x8b, 0xd4, 0x80, 0xbf, 0x67, 0x7c, 0x37, 0x6a, 0x5b, 0x46,
    0x4c, 0xa7, 0x98, 0x6f, 0xb9, 0x22, 0x00, 0x2b, 0x00, 0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03,
    0x02, 0x03, 0x01, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
    0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x00,
    0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x15, 0x00, 0x96, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};

static int send_fake_data(const HANDLE w_filter,
                          const PWINDIVERT_ADDRESS addr,
                          const char *pkt,
                          const UINT packetLen,
                          const BOOL is_ipv6,
                          const BOOL is_https,
                          const BYTE set_ttl,
                          const BYTE set_checksum,
                          const BYTE set_seq,
                          const struct fake_t *fake_data
                         ) {
    char packet_fake[MAX_PACKET_SIZE];
    WINDIVERT_ADDRESS addr_new;
    PVOID packet_data;
    UINT packet_dataLen;
    UINT packetLen_new;
    PWINDIVERT_IPHDR ppIpHdr;
    PWINDIVERT_IPV6HDR ppIpV6Hdr;
    PWINDIVERT_TCPHDR ppTcpHdr;
    unsigned const char *fake_request_data = is_https ? fake_https_request : fake_http_request;
    UINT fake_request_size = is_https ? sizeof(fake_https_request) : sizeof(fake_http_request) - 1;
    if (fake_data) {
        fake_request_data = fake_data->data;
        fake_request_size = fake_data->size;
    }

    memcpy(&addr_new, addr, sizeof(WINDIVERT_ADDRESS));
    memcpy(packet_fake, pkt, packetLen);

    addr_new.TCPChecksum = 0;
    addr_new.IPChecksum = 0;

    if (!is_ipv6) {
        // IPv4 TCP Data packet
        if (!WinDivertHelperParsePacket(packet_fake, packetLen, &ppIpHdr,
            NULL, NULL, NULL, NULL, &ppTcpHdr, NULL, &packet_data, &packet_dataLen,
            NULL, NULL))
            return 1;
    }
    else {
        // IPv6 TCP Data packet
        if (!WinDivertHelperParsePacket(packet_fake, packetLen, NULL,
            &ppIpV6Hdr, NULL, NULL, NULL, &ppTcpHdr, NULL, &packet_data, &packet_dataLen,
            NULL, NULL))
            return 1;
    }

    if (packetLen + fake_request_size + 1 > MAX_PACKET_SIZE)
        return 2;

    memcpy(packet_data, fake_request_data, fake_request_size);
    packetLen_new = packetLen - packet_dataLen + fake_request_size;

    if (!is_ipv6) {
        ppIpHdr->Length = htons(
            ntohs(ppIpHdr->Length) -
            packet_dataLen + fake_request_size
        );

        if (set_ttl)
            ppIpHdr->TTL = set_ttl;
    }
    else {
        ppIpV6Hdr->Length = htons(
            ntohs(ppIpV6Hdr->Length) -
            packet_dataLen + fake_request_size
        );

        if (set_ttl)
            ppIpV6Hdr->HopLimit = set_ttl;
    }

    if (set_seq) {
        // This is the smallest ACK drift Linux can't handle already, since at least v2.6.18.
        // https://github.com/torvalds/linux/blob/v2.6.18/net/netfilter/nf_conntrack_proto_tcp.c#L395
        ppTcpHdr->AckNum = htonl(ntohl(ppTcpHdr->AckNum) - 66000);
        // This is just random, no specifics about this value.
        ppTcpHdr->SeqNum = htonl(ntohl(ppTcpHdr->SeqNum) - 10000);
    }

    // Recalculate the checksum
    WinDivertHelperCalcChecksums(packet_fake, packetLen_new, &addr_new, 0ULL);

    if (set_checksum) {
        // ...and damage it
        ppTcpHdr->Checksum = htons(ntohs(ppTcpHdr->Checksum) - 1);
    }
    //printf("Pseudo checksum: %d\n", addr_new.TCPChecksum);

    WinDivertSend(
        w_filter, packet_fake,
        packetLen_new,
        NULL, &addr_new
    );
    debug("Fake packet: OK");

    return 0;
}

static int send_fake_request(const HANDLE w_filter,
                                  const PWINDIVERT_ADDRESS addr,
                                  const char *pkt,
                                  const UINT packetLen,
                                  const BOOL is_ipv6,
                                  const BOOL is_https,
                                  const BYTE set_ttl,
                                  const BYTE set_checksum,
                                  const BYTE set_seq,
                                  const struct fake_t *fake_data
                                 ) {
    if (set_ttl) {
        send_fake_data(w_filter, addr, pkt, packetLen,
                          is_ipv6, is_https,
                          set_ttl, FALSE, FALSE,
                          fake_data);
    }
    if (set_checksum) {
        send_fake_data(w_filter, addr, pkt, packetLen,
                          is_ipv6, is_https,
                          FALSE, set_checksum, FALSE,
                          fake_data);
    }
    if (set_seq) {
        send_fake_data(w_filter, addr, pkt, packetLen,
                          is_ipv6, is_https,
                          FALSE, FALSE, set_seq,
                          fake_data);
    }
    return 0;
}

int send_fake_http_request(const HANDLE w_filter,
                                  const PWINDIVERT_ADDRESS addr,
                                  const char *pkt,
                                  const UINT packetLen,
                                  const BOOL is_ipv6,
                                  const BYTE set_ttl,
                                  const BYTE set_checksum,
                                  const BYTE set_seq
                                 ) {
    int ret = 0;
    for (int i=0; i<fakes_count || i == 0; i++) {
        for (int j=0; j<fakes_resend; j++)
            if (send_fake_request(w_filter, addr, pkt, packetLen,
                            is_ipv6, FALSE,
                            set_ttl, set_checksum, set_seq,
                            fakes[i]))
            {
                ret++;
            }
    }
    return ret;
}

int send_fake_https_request(const HANDLE w_filter,
                                   const PWINDIVERT_ADDRESS addr,
                                   const char *pkt,
                                   const UINT packetLen,
                                   const BOOL is_ipv6,
                                   const BYTE set_ttl,
                                   const BYTE set_checksum,
                                   const BYTE set_seq
                                 ) {
    int ret = 0;
    for (int i=0; i<fakes_count || i == 0; i++) {
        for (int j=0; j<fakes_resend; j++)
            if (send_fake_request(w_filter, addr, pkt, packetLen,
                          is_ipv6, TRUE,
                          set_ttl, set_checksum, set_seq,
                          fakes[i]))
            {
                ret++;
            }
    }
    return ret;
}

static int fake_add(const unsigned char *data, size_t size) {
    struct fake_t *fake = malloc(sizeof(struct fake_t));
    fake->size = size;
    fake->data = data;

    for (size_t k = 0; k <= sizeof(fakes) / sizeof(*fakes); k++) {
        if (!fakes[k]) {
            fakes[k] = fake;
            fakes_count++;
            return 0;
        }
    }
    return 3;
}

int fake_load_from_hex(const char *data) {
    size_t len = strlen(data);
    if (len < 2 || len % 2 || len > (1420 * 2))
        return 1;

    unsigned char *finaldata = calloc((len + 2) / 2, 1);

    for (size_t i = 0; i<len - 1; i+=2) {
        char num1 = data[i];
        char num2 = data[i+1];
        debug("Current num1: %X, num2: %X\n", num1, num2);
        unsigned char finalchar = 0;
        char curchar = num1;

        for (int j=0; j<=1; j++) {
            if (curchar >= '0' && curchar <= '9')
                curchar -= '0';
            else if (curchar >= 'a' && curchar <= 'f')
                curchar -= 'a' - 0xA;
            else if (curchar >= 'A' && curchar <= 'F')
                curchar -= 'A' - 0xA;
            else
                return 2; // incorrect character, not a hex data

            if (!j) {
                num1 = curchar;
                curchar = num2;
                continue;
            }
            num2 = curchar;
        }
        debug("Processed num1: %X, num2: %X\n", num1, num2);
        finalchar = (num1 << 4) | num2;
        debug("Final char: %X\n", finalchar);
        finaldata[i/2] = finalchar;
    }

    return fake_add(finaldata, len / 2);
}

int fake_load_random(unsigned int count, unsigned int maxsize) {
    if (count < 1 || count > sizeof(fakes) / sizeof(*fakes))
        return 1;

    unsigned int random = 0;

    for (unsigned int i=0; i<count; i++) {
        unsigned int len = 0;
        if (rand_s(&len))
            return 1;
        len = 8 + (len % maxsize);

        unsigned char *data = calloc(len, 1);
        for (unsigned int j=0; j<len; j++) {
            rand_s(&random);
            data[j] = random % 0xFF;
        }
        if (fake_add(data, len))
            return 2;
    }
    return 0;
}
