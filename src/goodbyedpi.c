static void send_native_fragment(HANDLE w_filter, WINDIVERT_ADDRESS addr,
                        char *packet, UINT packetLen, PVOID packet_data,
                        UINT packet_dataLen, int packet_v4, int packet_v6,
                        PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr,
                        PWINDIVERT_TCPHDR ppTcpHdr,
                        unsigned int fragment_size, int step) {
    char packet_bak[MAX_PACKET_SIZE];
    memcpy(packet_bak, packet, packetLen);
    UINT orig_packetLen = packetLen;

    if (fragment_size >= packet_dataLen) {
        if (step == 1)
            fragment_size = 0;
        else
            return;
    }

    switch(step) {
        case 0:
            if (packet_v4)
                ppIpHdr->Length = htons(
                    ntohs(ppIpHdr->Length) -
                    packet_dataLen + fragment_size
                );
            else if (packet_v6)
                ppIpV6Hdr->Length = htons(
                    ntohs(ppIpV6Hdr->Length) -
                    packet_dataLen + fragment_size
                );
            packetLen = packetLen - packet_dataLen + fragment_size;
            break;
        case 1:
            if (packet_v4)
                ppIpHdr->Length = htons(
                    ntohs(ppIpHdr->Length) - fragment_size
                );
            else if (packet_v6)
                ppIpV6Hdr->Length = htons(
                    ntohs(ppIpV6Hdr->Length) - fragment_size
                );
            memmove(packet_data,
                    (char*)packet_data + fragment_size,
                    packet_dataLen - fragment_size);
            packetLen -= fragment_size;

            ppTcpHdr->SeqNum = htonl(ntohl(ppTcpHdr->SeqNum) + fragment_size);
            break;
    }

    addr.IPChecksum = 0;
    addr.TCPChecksum = 0;

    WinDivertHelperCalcChecksums(
        packet, packetLen, &addr, 0
    );
    WinDivertSend(
        w_filter, packet,
        packetLen,
        NULL, &addr
    );
    memcpy(packet, packet_bak, orig_packetLen);
}
