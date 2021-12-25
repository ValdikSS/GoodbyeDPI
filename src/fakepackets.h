int send_fake_http_request(const HANDLE w_filter,
                                  const PWINDIVERT_ADDRESS addr,
                                  const char *pkt,
                                  const UINT packetLen,
                                  const BOOL is_ipv6,
                                  const BYTE set_ttl,
                                  const BYTE set_checksum,
                                  const BYTE set_seq
                                 );
int send_fake_https_request(const HANDLE w_filter,
                                   const PWINDIVERT_ADDRESS addr,
                                   const char *pkt,
                                   const UINT packetLen,
                                   const BOOL is_ipv6,
                                   const BYTE set_ttl,
                                   const BYTE set_checksum,
                                   const BYTE set_seq
                                 );
