int blackwhitelist_load_blacklist(const char *filename);
int blackwhitelist_load_whitelist(const char *filename);
int blackwhitelist_check_hostname_blacklist(const char *host_addr, size_t host_len);
int blackwhitelist_check_hostname_whitelist(const char *host_addr, size_t host_len);
