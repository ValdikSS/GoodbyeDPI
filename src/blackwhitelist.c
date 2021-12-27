/*
 * Blacklist for GoodbyeDPI HTTP DPI circumvention tricks
 *
 * This is a simple domain hash table.
 * Domain records are added from a text file, where every
 * domain is separated with a new line.
 */
#include <windows.h>
#include <stdio.h>
#include "goodbyedpi.h"
#include "utils/uthash.h"
#include "utils/getline.h"

typedef struct blackwhitelist_record {
    const char *host;
    UT_hash_handle hh;   /* makes this structure hashable */
} blackwhitelist_record_t;

static blackwhitelist_record_t *blackwhitelist = NULL;

static int check_get_hostname(const char *host) {
    blackwhitelist_record_t *tmp_record = NULL;
    if (!blackwhitelist) return FALSE;

    HASH_FIND_STR(blackwhitelist, host, tmp_record);
    if (tmp_record) {
        debug("check_get_hostname found host\n");
        return TRUE;
    }
    debug("check_get_hostname host not found\n");
    return FALSE;
}

static int add_hostname(const char *host) {
    if (!host)
        return FALSE;

    blackwhitelist_record_t *tmp_record = malloc(sizeof(blackwhitelist_record_t));
    char *host_c = NULL;

    if (!check_get_hostname(host)) {
        host_c = strdup(host);
        tmp_record->host = host_c;
        HASH_ADD_KEYPTR(hh, blackwhitelist, tmp_record->host,
                        strlen(tmp_record->host), tmp_record);
        debug("Added host %s\n", host_c);
        return TRUE;
    }
    debug("Not added host %s\n", host);
    free(tmp_record);
    if (host_c)
        free(host_c);
    return FALSE;
}

int blackwhitelist_load_list(const char *filename) {
    char *line = malloc(HOST_MAXLEN + 1);
    size_t linelen = HOST_MAXLEN + 1;
    int cnt = 0;
    ssize_t read;

    FILE *fp = fopen(filename, "r");
    if (!fp) return FALSE;

    while ((read = getline(&line, &linelen, fp)) != -1) {
        /* works with both \n and \r\n */
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > HOST_MAXLEN) {
            printf("WARNING: host %s exceeds maximum host length and has not been added\n",
                line);
            continue;
        }
        if (strlen(line) < 3) {
            printf("WARNING: host %s is less than 3 bytes, skipping\n", line);
            continue;
        }
        if (add_hostname(line))
            cnt++;
    }
    free(line);
    if (!blackwhitelist) return FALSE;
    printf("Loaded %d hosts from file %s\n", cnt, filename);
    fclose(fp);
    return TRUE;
}

int blackwhitelist_check_hostname(const char *host_addr, size_t host_len) {
    char current_host[HOST_MAXLEN + 1];
    char *tokenized_host = NULL;

    if (host_len > HOST_MAXLEN) return FALSE;
    if (host_addr && host_len) {
        memcpy(current_host, host_addr, host_len);
        current_host[host_len] = '\0';
    }

    if (check_get_hostname(current_host))
            return TRUE;

    tokenized_host = strchr(current_host, '.');
    while (tokenized_host != NULL && tokenized_host < (current_host + HOST_MAXLEN)) {
        /* Search hostname only if there is next token */
        if (strchr(tokenized_host + 1, '.') && check_get_hostname(tokenized_host + 1))
            return TRUE;
        tokenized_host = strchr(tokenized_host + 1, '.');
    }

    debug("____blackwhitelist_check_hostname FALSE: host %s\n", current_host);
    return FALSE;
}
