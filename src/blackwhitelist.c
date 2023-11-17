/*
 * Blacklist for GoodbyeDPI HTTP DPI circumvention tricks
 *
 * This is a simple domain hash table.
 * Domain records are added from a file, where every
 * domain is separated by a new line.
 */
#include <windows.h>
#include <stdio.h>
#include "goodbyedpi.h"
#include "utils/uthash.h"
#include "utils/getline.h"

/* Define the minimum length of a host name */
#define HOST_MINLEN 3

/* Define the structure of a blacklist record */
typedef struct blacklist_record {
    const char *host; /* The host name of the blacklisted domain */
    UT_hash_handle hh; /* The hash handle for the hash table */
} blacklist_record_t;

/* Check if a host name is in the blacklist hash table */
static int blacklist_check_hostname(const char *host, blacklist_record_t *blacklist) {
    blacklist_record_t *tmp_record = NULL;
    if (!blacklist) return FALSE; /* Return false if the hash table is empty */

    HASH_FIND_STR(blacklist, host, tmp_record); /* Find the host name in the hash table */
    if (tmp_record) {
        debug("blacklist_check_hostname found host\n");
        return TRUE; /* Return true if the host name is found */
    }
    debug("blacklist_check_hostname host not found\n");
    return FALSE; /* Return false if the host name is not found */
}

/* Add a host name to the blacklist hash table */
static int blacklist_add_hostname(const char *host, blacklist_record_t **blacklist) {
    if (!host || !blacklist)
        return FALSE; /* Return false if the host name or the hash table pointer is null */

    blacklist_record_t *tmp_record = NULL;
    char *host_c = NULL;

    if (!blacklist_check_hostname(host, *blacklist)) { /* Check if the host name is already in the hash table */
        tmp_record = malloc(sizeof(blacklist_record_t)); /* Allocate memory for a new record */
        if (!tmp_record) return FALSE; /* Return false if the allocation fails */
        host_c = strdup(host); /* Duplicate the host name */
        if (!host_c) { /* Return false if the duplication fails */
            free(tmp_record); /* Free the allocated memory for the record */
            return FALSE;
        }
        tmp_record->host = host_c; /* Set the host name field of the record */
        HASH_ADD_KEYPTR(hh, *blacklist, tmp_record->host,
                        strlen(tmp_record->host), tmp_record); /* Add the record to the hash table */
        debug("Added host %s\n", host_c);
        return TRUE; /* Return true if the host name is added successfully */
    }
    debug("Not added host %s\n", host);
    return FALSE; /* Return false if the host name is already in the hash table */
}

/* Load the blacklist from a file and store it in a hash table */
int blacklist_load_list(const char *filename, blacklist_record_t **blacklist) {
    char *line = NULL;
    size_t linelen = 0;
    int cnt = 0;
    ssize_t read;

    FILE *fp = fopen(filename, "r"); /* Open the file for reading */
    if (!fp) return FALSE; /* Return false if the file does not exist or cannot be opened */

    while ((read = getline(&line, &linelen, fp)) != -1) { /* Read a line from the file */
        /* Remove the trailing newline or carriage return characters */
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) < HOST_MINLEN) { /* Skip the line if the host name is too short */
            printf("WARNING: host %s is less than %d bytes, skipping\n", line, HOST_MINLEN);
            continue;
        }
        if (blacklist_add_hostname(line, blacklist)) /* Add the host name to the hash table */
            cnt++; /* Increment the counter of added host names */
    }
    free(line); /* Free the allocated memory for the line buffer */
    if (!*blacklist) return FALSE; /* Return false if the hash table is empty */
    printf("Loaded %d hosts from file %s\n", cnt, filename);
    fclose(fp); /* Close the file */
    return TRUE; /* Return true if the hash table is loaded successfully */
}

/* Free the memory allocated for the blacklist hash table and its records */
void blacklist_free_list(blacklist_record_t **blacklist) {
    blacklist_record_t *tmp_record = NULL, *tmp = NULL;
    if (!blacklist || !*blacklist) return; /* Return if the hash table pointer is null or the hash table is empty */

    HASH_ITER(hh, *blacklist, tmp_record, tmp) { /* Iterate over the hash table records */
        HASH_DEL(*blacklist, tmp_record); /* Delete the record from the hash table */
        free(tmp_record->host); /* Free the memory allocated for the host name */
        free(tmp_record); /* Free the memory allocated for the record */
    }
    *blacklist = NULL; /* Set the hash table pointer to null */
}

/* Check if a host name matches any of the blacklisted domains */
int blacklist_match_hostname(const char *host_addr, size_t host_len, blacklist_record_t *blacklist) {
    char current_host[HOST_MAXLEN + 1];
    char *tokenized_host = NULL;

    if (host_len > HOST_MAXLEN) return FALSE; /* Return false if the host name is too long */
    if (host_addr && host_len) {
        memcpy(current_host, host_addr, host_len); /* Copy the host name to a local buffer */
        current_host[host_len] = '\0'; /* Add a null terminator */
    }

    if (blacklist_check_hostname(current_host, blacklist)) /* Check if the host name is in the hash table */
            return TRUE; /* Return true if the host name is found */

    tokenized_host = strchr(current_host, '.'); /* Find the first dot in the host name */
    while (tokenized_host != NULL && tokenized_host < (current_host + HOST_MAXLEN)) {
        /* Search hostname only if there is next token */
        if (strchr(tokenized_host + 1, '.') && blacklist_check_hostname(tokenized_host + 1, blacklist))
            return TRUE; /* Return true if the host name is found */
        tokenized_host = strchr(tokenized_host + 1, '.'); /* Find the next dot in the host name */
    }

    debug("____blacklist_match_hostname FALSE: host %s\n", current_host);
    return FALSE; /* Return false if the host name is not found */
}
