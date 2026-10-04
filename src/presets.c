/*
 * Ready-made option sets for GoodbyeDPI: --preset <name>
 *
 * A preset is just a list of normal command line options which is
 * spliced into argv before getopt runs. Options given by the user
 * after the preset are processed as usual.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "presets.h"

#define PRESET_MAX_ARGS 24

typedef struct {
    const char *name;
    const char *description;
    const char *args[PRESET_MAX_ARGS]; /* NULL-terminated */
} preset_t;

/*
 * These are starting points, not guarantees: what works depends on the
 * ISP, the region, the modem/router and changes over time. Edit freely.
 *
 * The ISP presets deliberately use different fake-packet modes so they
 * can be compared against each other: -9 (wrong SEQ + wrong checksum),
 * -5 (auto TTL) and -6 (wrong SEQ only).
 */
static const preset_t presets[] = {
    {
        "viettel",
        "Viettel: mode -9 + DNS 1.1.1.1",
        { "-9", "--dns-addr", "1.1.1.1", NULL }
    },
    {
        "fpt",
        "FPT Telecom: mode -5 (auto TTL) + DNS 8.8.8.8",
        { "-5", "--dns-addr", "8.8.8.8", NULL }
    },
    {
        "vnpt",
        "VNPT: mode -6 (wrong SEQ) + DNS 1.1.1.1",
        { "-6", "--dns-addr", "1.1.1.1", NULL }
    },
    {
        "steam",
        "Steam only: circumvention applied to Steam domains, other traffic untouched. DNS 1.1.1.1",
        { "-f", "2", "-e", "2", "--wrong-seq", "--wrong-chksum", "--reverse-frag",
          "--max-payload=1200", "--frag-by-sni",
          "--blacklist-builtin", "steam",
          "--dns-addr", "1.1.1.1", NULL }
    },
};

#define PRESETS_COUNT (sizeof(presets) / sizeof(presets[0]))

static void print_list(void) {
    puts("Available presets:");
    for (size_t i = 0; i < PRESETS_COUNT; i++)
        printf(" %-8s %s\n", presets[i].name, presets[i].description);
}

static const preset_t *find_preset(const char *name) {
    for (size_t i = 0; i < PRESETS_COUNT; i++)
        if (strcmp(presets[i].name, name) == 0)
            return &presets[i];
    return NULL;
}

static int is_option(const char *arg, const char *name) {
    size_t len = strlen(name);
    return strncmp(arg, name, len) == 0 && (arg[len] == '\0' || arg[len] == '=');
}

static size_t preset_argc(const preset_t *preset) {
    size_t n = 0;
    while (n < PRESET_MAX_ARGS && preset->args[n])
        n++;
    return n;
}

int presets_expand(int argc, char *argv[], int *out_argc, char ***out_argv) {
    const char *name = NULL;
    const preset_t *preset;
    int user_dns = 0;
    int i;
    size_t j, n, pos = 0;
    char **new_argv;

    /* First pass: find the preset and note whether the user set DNS themselves */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--list-presets") == 0) {
            print_list();
            exit(EXIT_SUCCESS);
        }
        if (is_option(argv[i], "--preset")) {
            if (name) {
                puts("Only one --preset can be used.");
                return PRESET_ERROR;
            }
            if (argv[i][8] == '=') {
                name = argv[i] + 9;
            } else if (i + 1 < argc) {
                name = argv[++i];
            } else {
                puts("--preset requires a name.");
                print_list();
                return PRESET_ERROR;
            }
        } else if (is_option(argv[i], "--dns-addr")) {
            user_dns = 1;
        }
    }

    if (!name)
        return PRESET_NONE;

    preset = find_preset(name);
    if (!preset) {
        printf("Unknown preset: %s\n", name);
        print_list();
        return PRESET_ERROR;
    }

    n = preset_argc(preset);
    new_argv = malloc(sizeof(char *) * ((size_t)argc + n + 1));
    if (!new_argv) {
        puts("Out of memory while expanding preset.");
        return PRESET_ERROR;
    }

    new_argv[pos++] = argv[0];

    /* Preset options first. If the user gave their own --dns-addr, theirs wins */
    for (j = 0; j < n; j++) {
        if (user_dns && strcmp(preset->args[j], "--dns-addr") == 0) {
            j++; /* skip its value too */
            continue;
        }
        new_argv[pos++] = (char *)preset->args[j];
    }

    /* Then the user's own options, minus the preset selector itself */
    for (i = 1; i < argc; i++) {
        if (is_option(argv[i], "--preset")) {
            if (argv[i][8] != '=')
                i++; /* skip the name */
            continue;
        }
        new_argv[pos++] = argv[i];
    }
    new_argv[pos] = NULL;

    printf("Preset '%s': %s\nExpanded options:", preset->name, preset->description);
    for (i = 1; (size_t)i < pos; i++)
        printf(" %s", new_argv[i]);
    puts("\n");

    *out_argc = (int)pos;
    *out_argv = new_argv;
    return PRESET_EXPANDED;
}
