#ifndef _PRESETS_H
#define _PRESETS_H

#define PRESET_NONE      0
#define PRESET_EXPANDED  1
#define PRESET_ERROR    -1

/*
 * Looks for "--preset <name>" / "--preset=<name>" and "--list-presets"
 * in the command line.
 *
 * Returns PRESET_NONE if there is nothing to expand (out_* are untouched),
 * PRESET_EXPANDED if a newly allocated argv was stored in out_argv/out_argc,
 * or PRESET_ERROR if the preset name is missing or unknown (a message
 * has been printed). --list-presets prints the list and exits.
 */
int presets_expand(int argc, char *argv[], int *out_argc, char ***out_argv);

#endif
