/* pathstr.h: every path function on two fuzz strings, into exact-size output buffers of a
   fuzz-chosen capacity (so ASan sees any write past capacity). */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define PATHSTR_IMPLEMENTATION
#include "../../pathstr.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 4096) return -1;
    size_t cap = data[0];
    const char *rest = (const char *)data + 1;
    size_t rlen = size - 1;
    const char *nul = memchr(rest, 0, rlen);
    size_t alen = nul ? (size_t)(nul - rest) : rlen;
    char *a = (char *)malloc(alen + 1); memcpy(a, rest, alen); a[alen] = 0;
    size_t blen = nul ? rlen - alen - 1 : 0;
    char *b = (char *)malloc(blen + 1); if (blen) memcpy(b, nul + 1, blen); b[blen] = 0;
    char *out = (char *)malloc(cap ? cap : 1);
    char *o = cap ? out : NULL;
    pathstr_basename(a, o, cap);
    pathstr_dirname(a, o, cap);
    pathstr_extname(a, o, cap);
    pathstr_replace_extension(a, b, o, cap);
    pathstr_join(a, b, o, cap);
    pathstr_normalize(a, o, cap);
    pathstr_to_posix(a, o, cap);
    pathstr_to_windows(a, o, cap);
    pathstr_make_relative(a, b, PATHSTR_CASE_SENSITIVE, o, cap);
    pathstr_make_relative(a, b, PATHSTR_CASE_INSENSITIVE, o, cap);
    (void)pathstr_is_absolute(a);
    (void)pathstr_is_relative(a);
    (void)pathstr_wildcard_compare(a, b, PATHSTR_CASE_SENSITIVE);
    (void)pathstr_wildcard_compare(a, b, PATHSTR_CASE_INSENSITIVE);
    free(out); free(a); free(b);
    return 0;
}
