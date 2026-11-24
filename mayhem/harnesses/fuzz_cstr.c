/* cstr.h: string interning pool + string operations on fuzz strings. Input: 4 parameter bytes, then
   up to three NUL-separated strings. The pool is reset after every input (cstr_reset), so no state
   carries across inputs. The input is never used as a format string. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define CSTR_IMPLEMENTATION
#include "../../cstr.h"

static char *take(const uint8_t **p, size_t *n) {
    const uint8_t *z = memchr(*p, 0, *n);
    size_t l = z ? (size_t)(z - *p) : *n;
    char *s = (char *)malloc(l + 1);
    memcpy(s, *p, l); s[l] = 0;
    *p += z ? l + 1 : l; *n -= z ? l + 1 : l;
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > 4096) return -1;
    uint8_t k0 = data[0], k1 = data[1], k2 = data[2], pad = data[3];
    const uint8_t *p = data + 4; size_t n = size - 4;
    char *a = take(&p, &n), *b = take(&p, &n), *c = take(&p, &n);
    char const *s = cstr(a);
    char const *t = cstr_n(b, k0);
    (void)cstr_is_interned(s); (void)cstr_len(s);
    s = cstr_cat(s, t);
    (void)cstr_trim(s); (void)cstr_ltrim(s); (void)cstr_rtrim(s);
    (void)cstr_left(s, k0); (void)cstr_right(s, k1); (void)cstr_mid(s, k0, k1);
    (void)cstr_upper(s); (void)cstr_lower(s);
    (void)cstr_lpad(s, (char)pad, k2); (void)cstr_rpad(s, (char)pad, k2);
    (void)cstr_join(a, b, c);
    if (b[0]) (void)cstr_replace(s, b, c);
    int len = (int)cstr_len(s);
    (void)cstr_insert(s, len ? k0 % (len + 1) : 0, c);
    if (len) { int st = k1 % len; (void)cstr_remove(s, st, k2 % (len - st + 1)); }
    (void)cstr_format("%s|%s|%d", a, b, (int)k0);
    (void)cstr_int((int)(k0 << 24 | k1 << 16 | k2 << 8 | pad));
    (void)cstr_starts(s, b);
    cstr_reset();
    free(a); free(b); free(c);
    return 0;
}
