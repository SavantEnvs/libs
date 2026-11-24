/* libxdiff.h: binary patch (xdl_bpatch / xdl_bdiff_tgsize) and text unified-diff patch (xdl_patch).
   Input layout: 2-byte little-endian base length, base, then the patch. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/* libc provides these; without the HAVE_* macros libxdiff.h declares (and defines) its own */
#define HAVE_MEMCHR
#define HAVE_MEMCMP
#define HAVE_MEMCPY
#define HAVE_MEMSET
#define HAVE_STRLEN
#define LIBXDIFF_IMPLEMENTATION
#include "../../libxdiff.h"

static void *m_malloc(void *p, unsigned int n) { (void)p; return malloc(n); }
static void m_free(void *p, void *ptr) { (void)p; free(ptr); }
static void *m_realloc(void *p, void *ptr, unsigned int n) { (void)p; return realloc(ptr, n); }
static int out_cb(void *priv, mmbuffer_t *mb, int nbuf) {
    size_t *acc = (size_t *)priv;
    for (int i = 0; i < nbuf; i++) *acc += (size_t)mb[i].size;
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    memallocator_t ma = { NULL, m_malloc, m_free, m_realloc };
    xdl_set_allocator(&ma);
    return 0;
}

static int fill(mmfile_t *f, const uint8_t *p, size_t n) {
    if (xdl_init_mmfile(f, 1024, XDL_MMF_ATOMIC) < 0) return -1;
    if (n && xdl_write_mmfile(f, p, (long)n) != (long)n) { xdl_free_mmfile(f); return -1; }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > (1 << 20)) return -1;
    size_t blen = (size_t)data[0] | ((size_t)data[1] << 8);
    if (blen > size - 2) blen = size - 2;
    const uint8_t *base = data + 2, *patch = data + 2 + blen;
    size_t plen = size - 2 - blen;
    size_t acc = 0, rej = 0;
    xdemitcb_t ecb = { &acc, out_cb }, rjecb = { &rej, out_cb };
    mmfile_t mb, mp;
    if (fill(&mb, base, blen) < 0) return 0;
    if (fill(&mp, patch, plen) < 0) { xdl_free_mmfile(&mb); return 0; }
    (void)xdl_bdiff_tgsize(&mp);
    xdl_bpatch(&mb, &mp, &ecb);
    xdl_free_mmfile(&mb); xdl_free_mmfile(&mp);

    if (fill(&mb, base, blen) < 0) return 0;
    if (fill(&mp, patch, plen) < 0) { xdl_free_mmfile(&mb); return 0; }
    xdl_patch(&mb, &mp, XDL_PATCH_NORMAL, &ecb, &rjecb);
    xdl_free_mmfile(&mb); xdl_free_mmfile(&mp);
    return 0;
}
