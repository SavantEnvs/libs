/* assetsys.h: mount a zip archive from memory (bundled miniz) and load every file in it. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define ASSETSYS_IMPLEMENTATION
#define STRPOOL_IMPLEMENTATION
#include "../../strpool.h"
#include "../../assetsys.h"

static void walk(assetsys_t *sys, const char *path, int depth) {
    if (depth > 16) return;
    int fc = assetsys_file_count(sys, path);
    for (int i = 0; i < fc; i++) {
        const char *fp = assetsys_file_path(sys, path, i);
        (void)assetsys_file_name(sys, path, i);
        if (!fp) continue;
        assetsys_file_t f;
        if (assetsys_file(sys, fp, &f) != ASSETSYS_SUCCESS) continue;
        int sz = assetsys_file_size(sys, f);
        if (sz < 0 || sz > (1 << 24)) continue;
        void *b = malloc(sz ? sz : 1);
        if (!b) continue;
        int got = 0;
        assetsys_file_load(sys, f, &got, b, sz);
        free(b);
    }
    int sc = assetsys_subdir_count(sys, path);
    for (int i = 0; i < sc; i++) {
        const char *sp = assetsys_subdir_path(sys, path, i);
        (void)assetsys_subdir_name(sys, path, i);
        if (sp) walk(sys, sp, depth + 1);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0x7fffffff) return -1;
    assetsys_t *sys = assetsys_create(NULL);
    if (!sys) return 0;
    if (assetsys_mount_from_memory(sys, data, (int)size, "/data") == ASSETSYS_SUCCESS) {
        walk(sys, "/data", 0);
        assetsys_dismount(sys, "", "/data");
    }
    assetsys_destroy(sys);
    return 0;
}
