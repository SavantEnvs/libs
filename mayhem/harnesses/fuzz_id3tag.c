/* id3tag.h: ID3v2 tag parse (all fields), ID3v1 parse of the trailing 128 bytes.
   (id3tag_save is an unimplemented stub upstream, so it is not called.) */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#define ID3TAG_IMPLEMENTATION
#include "../../id3tag.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size >= 10) (void)id3tag_size(data);
    id3tag_t *tag = id3tag_load(data, size, ID3TAG_ALL_FIELDS, NULL);
    if (tag) id3tag_free(tag);
    if (size >= 128) {
        id3tag_t *v1 = id3tag_load_id3v1(data + size - 128, 128, NULL);
        if (v1) id3tag_free(v1);
    }
    return 0;
}
