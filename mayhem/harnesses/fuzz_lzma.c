/* lzma.h: LzmaUncompress; the first 5 bytes are the LZMA properties, the rest the stream. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define LZMA_IMPLEMENTATION
#include "../../lzma.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < LZMA_PROPS_SIZE) return -1;
    size_t cap = 1u << 20;
    unsigned char *dest = (unsigned char *)malloc(cap);
    if (!dest) return 0;
    size_t destLen = cap;
    size_t srcLen = size - LZMA_PROPS_SIZE;
    LzmaUncompress(dest, &destLen, data + LZMA_PROPS_SIZE, &srcLen, data, LZMA_PROPS_SIZE);
    free(dest);
    return 0;
}
