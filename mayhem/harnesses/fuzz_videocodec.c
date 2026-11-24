/* videocodec.h: decoder. Input = 96-byte stream header followed by the frame stream, fed the way the
   bundled player does it: ask the decoder how many bytes the next frame needs, hand it that many. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define VIDEOCODEC_IMPLEMENTATION
#include "../../videocodec.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < VIDEOCODEC_DEC_HEADER_SIZE) return -1;
    uint8_t hdr[VIDEOCODEC_DEC_HEADER_SIZE];
    memcpy(hdr, data, sizeof hdr); /* aligned copy: the decoder reads the header as int32s */
    videocodec_dec_t *dec = videocodec_dec_create(hdr);
    if (!dec) return 0;
    int w = videocodec_dec_width(dec), h = videocodec_dec_height(dec);
    /* The caller allocates out_xbgr as width*height pixels (API docs for videocodec_dec_next_frame);
       a non-positive or huge size cannot be allocated by any caller. */
    if (w <= 0 || h <= 0 || (int64_t)w * h > (1 << 20)) { videocodec_dec_destroy(dec); return -1; }
    uint32_t *out = (uint32_t *)malloc((size_t)w * h * sizeof(uint32_t));
    size_t pos = VIDEOCODEC_DEC_HEADER_SIZE;
    for (int frames = 0; out && frames < 64; frames++) {
        size_t need = videocodec_dec_next_frame(dec, NULL, 0, NULL);
        if (need == 0 || need > size - pos) break;
        uint8_t *chunk = (uint8_t *)malloc(need);
        if (!chunk) break;
        memcpy(chunk, data + pos, need);
        size_t next = videocodec_dec_next_frame(dec, chunk, need, out);
        free(chunk);
        pos += need;
        if (next == 0) break;
    }
    free(out);
    videocodec_dec_destroy(dec);
    return 0;
}
