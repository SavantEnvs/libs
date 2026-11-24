/* speech.h: text -> phonemes -> formant synthesis. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define SPEECH_IMPLEMENTATION
#include "../../speech.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 256) return -1; /* synthesis cost is linear in text length; keep execs fast */
    char *s = (char *)malloc(size + 1);
    memcpy(s, data, size); s[size] = 0;
    int n = 0;
    short *pcm = speech_gen(&n, s, NULL);
    if (pcm) speech_free(pcm, NULL);
    free(s);
    return 0;
}
