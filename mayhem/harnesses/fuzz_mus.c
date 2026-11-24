/* mus.h: DMX MUS score parse + event decoding. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define MUS_IMPLEMENTATION
#include "../../mus.h"

/* KNOWN UPSTREAM BUG: mus_create() reads the 8-byte header (signature + two uint16 fields,
   mus.h:130-139) before it looks at `size`, so any input under 8 bytes is a heap over-read. mus.h
   documents no minimum size. Under halting ASan that one bug fires on nearly every short mutation
   and the target cannot fuzz at all (libFuzzer never gets past its first inputs), so the harness
   gives it the readable bytes a file loader would: the input is copied into a buffer of at least
   MUS_HEADER_READ bytes, zero-padded, and mus_create() still gets the real `size`. Every input,
   empty included, reaches mus_create(); none is rejected. */
#define MUS_HEADER_READ 8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t cap = size < MUS_HEADER_READ ? MUS_HEADER_READ : size;
    void *copy = calloc(1, cap);
    if (!copy) return 0;
    if (size) memcpy(copy, data, size);
    mus_t *mus = mus_create(copy, size, NULL);
    if (mus) {
        mus_event_t ev;
        for (int i = 0; i < 20000; i++) {
            mus_next_event(mus, &ev);
            if (ev.cmd == MUS_CMD_FINISH) break;
        }
        mus_destroy(mus);
    }
    free(copy);
    return 0;
}
