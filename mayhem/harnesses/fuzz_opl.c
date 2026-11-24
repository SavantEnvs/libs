/* opl.h: OP2 (GENMIDI) instrument bank loader, then the MIDI interface + emulator driven by the
   bytes after the bank (3 bytes per event: kind, a, b). */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define OPL_IMPLEMENTATION
#include "../../opl.h"

#define OP2_SIZE (8 + 36 * 175 + 32 * 175)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (1 << 20)) return -1;
    opl_t *opl = opl_create();
    if (!opl) return 0;
    size_t bank = size < OP2_SIZE ? size : OP2_SIZE;
    void *copy = malloc(bank ? bank : 1);
    memcpy(copy, data, bank);
    int r = opl_loadbank_op2(opl, copy, (int)bank);
    free(copy);
    if (r == 0) {
        short samples[2 * 64];
        for (size_t i = bank; i + 3 <= size && i < bank + 3 * 256; i += 3) {
            int ch = data[i] & 15, a = data[i + 1] & 127, b = data[i + 2] & 127;
            switch ((data[i] >> 4) % 6) {
            case 0: opl_midi_noteon(opl, ch, a, b); break;
            case 1: opl_midi_noteoff(opl, ch, a); break;
            case 2: opl_midi_changeprog(opl, ch, a); break;
            case 3: opl_midi_controller(opl, ch, a, b); break;
            case 4: opl_midi_pitchwheel(opl, ch, (a << 7) | b); break;
            default: opl_render(opl, samples, 64, 1.0f); break;
            }
        }
        opl_render(opl, samples, 64, 1.0f);
    }
    opl_destroy(opl);
    return 0;
}
