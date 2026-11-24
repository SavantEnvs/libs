/* ini.h: ini_load -> section/property walk -> ini_find_section/ini_find_property -> ini_save -> reload. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define INI_IMPLEMENTATION
#include "../../ini.h"

static void walk(ini_t *ini, const char *probe, int probe_len) {
    int sc = ini_section_count(ini);
    for (int s = 0; s < sc; s++) {
        const char *sn = ini_section_name(ini, s);
        if (sn) { (void)ini_find_section(ini, sn, 0); (void)ini_find_section(ini, sn, (int)strlen(sn)); }
        int pc = ini_property_count(ini, s);
        for (int p = 0; p < pc; p++) {
            const char *pn = ini_property_name(ini, s, p);
            const char *pv = ini_property_value(ini, s, p);
            if (pn) { (void)ini_find_property(ini, s, pn, 0); (void)ini_find_property(ini, s, pn, (int)strlen(pn)); }
            if (pv) (void)ini_find_property(ini, s, pv, 0);
        }
        /* names that may not exist, explicit length and the strlen (0) path */
        (void)ini_find_property(ini, s, probe, probe_len);
        (void)ini_find_property(ini, s, probe, 0);
        (void)ini_find_property(ini, s, "", 0);
    }
    (void)ini_find_section(ini, probe, probe_len);
    (void)ini_find_section(ini, probe, 0);
    (void)ini_find_property(ini, INI_GLOBAL_SECTION, probe, 0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = 0;
    /* probe name: the first line of the input */
    int probe_len = 0;
    while (probe_len < (int)size && probe_len < 64 && buf[probe_len] && buf[probe_len] != '\n') probe_len++;
    char probe[65];
    memcpy(probe, buf, probe_len);
    probe[probe_len] = 0;

    ini_t *ini = ini_load(buf, NULL);
    if (ini) {
        walk(ini, probe, probe_len);
        int need = ini_save(ini, NULL, 0);
        if (need > 0) {
            char *out = (char *)malloc(need);
            if (out) {
                ini_save(ini, out, need);
                ini_t *again = ini_load(out, NULL);
                if (again) { walk(again, probe, probe_len); ini_destroy(again); }
                free(out);
            }
        }
        ini_destroy(ini);
    }
    free(buf);
    return 0;
}
