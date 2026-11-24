/* Known-answer tests for the headers the fuzz targets exercise. Prints one "PASS <name>" /
   "FAIL <name>" line per check and a final "SUMMARY passed=<p> failed=<f>" line. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define INI_IMPLEMENTATION
#include "../../ini.h"
#define LZMA_IMPLEMENTATION
#include "../../lzma.h"
#define PATHSTR_IMPLEMENTATION
#include "../../pathstr.h"
#define HOEDOWN_IMPLEMENTATION
#include "../../hoedown.h"

static int passed, failed;
static void check(const char *name, int ok) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) passed++; else failed++;
}
static int streq(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

static void test_ini(void) {
    const char *src = "top=1\n[first]\nname= hello world\nempty=\n;comment\n[second]\nk=v\n";
    ini_t *ini = ini_load(src, NULL);
    check("ini_load", ini != NULL);
    if (!ini) return;
    check("ini_section_count", ini_section_count(ini) == 3);
    int s = ini_find_section(ini, "first", 0);
    check("ini_find_section", s == 1);
    check("ini_find_section_missing", ini_find_section(ini, "nope", 0) == INI_NOT_FOUND);
    int p = ini_find_property(ini, s, "name", 0);
    check("ini_property_value", p >= 0 && streq(ini_property_value(ini, s, p), "hello world"));
    int e = ini_find_property(ini, s, "empty", 5);
    check("ini_empty_value", e >= 0 && streq(ini_property_value(ini, s, e), ""));
    check("ini_find_property_missing", ini_find_property(ini, s, "zzz", 0) == INI_NOT_FOUND);
    check("ini_find_property_empty_section", ini_find_property(ini, ini_find_section(ini, "second", 0), "name", 0) == INI_NOT_FOUND);
    check("ini_global", streq(ini_property_value(ini, INI_GLOBAL_SECTION, ini_find_property(ini, INI_GLOBAL_SECTION, "top", 0)), "1"));
    char out[256];
    int n = ini_save(ini, out, sizeof out);
    check("ini_save", n > 0 && strstr(out, "[second]\nk=v\n") != NULL && strstr(out, "name=hello world\n") != NULL);
    ini_destroy(ini);
}

static void test_lzma(void) {
    unsigned char src[2000], comp[4000], dec[2000], props[LZMA_PROPS_SIZE];
    for (int i = 0; i < 2000; i++) src[i] = (unsigned char)("libs lzma round trip "[i % 21]);
    size_t clen = sizeof comp, plen = LZMA_PROPS_SIZE;
    int r = LzmaCompress(comp, &clen, src, sizeof src, props, &plen, 5, 1 << 16, 3, 0, 2, 32, NULL, NULL);
    check("lzma_compress", r == SZ_OK && clen > 0 && clen < sizeof src);
    size_t dlen = sizeof dec, slen = clen;
    r = LzmaUncompress(dec, &dlen, comp, &slen, props, plen);
    check("lzma_roundtrip", r == SZ_OK && dlen == sizeof src && memcmp(dec, src, sizeof src) == 0);
}

static void test_pathstr(void) {
    char out[128];
    pathstr_normalize("a/b/../c/./d", out, sizeof out);
    check("pathstr_normalize", streq(out, "a/c/d"));
    pathstr_basename("/x/y/file.txt", out, sizeof out);
    check("pathstr_basename", streq(out, "file.txt"));
    pathstr_extname("/x/y/file.txt", out, sizeof out);
    check("pathstr_extname", streq(out, ".txt"));
    pathstr_join("dir", "file", out, sizeof out);
    check("pathstr_join", streq(out, "dir/file"));
    check("pathstr_wildcard", pathstr_wildcard_compare("*.txt", "a.txt", PATHSTR_CASE_SENSITIVE) &&
                              !pathstr_wildcard_compare("*.txt", "a.bin", PATHSTR_CASE_SENSITIVE));
}

static void test_hoedown(void) {
    const char *md = "# Title\n\nsome *emph* text\n";
    hoedown_renderer *r = hoedown_html_renderer_new(0, 0);
    hoedown_document *d = hoedown_document_new(r, 0, 16);
    hoedown_buffer *ob = hoedown_buffer_new(64);
    hoedown_document_render(d, ob, (const uint8_t *)md, strlen(md));
    const char *want = "<h1>Title</h1>\n\n<p>some <em>emph</em> text</p>\n";
    check("hoedown_render", ob->size == strlen(want) && memcmp(ob->data, want, ob->size) == 0);
    hoedown_buffer_free(ob); hoedown_document_free(d); hoedown_html_renderer_free(r);
}

int main(void) {
    test_ini(); test_lzma(); test_pathstr(); test_hoedown();
    printf("SUMMARY passed=%d failed=%d\n", passed, failed);
    return failed ? 1 : 0;
}
