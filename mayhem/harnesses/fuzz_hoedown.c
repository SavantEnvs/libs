/* hoedown.h: markdown -> HTML with every extension. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define HOEDOWN_IMPLEMENTATION
#include "../../hoedown.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned exts = HOEDOWN_EXT_BLOCK | HOEDOWN_EXT_SPAN | HOEDOWN_EXT_FLAGS;
    hoedown_renderer *r = hoedown_html_renderer_new(HOEDOWN_HTML_USE_XHTML, 0);
    hoedown_document *doc = hoedown_document_new(r, (hoedown_extensions)exts, 16);
    hoedown_buffer *ob = hoedown_buffer_new(64);
    hoedown_document_render(doc, ob, data, size);
    hoedown_buffer_free(ob);
    hoedown_document_free(doc);
    hoedown_html_renderer_free(r);

    r = hoedown_html_toc_renderer_new(4);
    doc = hoedown_document_new(r, (hoedown_extensions)exts, 16);
    ob = hoedown_buffer_new(64);
    hoedown_document_render(doc, ob, data, size);
    hoedown_buffer_free(ob);
    hoedown_document_free(doc);
    hoedown_html_renderer_free(r);
    return 0;
}
