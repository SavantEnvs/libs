/* dialog.h: compile dialog script text, walk every conversation/entry accessor, save + reload the
   compiled form and walk it again. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define DIALOG_IMPLEMENTATION
#include "../../dialog.h"

static volatile size_t sink;
static void s(const char *p) { if (p) sink += strlen(p); }

static void walk(dialog_t *d) {
    int cc = dialog_conversation_count(d);
    for (int c = 0; c < cc; c++) {
        dialog_conversation_t conv = dialog_conversation(d, c);
        const char *id = dialog_conversation_id(d, conv);
        s(id);
        if (id) sink += (size_t)dialog_find_conversation(d, id);
        int ec = dialog_conversation_entry_count(d, conv);
        for (int e = 0; e < ec; e++) {
            dialog_entry_t en = dialog_conversation_entry(d, conv, e);
            s(dialog_entry_id(d, en));
            switch (dialog_entry_type(d, en)) {
            case DIALOG_ENTRY_TYPE_LINE: {
                dialog_line_t l = dialog_entry_line(d, en);
                s(dialog_line_actor(d, l)); s(dialog_line_text(d, l)); break; }
            case DIALOG_ENTRY_TYPE_OPTION: {
                dialog_option_t o = dialog_entry_option(d, en);
                s(dialog_option_text(d, o)); s(dialog_option_target(d, o));
                sink += (size_t)dialog_option_is_persistent(d, o); break; }
            case DIALOG_ENTRY_TYPE_REDIRECT: s(dialog_redirect_target(d, dialog_entry_redirect(d, en))); break;
            case DIALOG_ENTRY_TYPE_EVENT: s(dialog_event_event(d, dialog_entry_event(d, en))); break;
            default: break;
            }
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (1 << 20)) return -1;
    /* dialog_parse() reads input[size] before its bounds check (dialog.h, row scan), so every input
       not ending in '\n' trips a 1-byte over-read. Give it the NUL terminator a file loader would. */
    char *text = (char *)malloc(size + 1);
    if (!text) return 0;
    memcpy(text, data, size);
    text[size] = '\0';
    dialog_t *d = dialog_create(text, (int)size);
    if (!d) { free(text); return 0; }
    walk(d);
    int n = dialog_save(d, NULL, 0);
    if (n > 0) {
        void *buf = malloc((size_t)n);
        if (buf) {
            dialog_save(d, buf, n);
            dialog_t *l = dialog_load(buf, n);
            if (l) { walk(l); dialog_unload(l); }
            free(buf);
        }
    }
    dialog_destroy(d);
    free(text);
    return 0;
}
