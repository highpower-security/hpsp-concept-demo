/* HPSP reference implementation - CBOR reader and writer for the HPSP profile.
 * Allocation-free. Reads from and writes to caller-owned buffers.
 * Profile (spec section "The CBOR profile"): definite lengths only, no tags,
 * no null/undefined, integers up to 64 bits, text map keys, depth <= 6,
 * <= 24 members per map, no duplicate keys, valid UTF-8 text. */
#ifndef HPSP_CBOR_H
#define HPSP_CBOR_H
#include <stddef.h>
#include <stdint.h>

#define HPSP_CBOR_MAX_DEPTH   6
#define HPSP_CBOR_MAX_MEMBERS 24
#define HPSP_CBOR_MAX_TEXT    255   /* 128 in general; 255 for endpoint host fields */

enum { CBOR_UINT = 0, CBOR_NINT = 1, CBOR_BYTES = 2, CBOR_TEXT = 3,
       CBOR_ARRAY = 4, CBOR_MAP = 5, CBOR_TAG = 6, CBOR_SIMPLE = 7 };

/* A view of one encoded item inside a buffer. */
typedef struct { const uint8_t *p; size_t len; } cbor_item;

/* Validate a whole message: exactly one map item that fills len bytes and obeys
 * the profile. Returns 0 if valid, a negative value otherwise. */
int cbor_validate_message(const uint8_t *buf, size_t len);

/* Size in bytes of the item at p (which must already be validated). */
size_t cbor_item_size(const uint8_t *p, size_t avail);

/* Look up a text key in a map item. Returns 0 and sets *val on success. */
int cbor_map_get(cbor_item map, const char *key, cbor_item *val);

int cbor_get_uint(cbor_item it, uint64_t *out);
int cbor_get_int(cbor_item it, int64_t *out);
int cbor_get_bool(cbor_item it, int *out);
int cbor_get_text(cbor_item it, const uint8_t **s, size_t *n);
int cbor_get_bytes(cbor_item it, const uint8_t **s, size_t *n);
int cbor_text_eq(cbor_item it, const char *s);
/* Array access: number of elements and the i-th element. */
int cbor_array_len(cbor_item it, size_t *n);
int cbor_array_at(cbor_item it, size_t i, cbor_item *out);

/* Writer. All functions are no-ops once w->err is set. */
typedef struct { uint8_t *p; size_t cap; size_t len; int err; } cbor_wr;
void cbor_wr_init(cbor_wr *w, uint8_t *buf, size_t cap);
void cbor_put_map(cbor_wr *w, size_t n);
void cbor_put_array(cbor_wr *w, size_t n);
void cbor_put_uint(cbor_wr *w, uint64_t v);
void cbor_put_int(cbor_wr *w, int64_t v);
void cbor_put_bool(cbor_wr *w, int v);
void cbor_put_text(cbor_wr *w, const char *s);
void cbor_put_textn(cbor_wr *w, const char *s, size_t n);
void cbor_put_bytes(cbor_wr *w, const uint8_t *b, size_t n);
void cbor_put_raw(cbor_wr *w, const uint8_t *b, size_t n);

#endif
