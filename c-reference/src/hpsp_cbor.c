/* HPSP reference implementation - CBOR reader and writer. See hpsp_cbor.h. */
#include "hpsp_cbor.h"
#include <string.h>

/* Read one item head. Returns bytes consumed, or 0 on error.
 * Rejects indefinite lengths, reserved additional info, tags and
 * simple values other than false/true and the three float sizes. */
static size_t head(const uint8_t *p, size_t avail, int *major, uint64_t *val, int *ai_out)
{
    if (avail < 1) return 0;
    int mj = p[0] >> 5, ai = p[0] & 0x1f;
    size_t n = 1; uint64_t v;
    if (ai < 24) v = (uint64_t)ai;
    else if (ai <= 27) {
        size_t k = (size_t)1 << (ai - 24);
        if (avail < 1 + k) return 0;
        v = 0;
        for (size_t i = 0; i < k; i++) v = (v << 8) | p[1 + i];
        n += k;
    } else return 0;                     /* 28..30 reserved, 31 indefinite */
    if (mj == CBOR_TAG) return 0;        /* tags are not used */
    if (mj == CBOR_SIMPLE) {
        if (ai < 24) { if (v != 20 && v != 21) return 0; }  /* only false/true */
        else if (ai == 24) return 0;                         /* other simple values */
    }
    *major = mj; *val = v; if (ai_out) *ai_out = ai;
    return n;
}

static int utf8_ok(const uint8_t *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        if (c < 0x80) { i++; continue; }
        size_t k; uint32_t cp;
        if ((c & 0xe0) == 0xc0) { k = 1; cp = c & 0x1f; }
        else if ((c & 0xf0) == 0xe0) { k = 2; cp = c & 0x0f; }
        else if ((c & 0xf8) == 0xf0) { k = 3; cp = c & 0x07; }
        else return 0;
        if (i + k >= n) return 0;                 /* sequence runs past the end */
        for (size_t j = 1; j <= k; j++) {
            if ((s[i + j] & 0xc0) != 0x80) return 0;
            cp = (cp << 6) | (s[i + j] & 0x3f);
        }
        if ((k == 1 && cp < 0x80) || (k == 2 && cp < 0x800) || (k == 3 && cp < 0x10000)) return 0;
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
        i += k + 1;
    }
    return 1;
}

/* Validate the item at p; return its size or 0 if invalid. */
static size_t check(const uint8_t *p, size_t avail, int depth)
{
    int mj, ai; uint64_t v;
    size_t h = head(p, avail, &mj, &v, &ai);
    if (!h) return 0;
    switch (mj) {
    case CBOR_UINT: case CBOR_NINT:
        return h;
    case CBOR_BYTES: case CBOR_TEXT:
        if (v > avail - h) return 0;
        if (mj == CBOR_TEXT && (v > HPSP_CBOR_MAX_TEXT || !utf8_ok(p + h, (size_t)v))) return 0;
        return h + (size_t)v;
    case CBOR_SIMPLE:
        return h;                         /* false, true, or a float of 2, 4 or 8 bytes */
    case CBOR_ARRAY: case CBOR_MAP: {
        if (depth >= HPSP_CBOR_MAX_DEPTH) return 0;
        if (mj == CBOR_MAP && v > HPSP_CBOR_MAX_MEMBERS) return 0;
        if (v > avail) return 0;          /* each element needs at least one byte */
        size_t off = h;
        const uint8_t *keys[HPSP_CBOR_MAX_MEMBERS]; size_t klen[HPSP_CBOR_MAX_MEMBERS];
        for (uint64_t i = 0; i < v; i++) {
            if (mj == CBOR_MAP) {
                int kmj; uint64_t kv;
                size_t kh = head(p + off, avail - off, &kmj, &kv, NULL);
                if (!kh || kmj != CBOR_TEXT) return 0;          /* text keys only */
                size_t ks = check(p + off, avail - off, depth + 1);
                if (!ks) return 0;
                for (uint64_t j = 0; j < i; j++)                 /* no duplicate keys */
                    if (klen[j] == ks && memcmp(keys[j], p + off, ks) == 0) return 0;
                keys[i] = p + off; klen[i] = ks;
                off += ks;
            }
            size_t s = check(p + off, avail - off, depth + 1);
            if (!s) return 0;
            off += s;
        }
        return off;
    }
    default:
        return 0;
    }
}

int cbor_validate_message(const uint8_t *buf, size_t len)
{
    if (len < 1 || (buf[0] >> 5) != CBOR_MAP) return -1;
    size_t s = check(buf, len, 0);
    if (!s) return -2;
    if (s != len) return -3;              /* trailing bytes */
    return 0;
}

size_t cbor_item_size(const uint8_t *p, size_t avail) { return check(p, avail, 0); }

int cbor_map_get(cbor_item map, const char *key, cbor_item *val)
{
    int mj; uint64_t n;
    size_t h = head(map.p, map.len, &mj, &n, NULL);
    if (!h || mj != CBOR_MAP) return -1;
    size_t off = h, kl = strlen(key);
    for (uint64_t i = 0; i < n; i++) {
        int kmj; uint64_t klen;
        size_t kh = head(map.p + off, map.len - off, &kmj, &klen, NULL);
        if (!kh) return -1;
        size_t ks = kh + (size_t)klen;
        size_t vs = check(map.p + off + ks, map.len - off - ks, 1);
        if (!vs) return -1;
        if (kmj == CBOR_TEXT && klen == kl && memcmp(map.p + off + kh, key, kl) == 0) {
            val->p = map.p + off + ks; val->len = vs; return 0;
        }
        off += ks + vs;
    }
    return -1;
}

int cbor_get_uint(cbor_item it, uint64_t *out)
{
    int mj; uint64_t v;
    if (!head(it.p, it.len, &mj, &v, NULL) || mj != CBOR_UINT) return -1;
    *out = v; return 0;
}

int cbor_get_int(cbor_item it, int64_t *out)
{
    int mj; uint64_t v;
    if (!head(it.p, it.len, &mj, &v, NULL)) return -1;
    if (v > (uint64_t)INT64_MAX) return -1;
    if (mj == CBOR_UINT) { *out = (int64_t)v; return 0; }
    if (mj == CBOR_NINT) { *out = -1 - (int64_t)v; return 0; }
    return -1;
}

int cbor_get_bool(cbor_item it, int *out)
{
    if (it.len < 1) return -1;
    if (it.p[0] == 0xf4) { *out = 0; return 0; }
    if (it.p[0] == 0xf5) { *out = 1; return 0; }
    return -1;
}

static int get_str(cbor_item it, int want, const uint8_t **s, size_t *n)
{
    int mj; uint64_t v;
    size_t h = head(it.p, it.len, &mj, &v, NULL);
    if (!h || mj != want || v > it.len - h) return -1;
    *s = it.p + h; *n = (size_t)v; return 0;
}
int cbor_get_text(cbor_item it, const uint8_t **s, size_t *n) { return get_str(it, CBOR_TEXT, s, n); }
int cbor_get_bytes(cbor_item it, const uint8_t **s, size_t *n) { return get_str(it, CBOR_BYTES, s, n); }

int cbor_text_eq(cbor_item it, const char *s)
{
    const uint8_t *t; size_t n;
    if (cbor_get_text(it, &t, &n)) return 0;
    return n == strlen(s) && memcmp(t, s, n) == 0;
}

int cbor_array_len(cbor_item it, size_t *n)
{
    int mj; uint64_t v;
    if (!head(it.p, it.len, &mj, &v, NULL) || mj != CBOR_ARRAY) return -1;
    *n = (size_t)v; return 0;
}

int cbor_array_at(cbor_item it, size_t i, cbor_item *out)
{
    int mj; uint64_t v;
    size_t off = head(it.p, it.len, &mj, &v, NULL);
    if (!off || mj != CBOR_ARRAY || i >= v) return -1;
    for (size_t k = 0; k <= i; k++) {
        size_t s = check(it.p + off, it.len - off, 1);
        if (!s) return -1;
        if (k == i) { out->p = it.p + off; out->len = s; return 0; }
        off += s;
    }
    return -1;
}

/* ---------------- writer ---------------- */
void cbor_wr_init(cbor_wr *w, uint8_t *buf, size_t cap) { w->p = buf; w->cap = cap; w->len = 0; w->err = 0; }

static void put_head(cbor_wr *w, int mj, uint64_t v)
{
    uint8_t b[9]; size_t n;
    if (v < 24) { b[0] = (uint8_t)((mj << 5) | v); n = 1; }
    else if (v <= 0xff) { b[0] = (uint8_t)((mj << 5) | 24); b[1] = (uint8_t)v; n = 2; }
    else if (v <= 0xffff) { b[0] = (uint8_t)((mj << 5) | 25); b[1] = (uint8_t)(v >> 8); b[2] = (uint8_t)v; n = 3; }
    else if (v <= 0xffffffffu) { b[0] = (uint8_t)((mj << 5) | 26); for (int i = 0; i < 4; i++) b[1 + i] = (uint8_t)(v >> (24 - 8 * i)); n = 5; }
    else { b[0] = (uint8_t)((mj << 5) | 27); for (int i = 0; i < 8; i++) b[1 + i] = (uint8_t)(v >> (56 - 8 * i)); n = 9; }
    cbor_put_raw(w, b, n);
}
void cbor_put_raw(cbor_wr *w, const uint8_t *b, size_t n)
{
    if (w->err) return;
    if (n > w->cap - w->len) { w->err = 1; return; }
    memcpy(w->p + w->len, b, n); w->len += n;
}
void cbor_put_map(cbor_wr *w, size_t n) { put_head(w, CBOR_MAP, n); }
void cbor_put_array(cbor_wr *w, size_t n) { put_head(w, CBOR_ARRAY, n); }
void cbor_put_uint(cbor_wr *w, uint64_t v) { put_head(w, CBOR_UINT, v); }
void cbor_put_int(cbor_wr *w, int64_t v) { if (v >= 0) put_head(w, CBOR_UINT, (uint64_t)v); else put_head(w, CBOR_NINT, (uint64_t)(-1 - v)); }
void cbor_put_bool(cbor_wr *w, int v) { uint8_t b = v ? 0xf5 : 0xf4; cbor_put_raw(w, &b, 1); }
void cbor_put_textn(cbor_wr *w, const char *s, size_t n) { put_head(w, CBOR_TEXT, n); cbor_put_raw(w, (const uint8_t *)s, n); }
void cbor_put_text(cbor_wr *w, const char *s) { cbor_put_textn(w, s, strlen(s)); }
void cbor_put_bytes(cbor_wr *w, const uint8_t *b, size_t n) { put_head(w, CBOR_BYTES, n); cbor_put_raw(w, b, n); }
