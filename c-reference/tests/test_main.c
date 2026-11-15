/* HPSP reference implementation - unit tests.
 * The test data in spec_data.h is generated from the specification itself,
 * so these tests check the code against the document, not against itself. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/hpsp_cbor.h"
#include "../src/hpsp_sha256.h"
#include "../src/hpsp_grant.h"
#include "../src/hpsp_device.h"
#include "spec_data.h"

static int fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* p256-m needs a random source for signing; verification does not use it. */
int p256_generate_random(uint8_t *out, unsigned n) { for (unsigned i = 0; i < n; i++) out[i] = (uint8_t)rand(); return 0; }

static void hex(const uint8_t *b, size_t n, char *out) { for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]); }

/* ---------------- SHA-256 ---------------- */
static void test_sha256(void)
{
    uint8_t h[32]; char s[65];
    hpsp_sha256((const uint8_t *)"abc", 3, h); hex(h, 32, s);
    CHECK(!strcmp(s, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256(abc) %s", s);
    hpsp_sha256((const uint8_t *)"", 0, h); hex(h, 32, s);
    CHECK(!strcmp(s, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "sha256('') %s", s);
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    hpsp_sha256((const uint8_t *)m, strlen(m), h); hex(h, 32, s);
    CHECK(!strcmp(s, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), "sha256(448-bit) %s", s);
    hpsp_sha256(V_INPUT, sizeof V_INPUT, h);
    CHECK(!memcmp(h, V_INPUTSHA256, 32), "sha256 of the spec's grant signing input");
}

/* ---------------- grant ---------------- */
static hpsp_grant_state fresh(uint64_t stored_block, int recovery)
{
    hpsp_grant_state st; memset(&st, 0, sizeof st);
    memcpy(st.signers[0].id, V_SIGNER, 32); memcpy(st.signers[0].pub, V_PUB, 64);
    st.signers[0].in_use = 1; st.signers[0].recovery_only = recovery;
    hpsp_grant_boot(&st, stored_block);
    return st;
}

static int check_vec(hpsp_grant_state *st, const uint8_t *nonce, const uint8_t *sig, uint64_t now_s)
{
    hpsp_grant g = { V_SIGNER, 32, V_COUNTER, V_EXPIRES, sig, 64 }; int nv;
    return hpsp_grant_check(st, &g, V_UUID, nonce, V_CID, 1, 0, V_DURATION, now_s, &nv);
}

static void test_grant(void)
{
    uint8_t in[HPSP_GRANT_INPUT_LEN];
    hpsp_grant_input(in, V_UUID, V_NONCE, V_COUNTER, V_CID, 1, 0, V_DURATION, V_EXPIRES);
    CHECK(sizeof V_INPUT == HPSP_GRANT_INPUT_LEN && !memcmp(in, V_INPUT, sizeof in), "signing input matches Annex E");

    hpsp_grant_state st = fresh(0, 0);
    CHECK(check_vec(&st, V_NONCE, V_SIG, 0) == GRANT_OK, "spec grant vector verifies (no valid time)");
    CHECK(check_vec(&st, V_NONCE, V_SIG, 0) == GRANT_REPLAY, "same grant again is a replay");

    st = fresh(0, 0);
    CHECK(check_vec(&st, V_NONCE, V_SIG, V_EXPIRES + 5) == GRANT_OK, "accepted within 5 s clock allowance");
    st = fresh(0, 0);
    CHECK(check_vec(&st, V_NONCE, V_SIG, V_EXPIRES + 6) == GRANT_EXPIRED, "expired grant refused");

    uint8_t nonce2[32]; memcpy(nonce2, V_NONCE, 32); nonce2[0] ^= 1;
    st = fresh(0, 0);
    CHECK(check_vec(&st, nonce2, V_SIG, 0) == GRANT_BAD_SIGNATURE, "grant for another session refused");

    uint8_t sig2[64]; memcpy(sig2, V_SIG, 64); sig2[63] ^= 1;
    st = fresh(0, 0);
    CHECK(check_vec(&st, V_NONCE, sig2, 0) == GRANT_BAD_SIGNATURE, "altered signature refused");

    st = fresh(0, 0); st.signers[0].id[0] ^= 1;
    CHECK(check_vec(&st, V_NONCE, V_SIG, 0) == GRANT_UNAUTHORIZED, "unknown signer refused");

    st = fresh(0, 1);
    CHECK(check_vec(&st, V_NONCE, V_SIG, 0) == GRANT_UNAUTHORIZED, "recovery-only signer cannot sign an unlock");

    st = fresh(1024, 0);   /* after a reboot with block 1024 reserved, the floor is 1088 */
    CHECK(st.floor == 1088 && check_vec(&st, V_NONCE, V_SIG, 0) == GRANT_REPLAY, "counter below the boot floor refused");

    /* wrong direction parameter changes the input, so the signature fails */
    st = fresh(0, 0);
    hpsp_grant g = { V_SIGNER, 32, V_COUNTER, V_EXPIRES, V_SIG, 64 }; int nv;
    CHECK(hpsp_grant_check(&st, &g, V_UUID, V_NONCE, V_CID, 1, 1, V_DURATION, 0, &nv) == GRANT_BAD_SIGNATURE, "parameter byte is covered by the signature");
}

/* ---------------- CBOR ---------------- */
static void test_cbor_examples(void)
{
    size_t off = 0, n = 0, ok = 0;
    while (off + 2 <= sizeof EXAMPLES) {
        size_t L = (size_t)EXAMPLES[off] << 8 | EXAMPLES[off + 1];
        const uint8_t *m = EXAMPLES + off + 2;
        int r = cbor_validate_message(m, L);
        cbor_item it = { m, L }, t;
        int has_type = !cbor_map_get(it, "type", &t);
        if (r == 0 && has_type) ok++;
        else printf("  example %zu (%s) rejected: %d\n", n, EXAMPLE_NAMES[n], r);
        off += 2 + L; n++;
    }
    CHECK(n == N_EXAMPLES && ok == n, "all %zu spec examples pass the CBOR profile (%zu ok)", n, ok);
}

static void test_cbor_negative(void)
{
    struct { const char *name; uint8_t b[40]; size_t n; } bad[] = {
        { "trailing byte", { 0xa1, 0x61, 'a', 0x01, 0x00 }, 5 },
        { "indefinite map", { 0xbf, 0x61, 'a', 0x01, 0xff }, 5 },
        { "tag", { 0xa1, 0x61, 'a', 0xc1, 0x01 }, 5 },
        { "null", { 0xa1, 0x61, 'a', 0xf6 }, 4 },
        { "undefined", { 0xa1, 0x61, 'a', 0xf7 }, 4 },
        { "duplicate key", { 0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02 }, 7 },
        { "integer key", { 0xa1, 0x01, 0x01 }, 3 },
        { "not a map", { 0x81, 0x01 }, 2 },
        { "truncated text", { 0xa1, 0x61, 'a', 0x65, 'x' }, 5 },
        { "bad utf-8", { 0xa1, 0x61, 'a', 0x62, 0xc3, 0x28 }, 6 },
        { "overlong utf-8", { 0xa1, 0x61, 'a', 0x62, 0xc0, 0x80 }, 6 },
        { "reserved additional info", { 0xa1, 0x61, 'a', 0x1c }, 4 },
        { "length larger than message", { 0xa1, 0x61, 'a', 0x5a, 0xff, 0xff, 0xff, 0xff }, 8 },
        { "too deep", { 0xa1, 0x61, 'a', 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01 }, 10 },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(cbor_validate_message(bad[i].b, bad[i].n) != 0, "rejects %s", bad[i].name);
    uint8_t big[200]; size_t k = 0; big[k++] = 0xb8; big[k++] = 25;          /* 25 members */
    for (int i = 0; i < 25; i++) { big[k++] = 0x62; big[k++] = (uint8_t)('a' + i / 26); big[k++] = (uint8_t)('a' + i % 26); big[k++] = 0x00; }
    CHECK(cbor_validate_message(big, k) != 0, "rejects a map with 25 members");
    big[1] = 24; k -= 4;
    CHECK(cbor_validate_message(big, k) == 0, "accepts a map with 24 members");
}

/* ---------------- device, end to end, with a fake port ---------------- */
typedef struct { uint8_t out[16384]; size_t out_len; int closed; uint64_t t; int forced_nonce; uint64_t nv[3]; int out_state[8]; } fake;
static int f_send(void *c, const uint8_t *b, size_t n) { fake *f = c; if (f->out_len + n > sizeof f->out) return -1; memcpy(f->out + f->out_len, b, n); f->out_len += n; return 0; }
static void f_close(void *c) { ((fake *)c)->closed = 1; }
static uint64_t f_now(void *c) { return ((fake *)c)->t; }
static int f_rand(void *c, uint8_t *b, size_t n) { fake *f = c; if (f->forced_nonce && n == 32) memcpy(b, V_NONCE, 32); else for (size_t i = 0; i < n; i++) b[i] = (uint8_t)rand(); return 0; }
static int f_nv(void *c, int k, uint64_t v) { ((fake *)c)->nv[k] = v; return 0; }
static void f_out(void *c, uint16_t cid, int on) { ((fake *)c)->out_state[cid & 7] = on; }
static const hpsp_port FP = { f_send, f_close, f_now, f_rand, f_nv, f_out, NULL };

/* Find the n-th frame sent with the given type and op; returns 0 if found. */
static int find_frame(fake *f, size_t from, const char *type, const char *op, cbor_item *out, size_t *next)
{
    size_t off = from;
    while (off + 4 <= f->out_len) {
        size_t L = (size_t)f->out[off] << 24 | (size_t)f->out[off + 1] << 16 | (size_t)f->out[off + 2] << 8 | f->out[off + 3];
        cbor_item m = { f->out + off + 4, L }, t, o;
        off += 4 + L;
        if (cbor_validate_message(m.p, m.len)) continue;
        if (!cbor_map_get(m, "type", &t) && cbor_text_eq(t, type) && (!op || (!cbor_map_get(m, "op", &o) && cbor_text_eq(o, op)))) {
            *out = m; if (next) *next = off; return 0;
        }
    }
    return -1;
}

static void setup(hpsp_device *d, fake *f)
{
    memset(f, 0, sizeof *f); f->t = 1000; f->forced_nonce = 1;
    hpsp_config c; memset(&c, 0, sizeof c);
    memcpy(c.uuid, V_UUID, 16); strcpy(c.uuid_str, V_DEVICE_ID);
    c.manufacturer = "Acme Ultimate Hardware Co"; c.product = "Door Defender 3000"; c.hw_rev = "B";
    c.fw_version = "0.5.0-ref"; c.serial = "REF-0001"; c.phy = "hpsp-e"; c.caps_id = "5e0a11c3";
    c.reader_cid = 0; c.lock_cids[0] = 2; c.n_lock_cids = 1; c.trust_epoch = 12;
    hpsp_device_init(d, &c, &FP, f);
    memcpy(d->grants.signers[0].id, V_SIGNER, 32); memcpy(d->grants.signers[0].pub, V_PUB, 64); d->grants.signers[0].in_use = 1;
}

static void test_device(void)
{
    static hpsp_device d; static fake f; cbor_item m, x, y; size_t nx;
    setup(&d, &f);
    hpsp_device_on_connect(&d);
    CHECK(!find_frame(&f, 0, "cmd", "hello", &m, NULL), "device sends hello on connect");
    if (!cbor_map_get(m, "data", &x) && !cbor_map_get(x, "session_nonce_b64", &y)) {
        const uint8_t *p; size_t n; cbor_get_bytes(y, &p, &n);
        CHECK(n == 32 && !memcmp(p, V_NONCE, 32), "hello carries the session value");
    }
    /* feed the specification's own hello response and unlock command */
    size_t mark = f.out_len;
    hpsp_device_process(&d, EX_HELLO_RSP, sizeof EX_HELLO_RSP);
    CHECK(d.hello_done && d.time_valid, "spec hello response accepted, time set");
    CHECK(d.ev_count == 0, "events below the controller's resume_from (1141 in the spec example) are released");
    mark = f.out_len;
    hpsp_device_process(&d, EX_UNLOCK, sizeof EX_UNLOCK);
    int got = !find_frame(&f, mark, "rsp", "unlock", &m, NULL);
    CHECK(got, "the spec's unlock example (with its real grant) is accepted");
    if (got) { CHECK(!cbor_map_get(m, "data", &x) && !cbor_map_get(x, "state", &y) && cbor_text_eq(y, "unlocked"), "state is unlocked"); }
    CHECK(f.out_state[2] == 1, "strike output released");
    CHECK(!find_frame(&f, mark, "evt", "lock_state", &m, NULL), "lock_state event for the release");
    mark = f.out_len;
    hpsp_device_process(&d, EX_UNLOCK, sizeof EX_UNLOCK);
    CHECK(!find_frame(&f, mark, "err", "unlock", &m, NULL) && !cbor_map_get(m, "data", &x) && !cbor_map_get(x, "code", &y) && cbor_text_eq(y, "replay"),
          "replaying the same unlock gives err replay");
    mark = f.out_len;
    f.t += 5000; hpsp_device_tick(&d);
    CHECK(f.out_state[2] == 0, "strike re-secured after 5 s");
    CHECK(!find_frame(&f, mark, "evt", "lock_state", &m, &nx) && !cbor_map_get(m, "data", &x) && !cbor_map_get(x, "cause", &y) && cbor_text_eq(y, "timeout"),
          "lock_state with cause timeout");

    /* fragments: a get_caps command sent in three pieces */
    uint8_t cmd[64]; cbor_wr w; cbor_wr_init(&w, cmd, sizeof cmd);
    cbor_put_map(&w, 3); cbor_put_text(&w, "id"); cbor_put_uint(&w, 50); cbor_put_text(&w, "op"); cbor_put_text(&w, "get_caps"); cbor_put_text(&w, "type"); cbor_put_text(&w, "cmd");
    size_t L = w.len, cut[4] = { 0, 5, 11, L };
    mark = f.out_len;
    for (int i = 0; i < 3; i++) {
        uint8_t fr[96]; cbor_wr fw; cbor_wr_init(&fw, fr, sizeof fr);
        cbor_put_map(&fw, 2); cbor_put_text(&fw, "data"); cbor_put_map(&fw, 4);
        cbor_put_text(&fw, "fid"); cbor_put_uint(&fw, 7);
        cbor_put_text(&fw, "total"); cbor_put_uint(&fw, L);
        cbor_put_text(&fw, "offset"); cbor_put_uint(&fw, cut[i]);
        cbor_put_text(&fw, "data_b64"); cbor_put_bytes(&fw, cmd + cut[i], cut[i + 1] - cut[i]);
        cbor_put_text(&fw, "type"); cbor_put_text(&fw, "frag");
        hpsp_device_process(&d, fr, fw.len);
    }
    CHECK(!find_frame(&f, mark, "rsp", "get_caps", &m, NULL), "a command split into fragments is joined and answered");

    /* a fragment set larger than max_assembled is refused */
    uint8_t fr[64]; cbor_wr_init(&w, fr, sizeof fr);
    cbor_put_map(&w, 2); cbor_put_text(&w, "data"); cbor_put_map(&w, 4);
    cbor_put_text(&w, "fid"); cbor_put_uint(&w, 8); cbor_put_text(&w, "total"); cbor_put_uint(&w, 100000);
    cbor_put_text(&w, "offset"); cbor_put_uint(&w, 0); cbor_put_text(&w, "data_b64"); cbor_put_bytes(&w, (const uint8_t *)"xx", 2);
    cbor_put_text(&w, "type"); cbor_put_text(&w, "frag");
    mark = f.out_len; hpsp_device_process(&d, fr, w.len);
    CHECK(!find_frame(&f, mark, "err", "frag", &m, NULL), "oversized fragment set refused");

    /* events are kept until acknowledged and replayed in a new session */
    size_t before = d.ev_count;
    CHECK(before == 2, "unacknowledged events retained (%zu)", before);
    uint8_t ack[32]; cbor_wr_init(&w, ack, sizeof ack);
    cbor_put_map(&w, 2); cbor_put_text(&w, "data"); cbor_put_map(&w, 1); cbor_put_text(&w, "seq"); cbor_put_uint(&w, d.ev[0].seq);
    cbor_put_text(&w, "type"); cbor_put_text(&w, "ack");
    hpsp_device_process(&d, ack, w.len);
    CHECK(d.ev_count == before - 1, "ack releases acknowledged events");

    /* heartbeats: three missed answers end the session */
    mark = f.out_len;
    for (int i = 0; i < 4; i++) { f.t += 10000; hpsp_device_tick(&d); }
    CHECK(!find_frame(&f, mark, "cmd", "heartbeat", &m, NULL) && !cbor_map_get(m, "data", &x) && !cbor_map_get(x, "mono_now", &y), "heartbeat carries mono_now");
    CHECK(f.closed && !d.up, "session closed after three missed heartbeats");

    /* a new session has a new session value, so the old grant is useless */
    f.forced_nonce = 0; f.closed = 0; mark = f.out_len;
    hpsp_device_on_connect(&d);
    hpsp_device_process(&d, EX_HELLO_RSP, sizeof EX_HELLO_RSP);
    CHECK(!memcmp(d.nonce, V_NONCE, 32) == 0, "new session value");
    mark = f.out_len;
    hpsp_device_process(&d, EX_UNLOCK, sizeof EX_UNLOCK);
    CHECK(!find_frame(&f, mark, "err", "unlock", &m, NULL), "old grant refused in a new session");

    /* invalid input closes the session */
    uint8_t junk[] = { 0xa1, 0x61, 'a', 0xf6 };
    f.closed = 0; hpsp_device_process(&d, junk, sizeof junk);
    CHECK(f.closed, "a message outside the CBOR profile closes the session");
}

/* ---------------- robustness: mutated inputs under the sanitizers ---------------- */
static void test_mutations(unsigned iters)
{
    static hpsp_device d; static fake f;
    uint8_t buf[2048];
    srand(12345);
    for (unsigned i = 0; i < iters; i++) {
        if (i % 500 == 0) { setup(&d, &f); hpsp_device_on_connect(&d); hpsp_device_process(&d, EX_HELLO_RSP, sizeof EX_HELLO_RSP); f.out_len = 0; }
        /* pick an example and mutate it */
        size_t off = 0, pick = (size_t)rand() % N_EXAMPLES, L = 0;
        for (size_t k = 0; ; k++) { L = (size_t)EXAMPLES[off] << 8 | EXAMPLES[off + 1]; if (k == pick) break; off += 2 + L; }
        if (L > sizeof buf) continue;
        memcpy(buf, EXAMPLES + off + 2, L);
        int muts = 1 + rand() % 4;
        for (int k = 0; k < muts; k++) {
            int kind = rand() % 4; size_t p = L ? (size_t)rand() % L : 0;
            if (kind == 0 && L) buf[p] ^= (uint8_t)(1 << (rand() % 8));
            else if (kind == 1 && L) buf[p] = (uint8_t)rand();
            else if (kind == 2 && L > 1) L = 1 + (size_t)rand() % (L - 1);
            else if (kind == 3 && L + 1 < sizeof buf) { memmove(buf + p + 1, buf + p, L - p); buf[p] = (uint8_t)rand(); L++; }
        }
        cbor_validate_message(buf, L);
        f.closed = 0; d.up = 1; d.hello_done = 1;
        hpsp_device_process(&d, buf, L);
        hpsp_device_on_bytes(&d, buf, L);
        if (f.out_len > 8000) f.out_len = 0;
    }
    CHECK(1, "mutation run completed");
    printf("  %u mutated messages processed\n", iters);
}

int main(int argc, char **argv)
{
    unsigned iters = argc > 1 ? (unsigned)atoi(argv[1]) : 200000;
    test_sha256();
    test_grant();
    test_cbor_examples();
    test_cbor_negative();
    test_device();
    test_mutations(iters);
    printf("%d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
