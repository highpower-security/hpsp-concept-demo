/* HPSP reference implementation - unlock grant check. See hpsp_grant.h. */
#include "hpsp_grant.h"
#include "hpsp_sha256.h"
#include "../third_party/p256-m/p256-m.h"
#include <string.h>

#define CLOCK_SKEW_S 5   /* a device MAY accept a grant up to 5 s past its expiry */

static void be(uint8_t *p, uint64_t v, int n) { for (int i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * (n - 1 - i))); }

void hpsp_grant_input(uint8_t out[HPSP_GRANT_INPUT_LEN], const uint8_t uuid[16], const uint8_t nonce[32],
                      uint64_t counter, uint16_t cid, uint8_t action, uint8_t param,
                      uint32_t duration_ms, uint64_t expires)
{
    memcpy(out, "HPSP2-GRANT\0", 12);
    memcpy(out + 12, uuid, 16);
    memcpy(out + 28, nonce, 32);
    be(out + 60, counter, 8);
    be(out + 68, cid, 2);
    out[70] = action;
    out[71] = param;
    be(out + 72, duration_ms, 4);
    be(out + 76, expires, 8);
}

void hpsp_grant_boot(hpsp_grant_state *st, uint64_t stored_block)
{
    st->reserved_block = stored_block;
    st->floor = stored_block + HPSP_COUNTER_BLOCK;   /* nothing below this can be fresh */
    st->last_counter = 0;
}

int hpsp_grant_check(hpsp_grant_state *st, const hpsp_grant *g, const uint8_t uuid[16], const uint8_t nonce[32],
                     uint16_t cid, uint8_t action, uint8_t param, uint32_t duration_ms,
                     uint64_t now_s, int *nv_write)
{
    *nv_write = 0;
    if (g->signer_id_len != 32 || g->sig_len != 64) return GRANT_BAD_REQUEST;

    /* 2. signer lookup (identifiers are public, so a plain search is fine) */
    const hpsp_signer *s = NULL;
    for (size_t i = 0; i < sizeof st->signers / sizeof st->signers[0]; i++)
        if (st->signers[i].in_use && memcmp(st->signers[i].id, g->signer_id, 32) == 0) { s = &st->signers[i]; break; }
    if (!s) return GRANT_UNAUTHORIZED;
    if (s->recovery_only && action != 4 && action != 5) return GRANT_UNAUTHORIZED;

    /* 3. counter: strictly above anything accepted, and not below the boot floor */
    if (g->counter <= st->last_counter || g->counter < st->floor) return GRANT_REPLAY;

    /* 4. expiry, only when the device holds valid time */
    if (now_s != 0 && now_s > g->expires + CLOCK_SKEW_S) return GRANT_EXPIRED;

    /* 5. rebuild the signing input from our own identity and session value, then verify */
    uint8_t in[HPSP_GRANT_INPUT_LEN], hash[32];
    hpsp_grant_input(in, uuid, nonce, g->counter, cid, action, param, duration_ms, g->expires);
    hpsp_sha256(in, sizeof in, hash);
    if (p256_ecdsa_verify(g->sig, s->pub, hash, sizeof hash) != P256_SUCCESS) return GRANT_BAD_SIGNATURE;

    /* 6. record the counter; reserve a new block in non-volatile memory when crossing one */
    st->last_counter = g->counter;
    uint64_t block = g->counter - (g->counter % HPSP_COUNTER_BLOCK);
    if (block > st->reserved_block || st->reserved_block == 0) { st->reserved_block = block; *nv_write = 1; }
    return GRANT_OK;
}
