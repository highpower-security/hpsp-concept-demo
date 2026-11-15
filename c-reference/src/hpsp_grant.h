/* HPSP reference implementation - unlock grant check (spec section "Signed unlock grants").
 * Signing input v2: 84 bytes
 *   0  12  "HPSP2-GRANT\0"
 *  12  16  device UUID (binary)
 *  28  32  session value sent in this session's hello
 *  60   8  counter, big-endian
 *  68   2  cid, big-endian (0xFFFF for whole-device actions)
 *  70   1  action code
 *  71   1  parameter (direction for action 3, otherwise 0)
 *  72   4  duration_ms, big-endian
 *  76   8  expires, seconds since 1970, big-endian */
#ifndef HPSP_GRANT_H
#define HPSP_GRANT_H
#include <stddef.h>
#include <stdint.h>

#define HPSP_GRANT_INPUT_LEN 84
#define HPSP_MAX_SIGNERS 4
#define HPSP_MAX_RECOVERY 2
#define HPSP_COUNTER_BLOCK 64u

enum { GRANT_OK = 0, GRANT_FORBIDDEN, GRANT_UNAUTHORIZED, GRANT_REPLAY, GRANT_EXPIRED,
       GRANT_BAD_SIGNATURE, GRANT_BAD_REQUEST };

typedef struct {
    uint8_t id[32];          /* SHA-256 of the signer's SubjectPublicKeyInfo */
    uint8_t pub[64];         /* public key, x || y */
    int recovery_only;       /* may sign only actions 4 and 5 */
    int in_use;
} hpsp_signer;

typedef struct {
    hpsp_signer signers[HPSP_MAX_SIGNERS + HPSP_MAX_RECOVERY];
    uint64_t last_counter;   /* highest counter accepted since start (RAM) */
    uint64_t floor;          /* grant_floor reported in hello */
    uint64_t reserved_block; /* start of the counter block recorded in non-volatile memory */
} hpsp_grant_state;

typedef struct {
    const uint8_t *signer_id; size_t signer_id_len;  /* 32 bytes on the wire (signer_hex) */
    uint64_t counter;
    uint64_t expires;
    const uint8_t *sig; size_t sig_len;              /* 64 bytes (sig_b64) */
} hpsp_grant;

/* Build the 84-byte signing input. */
void hpsp_grant_input(uint8_t out[HPSP_GRANT_INPUT_LEN], const uint8_t uuid[16], const uint8_t nonce[32],
                      uint64_t counter, uint16_t cid, uint8_t action, uint8_t param,
                      uint32_t duration_ms, uint64_t expires);

/* Run the checks of the spec in order (session check is the caller's).
 * now_s is the current time in seconds, or 0 if the device has no valid time.
 * On GRANT_OK the counter is recorded; *nv_write is set to 1 when the caller
 * must persist hpsp_grant_state.reserved_block before acting. */
int hpsp_grant_check(hpsp_grant_state *st, const hpsp_grant *g, const uint8_t uuid[16], const uint8_t nonce[32],
                     uint16_t cid, uint8_t action, uint8_t param, uint32_t duration_ms,
                     uint64_t now_s, int *nv_write);

/* At start-up: set the floor from the stored block. */
void hpsp_grant_boot(hpsp_grant_state *st, uint64_t stored_block);

#endif
