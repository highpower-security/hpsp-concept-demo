/* HPSP reference implementation - device side of an HPSP session.
 *
 * This is the protocol core: framing, fragments, the envelope, reliable events,
 * heartbeats and the operations needed for a reader-and-strike device
 * (hello, heartbeat, unlock, lock, get_caps, goodbye, ack). It is written in
 * allocation-free C99 and talks to the outside world only through hpsp_port.
 *
 * TLS is NOT part of this file. The port's send/receive functions are expected
 * to be the plaintext side of a TLS 1.3 session (see README: transport). The
 * POSIX test port uses plain TCP on localhost for testing only. */
#ifndef HPSP_DEVICE_H
#define HPSP_DEVICE_H
#include <stddef.h>
#include <stdint.h>
#include "hpsp_grant.h"

#define HPSP_MAX_MSG        1024
#define HPSP_MAX_ASSEMBLED  4096
#define HPSP_EVENT_SLOTS    32
#define HPSP_EVENT_MAX      224
#define HPSP_MAX_OUTPUTS    4

typedef struct {
    int      (*send)(void *ctx, const uint8_t *b, size_t n);   /* write to the secure session */
    void     (*close)(void *ctx);                              /* close the session */
    uint64_t (*now_ms)(void *ctx);                             /* monotonic milliseconds */
    int      (*random)(void *ctx, uint8_t *b, size_t n);       /* hardware random bytes, 0 = ok */
    int      (*nv_write_u64)(void *ctx, int key, uint64_t v);  /* persist a value, 0 = ok */
    void     (*output)(void *ctx, uint16_t cid, int on);       /* drive an output: 1 = release */
    void     (*log)(void *ctx, const char *msg);               /* optional diagnostics */
} hpsp_port;

enum { HPSP_NV_GRANT_BLOCK = 1, HPSP_NV_SEQ_BLOCK = 2 };

typedef struct {
    uint8_t  uuid[16];
    char     uuid_str[37];
    const char *manufacturer, *product, *hw_rev, *fw_version, *serial, *phy, *caps_id;
    uint16_t reader_cid;
    uint16_t lock_cids[HPSP_MAX_OUTPUTS];
    size_t   n_lock_cids;
    uint64_t trust_epoch;
    uint64_t stored_grant_block;   /* from non-volatile memory at boot */
    uint64_t stored_seq_block;
    uint32_t link_loss_grace_s;    /* delay before a latched unlock is secured after session loss */
} hpsp_config;

typedef struct {
    uint64_t seq;
    uint8_t  prio;                 /* 0 low, 1 normal, 2 high, 3 critical */
    uint16_t len;
    uint8_t  msg[HPSP_EVENT_MAX];  /* the encoded event message */
} hpsp_event_slot;

typedef struct {
    uint16_t cid;
    int      released;
    int      latched;
    uint64_t until_ms;
} hpsp_output_state;

typedef struct {
    const hpsp_port *port; void *pctx;
    hpsp_config cfg;
    hpsp_grant_state grants;

    /* session */
    int      up, hello_done;
    uint8_t  nonce[32];
    uint32_t next_id, hello_id, hb_id;
    int      hb_outstanding, hb_missed;
    uint64_t hb_last_ms;
    uint32_t heartbeat_s;
    uint32_t peer_max_msg, peer_max_assembled;
    int      time_valid;
    uint64_t time_s_at, time_ms_at;  /* wall time = time_s_at + (now - time_ms_at)/1000 */
    uint64_t boot_ms;

    /* receive */
    uint8_t  rx[4 + HPSP_MAX_MSG];
    size_t   rx_len;
    uint64_t rx_start_ms;

    /* fragment assembly */
    uint8_t  fbuf[HPSP_MAX_ASSEMBLED];
    int      f_active;
    uint64_t f_id, f_total, f_got, f_start_ms;

    /* events */
    hpsp_event_slot ev[HPSP_EVENT_SLOTS];
    size_t   ev_count;
    uint64_t seq_next, seq_block;
    uint64_t sent_upto;              /* highest seq sent in this session */
    int      dropped;                /* an events_dropped report is pending */
    uint64_t drop_from, drop_to, drop_count; uint8_t drop_prio;

    hpsp_output_state outs[HPSP_MAX_OUTPUTS];
    uint64_t lost_at_ms;             /* when the session was lost, for link_loss_grace_s */
    int      grace_pending;
} hpsp_device;

void hpsp_device_init(hpsp_device *d, const hpsp_config *cfg, const hpsp_port *port, void *pctx);
/* Session lifecycle: call on_connect once the secure session is established. */
void hpsp_device_on_connect(hpsp_device *d);
void hpsp_device_on_bytes(hpsp_device *d, const uint8_t *b, size_t n);
void hpsp_device_on_disconnect(hpsp_device *d);
/* Call every few milliseconds: timers, heartbeats, unlock expiry. */
void hpsp_device_tick(hpsp_device *d);
/* Application input: a card was read (raw bits, left-justified). */
void hpsp_device_credential(hpsp_device *d, uint16_t cid, const char *tech, uint16_t bits, const uint8_t *raw, size_t raw_len);

/* Exposed for tests: process one complete message body (no length prefix). */
void hpsp_device_process(hpsp_device *d, const uint8_t *msg, size_t len);

#endif
