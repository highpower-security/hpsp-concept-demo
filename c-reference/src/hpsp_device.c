/* HPSP reference implementation - device side. See hpsp_device.h.
 * Every map is written with its keys in the deterministic order of RFC 8949
 * section 4.2.1 (shorter keys first, then bytewise). */
#include "hpsp_device.h"
#include "hpsp_cbor.h"
#include <string.h>

#define FRAG_TIMEOUT_MS   10000u
#define MSG_TIMEOUT_MS     5000u
#define HB_MISSED_LIMIT       3
#define SEQ_BLOCK           256u

static void logm(hpsp_device *d, const char *m) { if (d->port->log) d->port->log(d->pctx, m); }
static uint64_t now(hpsp_device *d) { return d->port->now_ms(d->pctx); }
static uint64_t mono(hpsp_device *d) { return now(d) - d->boot_ms; }
static uint64_t wall_s(hpsp_device *d) { return d->time_valid ? d->time_s_at + (now(d) - d->time_ms_at) / 1000u : 0; }

/* ---------------- envelope ---------------- */
typedef struct {
    int has_id; uint32_t id; const char *op; int has_re; uint32_t re;
    int has_seq; uint64_t seq; int has_data; int has_mono; uint64_t mono; const char *type;
} env_t;

static void env_open(cbor_wr *w, const env_t *e)
{
    size_t n = (size_t)e->has_id + (e->op ? 1 : 0) + (size_t)e->has_re + (size_t)e->has_seq + (size_t)e->has_data + (size_t)e->has_mono + 1;
    cbor_put_map(w, n);
    if (e->has_id) { cbor_put_text(w, "id"); cbor_put_uint(w, e->id); }
    if (e->op) { cbor_put_text(w, "op"); cbor_put_text(w, e->op); }
    if (e->has_re) { cbor_put_text(w, "re"); cbor_put_uint(w, e->re); }
    if (e->has_seq) { cbor_put_text(w, "seq"); cbor_put_uint(w, e->seq); }
    if (e->has_data) cbor_put_text(w, "data");
}
static void env_close(cbor_wr *w, const env_t *e)
{
    if (e->has_mono) { cbor_put_text(w, "mono"); cbor_put_uint(w, e->mono); }
    cbor_put_text(w, "type"); cbor_put_text(w, e->type);
}

static void send_body(hpsp_device *d, const uint8_t *b, size_t n)
{
    if (!d->up) return;
    if (n > d->peer_max_msg) { logm(d, "message larger than peer max_msg; not sent"); return; }
    uint8_t hdr[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };
    if (d->port->send(d->pctx, hdr, 4) || d->port->send(d->pctx, b, n)) { d->port->close(d->pctx); hpsp_device_on_disconnect(d); }
}

static void send_err(hpsp_device *d, const char *op, int has_re, uint32_t re, const char *code)
{
    uint8_t buf[128]; cbor_wr w; cbor_wr_init(&w, buf, sizeof buf);
    env_t e = { 0 }; e.op = op; e.has_re = has_re; e.re = re; e.has_data = 1; e.type = "err";
    env_open(&w, &e);
    cbor_put_map(&w, 1); cbor_put_text(&w, "code"); cbor_put_text(&w, code);
    env_close(&w, &e);
    if (!w.err) send_body(d, buf, w.len);
}

/* ---------------- events ---------------- */
static void ev_reserve_seq(hpsp_device *d)
{
    if (d->seq_next >= d->seq_block + SEQ_BLOCK) {
        d->seq_block = d->seq_next - (d->seq_next % SEQ_BLOCK);
        d->port->nv_write_u64(d->pctx, HPSP_NV_SEQ_BLOCK, d->seq_block);
    }
}

static hpsp_event_slot *ev_alloc(hpsp_device *d, uint8_t prio)
{
    if (d->ev_count == HPSP_EVENT_SLOTS) {
        /* discard the oldest event of the lowest priority present */
        size_t victim = 0; uint8_t lp = 255;
        for (size_t i = 0; i < d->ev_count; i++) if (d->ev[i].prio < lp) { lp = d->ev[i].prio; victim = i; }
        if (lp > prio) return NULL;      /* never discard a higher-priority event for this one */
        uint64_t s = d->ev[victim].seq;
        if (!d->dropped) { d->dropped = 1; d->drop_from = s; d->drop_to = s; d->drop_count = 0; d->drop_prio = lp; }
        if (s < d->drop_from) d->drop_from = s;
        if (s > d->drop_to) d->drop_to = s;
        if (lp < d->drop_prio) d->drop_prio = lp;
        d->drop_count++;
        memmove(&d->ev[victim], &d->ev[victim + 1], (d->ev_count - victim - 1) * sizeof d->ev[0]);
        d->ev_count--;
    }
    hpsp_event_slot *s = &d->ev[d->ev_count];
    s->prio = prio; s->len = 0; s->seq = d->seq_next;
    return s;
}

/* Begin an event: returns a writer positioned to write the data map. */
static int ev_begin(hpsp_device *d, hpsp_event_slot **slot, cbor_wr *w, env_t *e, const char *op, uint8_t prio)
{
    hpsp_event_slot *s = ev_alloc(d, prio);
    if (!s) return -1;
    memset(e, 0, sizeof *e);
    e->op = op; e->has_seq = 1; e->seq = s->seq; e->has_data = 1; e->has_mono = 1; e->mono = mono(d); e->type = "evt";
    cbor_wr_init(w, s->msg, sizeof s->msg);
    env_open(w, e);
    *slot = s;
    return 0;
}

static void ev_end(hpsp_device *d, hpsp_event_slot *s, cbor_wr *w, const env_t *e)
{
    env_close(w, e);
    if (w->err) { logm(d, "event too large; dropped"); return; }
    s->len = (uint16_t)w->len;
    d->ev_count++;
    d->seq_next++;
    ev_reserve_seq(d);
    if (d->up && d->hello_done) { send_body(d, s->msg, s->len); if (s->seq > d->sent_upto) d->sent_upto = s->seq; }
}

static void ev_ack(hpsp_device *d, uint64_t seq)
{
    size_t k = 0;
    while (k < d->ev_count && d->ev[k].seq <= seq) k++;
    if (k) { memmove(&d->ev[0], &d->ev[k], (d->ev_count - k) * sizeof d->ev[0]); d->ev_count -= k; }
}

static void ev_flush_dropped(hpsp_device *d)
{
    if (!d->dropped) return;
    static const char *pn[] = { "low", "normal", "high", "critical" };
    hpsp_event_slot *s; cbor_wr w; env_t e;
    d->dropped = 0;  /* cleared first: allocating may itself drop and set it again */
    uint64_t from = d->drop_from, to = d->drop_to, cnt = d->drop_count; uint8_t pr = d->drop_prio;
    if (ev_begin(d, &s, &w, &e, "events_dropped", 3)) return;
    cbor_put_map(&w, 4);
    cbor_put_text(&w, "to"); cbor_put_uint(&w, to);
    cbor_put_text(&w, "from"); cbor_put_uint(&w, from);
    cbor_put_text(&w, "count"); cbor_put_uint(&w, cnt);
    cbor_put_text(&w, "priority"); cbor_put_text(&w, pn[pr & 3]);
    ev_end(d, s, &w, &e);
}

static void ev_lock_state(hpsp_device *d, uint16_t cid, const char *state, const char *cause)
{
    hpsp_event_slot *s; cbor_wr w; env_t e;
    if (ev_begin(d, &s, &w, &e, "lock_state", 2)) return;
    cbor_put_map(&w, 3);
    cbor_put_text(&w, "cid"); cbor_put_uint(&w, cid);
    cbor_put_text(&w, "cause"); cbor_put_text(&w, cause);
    cbor_put_text(&w, "state"); cbor_put_text(&w, state);
    ev_end(d, s, &w, &e);
}

void hpsp_device_credential(hpsp_device *d, uint16_t cid, const char *tech, uint16_t bits, const uint8_t *raw, size_t raw_len)
{
    hpsp_event_slot *s; cbor_wr w; env_t e;
    if (ev_begin(d, &s, &w, &e, "credential", 2)) return;
    cbor_put_map(&w, 5);
    cbor_put_text(&w, "cid"); cbor_put_uint(&w, cid);
    cbor_put_text(&w, "bits"); cbor_put_uint(&w, bits);
    cbor_put_text(&w, "tech"); cbor_put_text(&w, tech);
    cbor_put_text(&w, "raw_hex"); cbor_put_bytes(&w, raw, raw_len);
    cbor_put_text(&w, "secure_read"); cbor_put_bool(&w, 0);
    ev_end(d, s, &w, &e);
}

/* ---------------- session ---------------- */
void hpsp_device_init(hpsp_device *d, const hpsp_config *cfg, const hpsp_port *port, void *pctx)
{
    memset(d, 0, sizeof *d);
    d->port = port; d->pctx = pctx; d->cfg = *cfg;
    d->boot_ms = port->now_ms(pctx);
    hpsp_grant_boot(&d->grants, cfg->stored_grant_block);
    /* sequence numbers continue above the last reserved block: a gap after boot is expected */
    d->seq_block = cfg->stored_seq_block + SEQ_BLOCK;
    d->seq_next = d->seq_block;
    port->nv_write_u64(pctx, HPSP_NV_SEQ_BLOCK, d->seq_block);
    for (size_t i = 0; i < cfg->n_lock_cids; i++) {
        d->outs[i].cid = cfg->lock_cids[i];
        port->output(pctx, cfg->lock_cids[i], 0);   /* secure as soon as firmware runs */
    }
    d->heartbeat_s = 10; d->peer_max_msg = HPSP_MAX_MSG; d->peer_max_assembled = HPSP_MAX_ASSEMBLED;
    /* the first event of every boot */
    hpsp_event_slot *s; cbor_wr w; env_t e;
    if (!ev_begin(d, &s, &w, &e, "boot", 1)) {
        cbor_put_map(&w, 3);
        cbor_put_text(&w, "reason"); cbor_put_text(&w, "power_on");
        cbor_put_text(&w, "seq_base"); cbor_put_uint(&w, d->seq_next);
        cbor_put_text(&w, "fw_version"); cbor_put_text(&w, cfg->fw_version);
        ev_end(d, s, &w, &e);
    }
}

static void send_hello(hpsp_device *d)
{
    uint8_t buf[HPSP_MAX_MSG]; cbor_wr w; cbor_wr_init(&w, buf, sizeof buf);
    env_t e = { 0 }; e.has_id = 1; e.id = d->hello_id = d->next_id++; e.op = "hello"; e.has_data = 1; e.type = "cmd";
    env_open(&w, &e);
    /* event_seq is required (spec 5.7): the retained range of unacknowledged events,
       or, when none are retained, both equal to the last number used. */
    uint64_t ev_first = d->ev_count > 0 ? d->ev[0].seq : d->seq_next - 1;
    uint64_t ev_last  = d->ev_count > 0 ? d->ev[d->ev_count - 1].seq : d->seq_next - 1;
    cbor_put_map(&w, 18);
    cbor_put_text(&w, "dal"); cbor_put_uint(&w, 1);
    cbor_put_text(&w, "phy"); cbor_put_text(&w, d->cfg.phy);
    cbor_put_text(&w, "hw_rev"); cbor_put_text(&w, d->cfg.hw_rev);
    cbor_put_text(&w, "serial"); cbor_put_text(&w, d->cfg.serial);
    cbor_put_text(&w, "caps_id"); cbor_put_text(&w, d->cfg.caps_id);
    cbor_put_text(&w, "max_msg"); cbor_put_uint(&w, HPSP_MAX_MSG);
    cbor_put_text(&w, "product"); cbor_put_text(&w, d->cfg.product);
    cbor_put_text(&w, "mono_now"); cbor_put_uint(&w, mono(d));
    cbor_put_text(&w, "versions"); cbor_put_array(&w, 1); cbor_put_uint(&w, 1);
    cbor_put_text(&w, "device_id"); cbor_put_text(&w, d->cfg.uuid_str);
    cbor_put_text(&w, "event_seq"); cbor_put_map(&w, 2);
    cbor_put_text(&w, "last"); cbor_put_uint(&w, ev_last);
    cbor_put_text(&w, "first"); cbor_put_uint(&w, ev_first);
    cbor_put_text(&w, "fw_version"); cbor_put_text(&w, d->cfg.fw_version);
    cbor_put_text(&w, "time_valid"); cbor_put_bool(&w, d->time_valid);
    cbor_put_text(&w, "grant_floor"); cbor_put_uint(&w, d->grants.floor);
    cbor_put_text(&w, "trust_epoch"); cbor_put_uint(&w, d->cfg.trust_epoch);
    cbor_put_text(&w, "manufacturer"); cbor_put_text(&w, d->cfg.manufacturer);
    cbor_put_text(&w, "max_assembled"); cbor_put_uint(&w, HPSP_MAX_ASSEMBLED);
    cbor_put_text(&w, "session_nonce_b64"); cbor_put_bytes(&w, d->nonce, 32);
    env_close(&w, &e);
    if (!w.err) send_body(d, buf, w.len);
}

void hpsp_device_on_connect(hpsp_device *d)
{
    d->up = 1; d->hello_done = 0; d->rx_len = 0; d->f_active = 0; d->grace_pending = 0;
    d->hb_outstanding = 0; d->hb_missed = 0; d->sent_upto = 0;
    d->peer_max_msg = HPSP_MAX_MSG; d->peer_max_assembled = HPSP_MAX_ASSEMBLED;
    d->next_id = 1;
    /* a fresh session value for every session: it is bound into every grant */
    if (d->port->random(d->pctx, d->nonce, sizeof d->nonce)) { d->port->close(d->pctx); d->up = 0; return; }
    send_hello(d);
}

void hpsp_device_on_disconnect(hpsp_device *d)
{
    if (!d->up) return;
    d->up = 0; d->hello_done = 0; d->f_active = 0; d->rx_len = 0;
    /* link_loss: secure. Timed unlocks run to their end. A latched unlock is
     * secured after link_loss_grace_s unless a new session starts first. */
    d->lost_at_ms = now(d); d->grace_pending = 0;
    for (size_t i = 0; i < d->cfg.n_lock_cids; i++) if (d->outs[i].released && d->outs[i].latched) d->grace_pending = 1;
    hpsp_device_tick(d);
}

/* ---------------- time ---------------- */
static int parse_time(const uint8_t *s, size_t n, uint64_t *out)
{
    /* YYYY-MM-DDTHH:MM:SS[.fff]Z */
    if (n < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[n - 1] != 'Z') return -1;
    int v[6], pos[6] = { 0, 5, 8, 11, 14, 17 }, len[6] = { 4, 2, 2, 2, 2, 2 };
    for (int i = 0; i < 6; i++) {
        v[i] = 0;
        for (int j = 0; j < len[i]; j++) { uint8_t c = s[pos[i] + j]; if (c < '0' || c > '9') return -1; v[i] = v[i] * 10 + (c - '0'); }
    }
    int y = v[0], m = v[1], dd = v[2];
    if (m < 1 || m > 12 || dd < 1 || dd > 31 || v[3] > 23 || v[4] > 59 || v[5] > 60) return -1;
    y -= m <= 2;                                   /* days from civil (H. Hinnant) */
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (unsigned)((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + dd - 1);
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = (int64_t)era * 146097 + (int64_t)doe - 719468;
    if (days < 0) return -1;
    *out = (uint64_t)days * 86400u + (uint64_t)v[3] * 3600u + (uint64_t)v[4] * 60u + (uint64_t)v[5];
    return 0;
}

/* ---------------- operations ---------------- */
static hpsp_output_state *lock_output(hpsp_device *d, uint64_t cid)
{
    for (size_t i = 0; i < d->cfg.n_lock_cids; i++) if (d->outs[i].cid == cid) return &d->outs[i];
    return NULL;
}

static void reply_state(hpsp_device *d, const char *op, uint32_t re, uint16_t cid, const char *state, int has_dur, uint32_t dur)
{
    uint8_t buf[128]; cbor_wr w; cbor_wr_init(&w, buf, sizeof buf);
    env_t e = { 0 }; e.op = op; e.has_re = 1; e.re = re; e.has_data = 1; e.type = "rsp";
    env_open(&w, &e);
    cbor_put_map(&w, has_dur ? 3 : 2);
    cbor_put_text(&w, "cid"); cbor_put_uint(&w, cid);
    cbor_put_text(&w, "state"); cbor_put_text(&w, state);
    if (has_dur) { cbor_put_text(&w, "duration_ms"); cbor_put_uint(&w, dur); }
    env_close(&w, &e);
    if (!w.err) send_body(d, buf, w.len);
}

static void op_unlock(hpsp_device *d, uint32_t id, cbor_item data)
{
    static const char *codes[] = { "", "forbidden", "unauthorized", "replay", "expired", "bad_signature", "bad_request" };
    cbor_item it, g, x; uint64_t cid, dur = 0; int latched;
    if (cbor_map_get(data, "cid", &it) || cbor_get_uint(it, &cid)) { send_err(d, "unlock", 1, id, "bad_request"); return; }
    hpsp_output_state *o = lock_output(d, cid);
    if (!o) { send_err(d, "unlock", 1, id, "not_found"); return; }
    if (cbor_map_get(data, "mode", &it)) { send_err(d, "unlock", 1, id, "bad_request"); return; }
    if (cbor_text_eq(it, "timed")) {
        latched = 0;
        if (cbor_map_get(data, "duration_ms", &it) || cbor_get_uint(it, &dur) || dur < 100 || dur > 3600000) { send_err(d, "unlock", 1, id, "bad_request"); return; }
    } else if (cbor_text_eq(it, "latched")) {
        latched = 1;
        if (!cbor_map_get(data, "duration_ms", &it) && (cbor_get_uint(it, &dur) || dur != 0)) { send_err(d, "unlock", 1, id, "bad_request"); return; }
    } else { send_err(d, "unlock", 1, id, "bad_request"); return; }

    hpsp_grant gr;
    if (cbor_map_get(data, "grant", &g)
        || cbor_map_get(g, "signer_hex", &x) || cbor_get_bytes(x, &gr.signer_id, &gr.signer_id_len)
        || cbor_map_get(g, "counter", &x) || cbor_get_uint(x, &gr.counter)
        || cbor_map_get(g, "expires", &x) || cbor_get_uint(x, &gr.expires)
        || cbor_map_get(g, "sig_b64", &x) || cbor_get_bytes(x, &gr.sig, &gr.sig_len)) {
        send_err(d, "unlock", 1, id, "bad_request"); return;
    }
    int nvw;
    int r = hpsp_grant_check(&d->grants, &gr, d->cfg.uuid, d->nonce, (uint16_t)cid, latched ? 2 : 1, 0,
                             (uint32_t)dur, wall_s(d), &nvw);
    if (r != GRANT_OK) { send_err(d, "unlock", 1, id, codes[r]); return; }
    if (nvw && d->port->nv_write_u64(d->pctx, HPSP_NV_GRANT_BLOCK, d->grants.reserved_block)) {
        send_err(d, "unlock", 1, id, "hardware"); return;   /* never act on a counter we could not record */
    }
    o->released = 1; o->latched = latched; o->until_ms = latched ? 0 : now(d) + dur;
    d->port->output(d->pctx, o->cid, 1);
    reply_state(d, "unlock", id, o->cid, "unlocked", !latched, (uint32_t)dur);
    ev_lock_state(d, o->cid, "unlocked", "command");
}

static void op_lock(hpsp_device *d, uint32_t id, cbor_item data)
{
    cbor_item it; uint64_t cid;
    if (cbor_map_get(data, "cid", &it) || cbor_get_uint(it, &cid)) { send_err(d, "lock", 1, id, "bad_request"); return; }
    hpsp_output_state *o = lock_output(d, cid);
    if (!o) { send_err(d, "lock", 1, id, "not_found"); return; }
    int was = o->released;
    o->released = 0; o->latched = 0;
    d->port->output(d->pctx, o->cid, 0);
    reply_state(d, "lock", id, o->cid, "locked", 0, 0);
    if (was) ev_lock_state(d, o->cid, "locked", "command");
}

static void op_get_caps(hpsp_device *d, uint32_t id)
{
    uint8_t buf[HPSP_MAX_MSG]; cbor_wr w; cbor_wr_init(&w, buf, sizeof buf);
    env_t e = { 0 }; e.op = "get_caps"; e.has_re = 1; e.re = id; e.has_data = 1; e.type = "rsp";
    env_open(&w, &e);
    cbor_put_map(&w, 5);
    cbor_put_text(&w, "phy"); cbor_put_array(&w, 1); cbor_put_text(&w, d->cfg.phy);
    cbor_put_text(&w, "more"); cbor_put_bool(&w, 0);
    cbor_put_text(&w, "caps_id"); cbor_put_text(&w, d->cfg.caps_id);
    cbor_put_text(&w, "profiles"); cbor_put_array(&w, 2); cbor_put_text(&w, "reader"); cbor_put_text(&w, "electric_strike");
    cbor_put_text(&w, "components"); cbor_put_array(&w, 1 + d->cfg.n_lock_cids);
    cbor_put_map(&w, 3);
    cbor_put_text(&w, "cid"); cbor_put_uint(&w, d->cfg.reader_cid);
    cbor_put_text(&w, "kind"); cbor_put_text(&w, "reader");
    cbor_put_text(&w, "tech"); cbor_put_array(&w, 1); cbor_put_text(&w, "prox");
    for (size_t i = 0; i < d->cfg.n_lock_cids; i++) {
        cbor_put_map(&w, 7);
        cbor_put_text(&w, "cid"); cbor_put_uint(&w, d->cfg.lock_cids[i]);
        cbor_put_text(&w, "fail"); cbor_put_text(&w, "secure");
        cbor_put_text(&w, "kind"); cbor_put_text(&w, "output");
        cbor_put_text(&w, "role"); cbor_put_text(&w, "lock");
        cbor_put_text(&w, "lock_type"); cbor_put_text(&w, "strike");
        cbor_put_text(&w, "door_release"); cbor_put_bool(&w, 1);
        cbor_put_text(&w, "max_duration_ms"); cbor_put_uint(&w, 3600000);
    }
    env_close(&w, &e);
    if (!w.err) send_body(d, buf, w.len);
}

static void reply_empty(hpsp_device *d, const char *op, uint32_t re)
{
    uint8_t buf[64]; cbor_wr w; cbor_wr_init(&w, buf, sizeof buf);
    env_t e = { 0 }; e.op = op; e.has_re = 1; e.re = re; e.type = "rsp";
    env_open(&w, &e); env_close(&w, &e);
    if (!w.err) send_body(d, buf, w.len);
}

static void on_hello_rsp(hpsp_device *d, cbor_item data)
{
    cbor_item it; uint64_t v; const uint8_t *s; size_t n;
    if (!cbor_map_get(data, "heartbeat_s", &it) && !cbor_get_uint(it, &v) && v >= 2 && v <= 60) d->heartbeat_s = (uint32_t)v;
    if (!cbor_map_get(data, "max_msg", &it) && !cbor_get_uint(it, &v) && v >= 1024 && v <= 65536) d->peer_max_msg = (uint32_t)v;
    if (!cbor_map_get(data, "max_assembled", &it) && !cbor_get_uint(it, &v) && v >= 4096) d->peer_max_assembled = (uint32_t)(v > 0xffffffffu ? 0xffffffffu : v);
    /* time comes only from the authenticated controller session */
    if (!cbor_map_get(data, "time", &it) && !cbor_get_text(it, &s, &n) && !parse_time(s, n, &v)) {
        d->time_valid = 1; d->time_s_at = v; d->time_ms_at = now(d);
    }
    uint64_t resume = 0;
    if (!cbor_map_get(data, "resume_from", &it)) cbor_get_uint(it, &resume);
    if (resume > 0) ev_ack(d, resume - 1);
    d->hello_done = 1;
    d->hb_last_ms = now(d);
    /* replay everything not yet acknowledged, in order */
    for (size_t i = 0; i < d->ev_count; i++) { send_body(d, d->ev[i].msg, d->ev[i].len); d->sent_upto = d->ev[i].seq; }
    ev_flush_dropped(d);
}

static void process_frag(hpsp_device *d, cbor_item data)
{
    cbor_item it; uint64_t fid, total, off; const uint8_t *p; size_t n;
    if (cbor_map_get(data, "fid", &it) || cbor_get_uint(it, &fid)
        || cbor_map_get(data, "total", &it) || cbor_get_uint(it, &total)
        || cbor_map_get(data, "offset", &it) || cbor_get_uint(it, &off)
        || cbor_map_get(data, "data_b64", &it) || cbor_get_bytes(it, &p, &n)) {
        d->f_active = 0; send_err(d, "frag", 0, 0, "bad_request"); return;
    }
    if (off == 0) {
        if (total > HPSP_MAX_ASSEMBLED || total < 2) { d->f_active = 0; send_err(d, "frag", 0, 0, "bad_request"); return; }
        d->f_active = 1; d->f_id = fid; d->f_total = total; d->f_got = 0; d->f_start_ms = now(d);
    } else if (!d->f_active || fid != d->f_id || total != d->f_total) {
        d->f_active = 0; send_err(d, "frag", 0, 0, "bad_request"); return;
    }
    if (off != d->f_got || n == 0 || n > d->f_total - d->f_got) { d->f_active = 0; send_err(d, "frag", 0, 0, "bad_request"); return; }
    memcpy(d->fbuf + d->f_got, p, n);
    d->f_got += n;
    if (d->f_got == d->f_total) {
        d->f_active = 0;
        /* the joined message is processed as if it had arrived in one frame;
         * a fragment set may not contain another fragment */
        if (d->f_total >= 1 && cbor_validate_message(d->fbuf, (size_t)d->f_total) == 0) {
            cbor_item m = { d->fbuf, (size_t)d->f_total }, t;
            if (!cbor_map_get(m, "type", &t) && cbor_text_eq(t, "frag")) { d->port->close(d->pctx); hpsp_device_on_disconnect(d); return; }
        }
        hpsp_device_process(d, d->fbuf, (size_t)d->f_total);
    }
}

void hpsp_device_process(hpsp_device *d, const uint8_t *msg, size_t len)
{
    if (cbor_validate_message(msg, len) != 0) { logm(d, "invalid message; closing"); d->port->close(d->pctx); hpsp_device_on_disconnect(d); return; }
    cbor_item m = { msg, len }, t, it, data = { (const uint8_t *)"\xa0", 1 };
    if (cbor_map_get(m, "type", &t)) { d->port->close(d->pctx); hpsp_device_on_disconnect(d); return; }
    cbor_map_get(m, "data", &data);

    if (cbor_text_eq(t, "rsp")) {
        uint64_t re;
        if (cbor_map_get(m, "re", &it) || cbor_get_uint(it, &re)) return;
        if (re == d->hello_id && !d->hello_done) on_hello_rsp(d, data);
        else if (re == d->hb_id) { d->hb_outstanding = 0; d->hb_missed = 0; }
        return;
    }
    if (cbor_text_eq(t, "err")) {
        uint64_t re;
        if (!cbor_map_get(m, "re", &it) && !cbor_get_uint(it, &re) && re == d->hello_id && !d->hello_done) {
            logm(d, "hello refused; closing"); d->port->close(d->pctx); hpsp_device_on_disconnect(d);
        }
        return;
    }
    if (cbor_text_eq(t, "ack")) {
        uint64_t s;
        if (!cbor_map_get(data, "seq", &it) && !cbor_get_uint(it, &s)) ev_ack(d, s);
        return;
    }
    if (cbor_text_eq(t, "frag")) { process_frag(d, data); return; }
    if (!cbor_text_eq(t, "cmd") && !cbor_text_eq(t, "evt")) {
        logm(d, "unknown message type; closing"); d->port->close(d->pctx); hpsp_device_on_disconnect(d); return;
    }
    if (cbor_text_eq(t, "evt")) return;          /* controllers do not send events */

    uint64_t id; const uint8_t *op; size_t opn;
    if (cbor_map_get(m, "id", &it) || cbor_get_uint(it, &id) || id == 0 || id > 0xffffffffu
        || cbor_map_get(m, "op", &it) || cbor_get_text(it, &op, &opn)) {
        d->port->close(d->pctx); hpsp_device_on_disconnect(d); return;
    }
    char opname[32];
    if (opn >= sizeof opname) { send_err(d, "unknown", 1, (uint32_t)id, "unsupported"); return; }
    memcpy(opname, op, opn); opname[opn] = 0;
    if (!d->hello_done) { send_err(d, opname, 1, (uint32_t)id, "forbidden"); return; }

    if (!strcmp(opname, "unlock")) op_unlock(d, (uint32_t)id, data);
    else if (!strcmp(opname, "lock")) op_lock(d, (uint32_t)id, data);
    else if (!strcmp(opname, "get_caps")) op_get_caps(d, (uint32_t)id);
    else if (!strcmp(opname, "goodbye")) { reply_empty(d, "goodbye", (uint32_t)id); d->port->close(d->pctx); hpsp_device_on_disconnect(d); }
    else send_err(d, opname, 1, (uint32_t)id, "unsupported");
}

void hpsp_device_on_bytes(hpsp_device *d, const uint8_t *b, size_t n)
{
    while (n && d->up) {
        if (d->rx_len == 0) d->rx_start_ms = now(d);
        size_t need;
        if (d->rx_len < 4) need = 4 - d->rx_len;
        else {
            uint32_t L = (uint32_t)d->rx[0] << 24 | (uint32_t)d->rx[1] << 16 | (uint32_t)d->rx[2] << 8 | d->rx[3];
            need = 4 + L - d->rx_len;
        }
        size_t k = need < n ? need : n;
        memcpy(d->rx + d->rx_len, b, k); d->rx_len += k; b += k; n -= k;
        if (d->rx_len == 4) {
            uint32_t L = (uint32_t)d->rx[0] << 24 | (uint32_t)d->rx[1] << 16 | (uint32_t)d->rx[2] << 8 | d->rx[3];
            if (L < 2 || L > HPSP_MAX_MSG) { logm(d, "bad frame length; closing"); d->port->close(d->pctx); hpsp_device_on_disconnect(d); return; }
        } else if (d->rx_len > 4) {
            uint32_t L = (uint32_t)d->rx[0] << 24 | (uint32_t)d->rx[1] << 16 | (uint32_t)d->rx[2] << 8 | d->rx[3];
            if (d->rx_len == 4 + L) { d->rx_len = 0; hpsp_device_process(d, d->rx + 4, L); }
        }
    }
}

void hpsp_device_tick(hpsp_device *d)
{
    uint64_t t = now(d);
    /* timed unlocks run to their end, with or without a session */
    for (size_t i = 0; i < d->cfg.n_lock_cids; i++) {
        hpsp_output_state *o = &d->outs[i];
        if (o->released && !o->latched && t >= o->until_ms) {
            o->released = 0; d->port->output(d->pctx, o->cid, 0);
            ev_lock_state(d, o->cid, "locked", "timeout");
        }
    }
    if (d->grace_pending && !d->up && t - d->lost_at_ms >= (uint64_t)d->cfg.link_loss_grace_s * 1000u) {
        d->grace_pending = 0;
        for (size_t i = 0; i < d->cfg.n_lock_cids; i++)
            if (d->outs[i].released && d->outs[i].latched) {
                d->outs[i].released = 0; d->outs[i].latched = 0;
                d->port->output(d->pctx, d->outs[i].cid, 0);
                ev_lock_state(d, d->outs[i].cid, "locked", "link_loss");
            }
    }
    if (!d->up) return;
    if (d->rx_len && t - d->rx_start_ms > MSG_TIMEOUT_MS) { logm(d, "incomplete message; closing"); d->port->close(d->pctx); hpsp_device_on_disconnect(d); return; }
    if (d->f_active && t - d->f_start_ms > FRAG_TIMEOUT_MS) d->f_active = 0;
    if (d->hello_done && t - d->hb_last_ms >= (uint64_t)d->heartbeat_s * 1000u) {
        if (d->hb_outstanding && ++d->hb_missed >= HB_MISSED_LIMIT) {
            logm(d, "three heartbeats missed; session dead"); d->port->close(d->pctx); hpsp_device_on_disconnect(d); return;
        }
        d->hb_last_ms = t;
        uint8_t buf[96]; cbor_wr w; cbor_wr_init(&w, buf, sizeof buf);
        env_t e = { 0 }; e.has_id = 1; e.id = d->hb_id = d->next_id++; e.op = "heartbeat"; e.has_data = 1; e.type = "cmd";
        env_open(&w, &e);
        cbor_put_map(&w, 3);
        cbor_put_text(&w, "status"); cbor_put_text(&w, "ok");
        cbor_put_text(&w, "mono_now"); cbor_put_uint(&w, mono(d));
        cbor_put_text(&w, "uptime_s"); cbor_put_uint(&w, mono(d) / 1000u);
        env_close(&w, &e);
        d->hb_outstanding = 1;
        if (!w.err) send_body(d, buf, w.len);
    }
    ev_flush_dropped(d);
}
