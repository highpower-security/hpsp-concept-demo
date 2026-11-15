/* libFuzzer harness: arbitrary bytes into the CBOR validator and the device's
 * receive path. Build: make fuzz  (needs clang). */
#include <string.h>
#include <stdlib.h>
#include "../src/hpsp_cbor.h"
#include "../src/hpsp_device.h"
int p256_generate_random(uint8_t *o, unsigned n) { memset(o, 7, n); return 0; }
static uint64_t t = 1000;
static int f_send(void *c, const uint8_t *b, size_t n) { (void)c; (void)b; (void)n; return 0; }
static void f_close(void *c) { (void)c; }
static uint64_t f_now(void *c) { (void)c; return t; }
static int f_rand(void *c, uint8_t *b, size_t n) { (void)c; memset(b, 3, n); return 0; }
static int f_nv(void *c, int k, uint64_t v) { (void)c; (void)k; (void)v; return 0; }
static void f_out(void *c, uint16_t cid, int on) { (void)c; (void)cid; (void)on; }
static const hpsp_port FP = { f_send, f_close, f_now, f_rand, f_nv, f_out, NULL };
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static hpsp_device d; static int init;
    if (!init) {
        hpsp_config c; memset(&c, 0, sizeof c);
        strcpy(c.uuid_str, "7b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8");
        c.manufacturer = c.product = c.hw_rev = c.fw_version = c.serial = c.phy = c.caps_id = "x";
        c.lock_cids[0] = 2; c.n_lock_cids = 1;
        hpsp_device_init(&d, &c, &FP, NULL); init = 1;
    }
    cbor_validate_message(data, size);
    d.up = 1; d.hello_done = (size & 1);
    hpsp_device_process(&d, data, size);
    d.up = 1; hpsp_device_on_bytes(&d, data, size);
    t += 7; hpsp_device_tick(&d);
    return 0;
}
