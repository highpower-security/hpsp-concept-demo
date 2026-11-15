/* HPSP reference implementation - POSIX test device.
 *
 * TEST USE ONLY. This program speaks HPSP over PLAIN TCP to a controller
 * simulator on the same machine. A real device runs the same core over a
 * mutually authenticated TLS 1.3 session (see README). It uses a published
 * test signing key and must never be used to control a real door.
 *
 * Usage: hpsp_device <host> <port> [max_sessions] [link_loss_grace_s]   */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "../src/hpsp_device.h"
#include "test_keys.h"

typedef struct { int fd; uint64_t nv[3]; } port_ctx;

int p256_generate_random(uint8_t *out, unsigned n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, out, n); close(fd);
    return r == (ssize_t)n ? 0 : -1;
}

static int p_send(void *c, const uint8_t *b, size_t n)
{
    port_ctx *p = c;
    while (n) { ssize_t w = send(p->fd, b, n, MSG_NOSIGNAL); if (w <= 0) { if (errno == EINTR) continue; return -1; } b += w; n -= (size_t)w; }
    return 0;
}
static void p_close(void *c) { port_ctx *p = c; if (p->fd >= 0) { close(p->fd); p->fd = -1; } }
static uint64_t p_now(void *c) { (void)c; struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u; }
static int p_rand(void *c, uint8_t *b, size_t n) { (void)c; return p256_generate_random(b, (unsigned)n); }
static int p_nv(void *c, int k, uint64_t v) { ((port_ctx *)c)->nv[k] = v; return 0; }
static void p_out(void *c, uint16_t cid, int on) { (void)c; printf("[device] output %u -> %s\n", cid, on ? "RELEASED" : "secure"); fflush(stdout); }
static void p_log(void *c, const char *m) { (void)c; printf("[device] %s\n", m); fflush(stdout); }
static const hpsp_port PORT = { p_send, p_close, p_now, p_rand, p_nv, p_out, p_log };

static int dial(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1 || connect(fd, (struct sockaddr *)&a, sizeof a)) { close(fd); return -1; }
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s host port [max_sessions]\n", argv[0]); return 2; }
    int port = atoi(argv[2]), max_sessions = argc > 3 ? atoi(argv[3]) : 1000000, sessions = 0;
    static hpsp_device d; static port_ctx pc = { -1, { 0 } };
    hpsp_config c; memset(&c, 0, sizeof c);
    memcpy(c.uuid, K_UUID, 16); strcpy(c.uuid_str, K_DEVICE_ID);
    c.manufacturer = "HPSP reference"; c.product = "Host test device"; c.hw_rev = "host";
    c.fw_version = "0.5.0-ref"; c.serial = "REF-0001"; c.phy = "hpsp-e"; c.caps_id = "5e0a11c3";
    c.reader_cid = 0; c.lock_cids[0] = 2; c.n_lock_cids = 1; c.trust_epoch = 12;
    c.link_loss_grace_s = argc > 4 ? (uint32_t)atoi(argv[4]) : 10;
    hpsp_device_init(&d, &c, &PORT, &pc);
    memcpy(d.grants.signers[0].id, K_SIGNER, 32); memcpy(d.grants.signers[0].pub, K_PUB, 64); d.grants.signers[0].in_use = 1;
    printf("[device] TEST BUILD: plain TCP, published test key. Not for real doors.\n"); fflush(stdout);

    uint64_t backoff = 250, card_at = 0; int card_done = 0;
    for (;;) {
        if (pc.fd < 0) {
            if (d.up) hpsp_device_on_disconnect(&d);
            if (sessions >= max_sessions) break;
            usleep((useconds_t)(backoff * 1000));
            pc.fd = dial(argv[1], port);
            if (pc.fd < 0) { if (backoff < 4000) backoff *= 2; hpsp_device_tick(&d); continue; }
            backoff = 250; sessions++;
            printf("[device] connected (session %d)\n", sessions); fflush(stdout);
            hpsp_device_on_connect(&d);
            card_at = 0;
        }
        fd_set rf; FD_ZERO(&rf); FD_SET(pc.fd, &rf);
        struct timeval tv = { 0, 5000 };
        int r = select(pc.fd + 1, &rf, NULL, NULL, &tv);
        if (r > 0 && FD_ISSET(pc.fd, &rf)) {
            uint8_t buf[2048]; ssize_t n = recv(pc.fd, buf, sizeof buf, 0);
            if (n <= 0) { p_close(&pc); hpsp_device_on_disconnect(&d); printf("[device] connection closed\n"); fflush(stdout); continue; }
            hpsp_device_on_bytes(&d, buf, (size_t)n);
        }
        if (pc.fd >= 0 && !d.up) { p_close(&pc); continue; }   /* the core closed the session */
        hpsp_device_tick(&d);
        /* simulated card read, once, 300 ms after the first session is ready */
        if (d.hello_done && !card_done) {
            if (!card_at) card_at = p_now(NULL) + 300;
            else if (p_now(NULL) >= card_at) {
                static const uint8_t raw[] = { 0xc7, 0x6a, 0x18, 0xc0 };   /* H10301, fc 142, id 54321 */
                hpsp_device_credential(&d, 0, "prox", 26, raw, sizeof raw);
                card_done = 1;
            }
        }
    }
    printf("[device] done\n");
    return 0;
}
