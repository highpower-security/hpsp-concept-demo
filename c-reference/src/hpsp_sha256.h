/* HPSP reference implementation - SHA-256 (FIPS 180-4). Portable, no allocation. */
#ifndef HPSP_SHA256_H
#define HPSP_SHA256_H
#include <stddef.h>
#include <stdint.h>
typedef struct { uint32_t h[8]; uint64_t bits; uint8_t buf[64]; size_t n; } hpsp_sha256_ctx;
void hpsp_sha256_init(hpsp_sha256_ctx *c);
void hpsp_sha256_update(hpsp_sha256_ctx *c, const uint8_t *d, size_t len);
void hpsp_sha256_final(hpsp_sha256_ctx *c, uint8_t out[32]);
void hpsp_sha256(const uint8_t *d, size_t len, uint8_t out[32]);
#endif
