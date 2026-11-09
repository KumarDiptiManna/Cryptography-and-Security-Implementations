/*
 * fips202.h - SHA-3 / SHAKE (FIPS 202) used by ML-KEM (FIPS 203).
 *
 * Roles in ML-KEM:  H = SHA3-256,  G = SHA3-512,  J / PRF = SHAKE256,
 *                   XOF = SHAKE128.
 */
#ifndef MLKEM_FIPS202_H
#define MLKEM_FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
    uint64_t s[25];
    unsigned pos;   /* bytes absorbed into / squeezed out of current block */
    unsigned rate;  /* block size in bytes */
    uint8_t  ds;    /* domain-separation byte: 0x06 (SHA3) or 0x1f (SHAKE) */
} keccak_ctx;

void keccak_f1600(uint64_t s[25]);

void keccak_init(keccak_ctx *c, unsigned rate, uint8_t ds);
void keccak_absorb(keccak_ctx *c, const uint8_t *in, size_t len);
void keccak_finalize(keccak_ctx *c);
void keccak_squeeze(keccak_ctx *c, uint8_t *out, size_t len);

/* One-shot helpers */
void sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen);
void sha3_512(uint8_t out[64], const uint8_t *in, size_t inlen);
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

#endif

/* Written with assistance from Claude (Anthropic) - model: Claude Sonnet 5.5, Nov 2026. */
