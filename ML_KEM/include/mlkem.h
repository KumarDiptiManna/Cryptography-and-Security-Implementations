/*
 * mlkem.h - ML-KEM (CRYSTALS-Kyber, NIST FIPS 203) public API.
 *
 * All three standardized parameter sets are supported through a runtime
 * parameter object, so one library serves ML-KEM-512/768/1024:
 *
 *     uint8_t ek[MLKEM_MAX_EK_BYTES], dk[MLKEM_MAX_DK_BYTES];
 *     uint8_t ct[MLKEM_MAX_CT_BYTES], ss1[32], ss2[32];
 *
 *     mlkem_keygen(&mlkem768, ek, dk);        // Alice
 *     mlkem_encaps(&mlkem768, ct, ss1, ek);   // Bob   -> (c, K)
 *     mlkem_decaps(&mlkem768, ss2, ct, dk);   // Alice -> K'   (ss1 == ss2)
 *
 * Every function returns 0 on success and -1 on failure (invalid input or RNG
 * failure).
 */
#ifndef MLKEM_H
#define MLKEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MLKEM_N 256
#define MLKEM_Q 3329
#define MLKEM_SYMBYTES 32 /* seed rho, message m: 32 bytes */
#define MLKEM_SSBYTES 32  /* shared secret size */

#define MLKEM_MAX_EK_BYTES 1568
#define MLKEM_MAX_DK_BYTES 3168
#define MLKEM_MAX_CT_BYTES 1568

typedef struct {
    const char *name;
    int k;                /* module rank                            */
    int eta1, eta2;       /* CBD noise parameters                   */
    int du, dv;           /* ciphertext compression bits            */
    size_t ek_bytes;      /* encapsulation key  = 384k + 32         */
    size_t dk_bytes;      /* decapsulation key  = 768k + 96         */
    size_t ct_bytes;      /* ciphertext = 32 (du*k + dv)            */
    int security_category; /* NIST category 1 / 3 / 5               */
} mlkem_params;

extern const mlkem_params mlkem512;
extern const mlkem_params mlkem768;
extern const mlkem_params mlkem1024;

/* Randomized API (draws from the OS CSPRNG). */
int mlkem_keygen(const mlkem_params *p, uint8_t *ek, uint8_t *dk);
int mlkem_encaps(const mlkem_params *p, uint8_t *ct, uint8_t *ss,
                 const uint8_t *ek);

/* Decapsulation is deterministic. Wrong/tampered ciphertexts do NOT return an
 * error: they yield a pseudorandom key (implicit rejection). -1 is returned
 * only for a malformed decapsulation key. */
int mlkem_decaps(const mlkem_params *p, uint8_t *ss, const uint8_t *ct,
                 const uint8_t *dk);

/* Deterministic variants (for KATs and benchmarking; do NOT use with
 * predictable inputs in production).
 *   coins = d || z (64 bytes),  m = 32-byte message. */
int mlkem_keygen_derand(const mlkem_params *p, uint8_t *ek, uint8_t *dk,
                        const uint8_t coins[64]);
int mlkem_encaps_derand(const mlkem_params *p, uint8_t *ct, uint8_t *ss,
                        const uint8_t *ek, const uint8_t m[32]);

/* OS randomness (getrandom / arc4random_buf / /dev/urandom). */
int mlkem_randombytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif
#endif

/* Written with assistance from Claude (Anthropic) - model: Claude Sonnet 5.5, Nov 2026. */
