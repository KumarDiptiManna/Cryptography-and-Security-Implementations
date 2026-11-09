/* mlkem_internal.h - internals exposed only for tests and micro-benchmarks. */
#ifndef MLKEM_INTERNAL_H
#define MLKEM_INTERNAL_H

#include <stdint.h>

/* In-place forward / inverse NTT of a polynomial with 256 coefficients in [0,q). */
void mlkem_ntt(uint16_t f[256]);
void mlkem_invntt(uint16_t f[256]);

/* Expand rho into the k x k matrix A_hat (NTT domain), row-major in a
 * 4x4-strided array: a[i*4 + j]. If transposed != 0 the transpose is stored. */
void mlkem_gen_matrix(uint16_t (*a)[256], const uint8_t rho[32], int k,
                      int transposed);

/* Best-effort secure wipe. */
void mlkem_cleanse(void *p, unsigned long n);

#endif

/* Written with assistance from Claude (Anthropic) - model: Claude Sonnet 5.5, Nov 2026. */
