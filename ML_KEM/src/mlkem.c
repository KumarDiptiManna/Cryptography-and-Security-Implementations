/*
 * mlkem.c - ML-KEM (FIPS 203) in portable C99.
 *
 * Structure (names follow FIPS 203):
 *   - Z_q arithmetic, NTT, base-case multiplication     (Sec. 4.3)
 *   - ByteEncode / ByteDecode, Compress / Decompress    (Sec. 4.2.1, 4.2.1)
 *   - SampleNTT, SamplePolyCBD                          (Alg. 7, 8)
 *   - K-PKE.KeyGen / Encrypt / Decrypt                  (Alg. 13-15)
 *   - ML-KEM.KeyGen / Encaps / Decaps (FO transform)    (Alg. 16-18)
 *
 * Fujisaki-Okamoto transform (as on the slides):
 *   Encaps : m <- {0,1}^256 ; (K,R) = G(m || H(ek)) ; c = PKE.Enc(ek,m;R)
 *   Decaps : m' = PKE.Dec(s,c) ; (K',R') = G(m' || H(ek)) ; Kbar = J(z || c)
 *            c' = PKE.Enc(ek,m';R') ; return (c == c') ? K' : Kbar
 *
 * Secret-dependent control flow / indexing is avoided: modular reductions use
 * Barrett with fixed instruction sequences, Compress uses division by the
 * constant q (compiled to multiply+shift), and the re-encryption check is
 * a constant-time compare followed by a constant-time select.
 * NOTE: this is not formally verified constant-time; see README.
 */
#include "mlkem.h"
#include "mlkem_internal.h"
#include "fips202.h"

#include <string.h>

#define N MLKEM_N
#define Q MLKEM_Q
#define KMAX 4
#define POLYBYTES 384 /* 256 * 12 bits */

typedef uint16_t poly[N];

/* ------------------------------------------------------------------------ */
/* Parameter sets (match the standardized table: k, (eta1,eta2), (du,dv))   */
/* ------------------------------------------------------------------------ */
const mlkem_params mlkem512  = {"ML-KEM-512",  2, 3, 2, 10, 4,  800, 1632,  768, 1};
const mlkem_params mlkem768  = {"ML-KEM-768",  3, 2, 2, 10, 4, 1184, 2400, 1088, 3};
const mlkem_params mlkem1024 = {"ML-KEM-1024", 4, 2, 2, 11, 5, 1568, 3168, 1568, 5};

/* zeta^BitRev7(i) mod q, zeta = 17 */
static const uint16_t ZETAS[128] = {
       1, 1729, 2580, 3289, 2642,  630, 1897,  848,
    1062, 1919,  193,  797, 2786, 3260,  569, 1746,
     296, 2447, 1339, 1476, 3046,   56, 2240, 1333,
    1426, 2094,  535, 2882, 2393, 2879, 1974,  821,
     289,  331, 3253, 1756, 1197, 2304, 2277, 2055,
     650, 1977, 2513,  632, 2865,   33, 1320, 1915,
    2319, 1435,  807,  452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481,  648, 2474, 3110, 1227,  910,
      17, 2761,  583, 2649, 1637,  723, 2288, 1100,
    1409, 2662, 3281,  233,  756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847,  952, 1461, 2687,
     939, 2308, 2437, 2388,  733, 2337,  268,  641,
    1584, 2298, 2037, 3220,  375, 2549, 2090, 1645,
    1063,  319, 2773,  757, 2099,  561, 2466, 2594,
    2804, 1092,  403, 1026, 1143, 2150, 2775,  886,
    1722, 1212, 1874, 1029, 2110, 2935,  885, 2154,
};

/* zeta^(2*BitRev7(i)+1) mod q */
static const uint16_t GAMMAS[128] = {
      17, 3312, 2761,  568,  583, 2746, 2649,  680,
    1637, 1692,  723, 2606, 2288, 1041, 1100, 2229,
    1409, 1920, 2662,  667, 3281,   48,  233, 3096,
     756, 2573, 2156, 1173, 3015,  314, 3050,  279,
    1703, 1626, 1651, 1678, 2789,  540, 1789, 1540,
    1847, 1482,  952, 2377, 1461, 1868, 2687,  642,
     939, 2390, 2308, 1021, 2437,  892, 2388,  941,
     733, 2596, 2337,  992,  268, 3061,  641, 2688,
    1584, 1745, 2298, 1031, 2037, 1292, 3220,  109,
     375, 2954, 2549,  780, 2090, 1239, 1645, 1684,
    1063, 2266,  319, 3010, 2773,  556,  757, 2572,
    2099, 1230,  561, 2768, 2466,  863, 2594,  735,
    2804,  525, 1092, 2237,  403, 2926, 1026, 2303,
    1143, 2186, 2150, 1179, 2775,  554,  886, 2443,
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
    2110, 1219, 2935,  394,  885, 2444, 2154, 1175,
};

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */
void mlkem_cleanse(void *p, unsigned long n)
{
    static void *(*const volatile memset_v)(void *, int, size_t) = memset;
    memset_v(p, 0, (size_t)n);
}

static inline uint32_t load32(const uint8_t *x)
{
    return (uint32_t)x[0] | ((uint32_t)x[1] << 8) | ((uint32_t)x[2] << 16) |
           ((uint32_t)x[3] << 24);
}

/* all-ones if r < 0 else 0 */
static inline int32_t smask(int32_t r) { return -(int32_t)((uint32_t)r >> 31); }

static inline uint16_t addq(uint16_t a, uint16_t b)
{
    int32_t r = (int32_t)a + (int32_t)b - Q;
    return (uint16_t)(r + (smask(r) & Q));
}
static inline uint16_t subq(uint16_t a, uint16_t b)
{
    int32_t r = (int32_t)a - (int32_t)b;
    return (uint16_t)(r + (smask(r) & Q));
}

/* Barrett reduction, valid for any uint32_t input. floor(2^32/q) = 1290167. */
static inline uint16_t barrett(uint32_t a)
{
    uint32_t t = (uint32_t)(((uint64_t)a * 1290167u) >> 32);
    int32_t r = (int32_t)(a - t * Q); /* in [0, 2q) */
    r -= Q;
    return (uint16_t)(r + (smask(r) & Q));
}

/* constant-time "a != b" over n bytes: returns 1 if different, else 0 */
static int ct_ne(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t r = 0;
    for (size_t i = 0; i < n; i++)
        r |= (uint8_t)(a[i] ^ b[i]);
    return (int)((0u - (uint32_t)r) >> 31);
}

/* constant-time: if flag==1 copy src -> dst */
static void ct_cmov(uint8_t *dst, const uint8_t *src, size_t n, int flag)
{
    uint8_t mask = (uint8_t)(0 - (unsigned)flag);
    for (size_t i = 0; i < n; i++)
        dst[i] ^= (uint8_t)(mask & (dst[i] ^ src[i]));
}

/* ------------------------------------------------------------------------ */
/* NTT (Alg. 9, 10) and multiplication in T_q (Alg. 11, 12)                 */
/* ------------------------------------------------------------------------ */
void mlkem_ntt(uint16_t f[N])
{
    unsigned i = 1;
    for (unsigned len = 128; len >= 2; len >>= 1) {
        for (unsigned start = 0; start < N; start += 2 * len) {
            uint32_t zeta = ZETAS[i++];
            for (unsigned j = start; j < start + len; j++) {
                uint16_t t = barrett(zeta * f[j + len]);
                f[j + len] = subq(f[j], t);
                f[j] = addq(f[j], t);
            }
        }
    }
}

void mlkem_invntt(uint16_t f[N])
{
    unsigned i = 127;
    for (unsigned len = 2; len <= 128; len <<= 1) {
        for (unsigned start = 0; start < N; start += 2 * len) {
            uint32_t zeta = ZETAS[i--];
            for (unsigned j = start; j < start + len; j++) {
                uint16_t t = f[j];
                f[j] = addq(t, f[j + len]);
                f[j + len] = barrett(zeta * subq(f[j + len], t));
            }
        }
    }
    for (unsigned j = 0; j < N; j++)
        f[j] = barrett((uint32_t)f[j] * 3303u); /* 128^-1 mod q */
}

/* r = sum_{m<k} a[m] o b[m]   (pointwise product in the NTT domain).
 * Accumulates in 32 bits: each term < 2*3328^2 ~ 2.2e7, k <= 4. */
static void polyvec_basemul_acc(poly r, const poly *a, const poly *b, int k)
{
    uint32_t acc[N];
    memset(acc, 0, sizeof acc);
    for (int m = 0; m < k; m++) {
        for (unsigned i = 0; i < N / 2; i++) {
            uint32_t a0 = a[m][2 * i], a1 = a[m][2 * i + 1];
            uint32_t b0 = b[m][2 * i], b1 = b[m][2 * i + 1];
            uint32_t t = (uint32_t)barrett(a1 * b1) * GAMMAS[i];
            acc[2 * i] += a0 * b0 + t;
            acc[2 * i + 1] += a0 * b1 + a1 * b0;
        }
    }
    for (unsigned i = 0; i < N; i++)
        r[i] = barrett(acc[i]);
}

static void poly_add(poly r, const poly a, const poly b)
{
    for (unsigned i = 0; i < N; i++)
        r[i] = addq(a[i], b[i]);
}
static void poly_sub(poly r, const poly a, const poly b)
{
    for (unsigned i = 0; i < N; i++)
        r[i] = subq(a[i], b[i]);
}

/* ------------------------------------------------------------------------ */
/* Encoding / compression (Alg. 5, 6 and Sec. 4.2.1)                        */
/* ------------------------------------------------------------------------ */
static void byte_encode(uint8_t *out, const poly f, int d)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (unsigned i = 0; i < N; i++) {
        acc |= (uint32_t)f[i] << bits;
        bits += d;
        while (bits >= 8) {
            out[o++] = (uint8_t)acc;
            acc >>= 8;
            bits -= 8;
        }
    }
}

/* for d == 12 the result is reduced mod q (per FIPS 203) */
static void byte_decode(poly f, const uint8_t *in, int d)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    const uint32_t mask = (1u << d) - 1;
    for (unsigned i = 0; i < N; i++) {
        while (bits < d) {
            acc |= (uint32_t)in[o++] << bits;
            bits += 8;
        }
        uint32_t v = acc & mask;
        f[i] = (d == 12) ? barrett(v) : (uint16_t)v;
        acc >>= d;
        bits -= d;
    }
}

/* round(2^d / q * x) mod 2^d ; q is odd so rounding is exact with +floor(q/2) */
static inline uint16_t compress(uint16_t x, int d)
{
    uint32_t t = (((uint32_t)x << d) + (Q / 2)) / Q;
    return (uint16_t)(t & ((1u << d) - 1));
}
/* round(q / 2^d * y) */
static inline uint16_t decompress(uint16_t y, int d)
{
    return (uint16_t)(((uint32_t)y * Q + (1u << (d - 1))) >> d);
}

static void poly_compress(uint8_t *out, const poly a, int d)
{
    poly t;
    for (unsigned i = 0; i < N; i++)
        t[i] = compress(a[i], d);
    byte_encode(out, t, d);
}
static void poly_decompress(poly r, const uint8_t *in, int d)
{
    byte_decode(r, in, d);
    for (unsigned i = 0; i < N; i++)
        r[i] = decompress(r[i], d);
}

/* message <-> polynomial (Compress_1 / Decompress_1 on bit strings) */
static void poly_frommsg(poly r, const uint8_t m[32])
{
    for (unsigned i = 0; i < N; i++) {
        uint16_t bit = (m[i >> 3] >> (i & 7)) & 1;
        r[i] = (uint16_t)((0u - bit) & ((Q + 1) / 2)); /* 1665 */
    }
}
static void poly_tomsg(uint8_t m[32], const poly a)
{
    memset(m, 0, 32);
    for (unsigned i = 0; i < N; i++)
        m[i >> 3] |= (uint8_t)(compress(a[i], 1) << (i & 7));
}

/* ------------------------------------------------------------------------ */
/* Sampling (Alg. 7, 8)                                                     */
/* ------------------------------------------------------------------------ */
static void sample_ntt(poly a, const uint8_t rho[32], uint8_t x, uint8_t y)
{
    keccak_ctx c;
    uint8_t in[34], buf[SHAKE128_RATE];
    memcpy(in, rho, 32);
    in[32] = x;
    in[33] = y;
    keccak_init(&c, SHAKE128_RATE, 0x1f);
    keccak_absorb(&c, in, 34);
    keccak_finalize(&c);

    unsigned n = 0;
    while (n < N) {
        keccak_squeeze(&c, buf, sizeof buf);
        for (unsigned k = 0; k + 3 <= sizeof buf && n < N; k += 3) {
            uint16_t d1 = (uint16_t)(buf[k] | ((buf[k + 1] & 0x0f) << 8));
            uint16_t d2 = (uint16_t)((buf[k + 1] >> 4) | (buf[k + 2] << 4));
            if (d1 < Q)
                a[n++] = d1;
            if (d2 < Q && n < N)
                a[n++] = d2;
        }
    }
}

/* a[i*KMAX + j] = A_hat[i][j] = SampleNTT(rho, j, i); transposed stores A^T. */
void mlkem_gen_matrix(uint16_t (*a)[N], const uint8_t rho[32], int k,
                      int transposed)
{
    for (int i = 0; i < k; i++)
        for (int j = 0; j < k; j++) {
            if (transposed)
                sample_ntt(a[j * KMAX + i], rho, (uint8_t)j, (uint8_t)i);
            else
                sample_ntt(a[i * KMAX + j], rho, (uint8_t)j, (uint8_t)i);
        }
}

static inline uint16_t cbd_fix(int a, int b)
{
    int32_t v = a - b;
    return (uint16_t)(v + (smask(v) & Q));
}

static void cbd(poly r, const uint8_t *buf, int eta)
{
    if (eta == 2) {
        for (unsigned i = 0; i < N / 8; i++) {
            uint32_t t = load32(buf + 4 * i);
            uint32_t d = (t & 0x55555555u) + ((t >> 1) & 0x55555555u);
            for (unsigned j = 0; j < 8; j++) {
                int a = (int)((d >> (4 * j)) & 3);
                int b = (int)((d >> (4 * j + 2)) & 3);
                r[8 * i + j] = cbd_fix(a, b);
            }
        }
    } else { /* eta == 3 */
        for (unsigned i = 0; i < N / 4; i++) {
            uint32_t t = (uint32_t)buf[3 * i] | ((uint32_t)buf[3 * i + 1] << 8) |
                         ((uint32_t)buf[3 * i + 2] << 16);
            uint32_t d = (t & 0x249249u) + ((t >> 1) & 0x249249u) +
                         ((t >> 2) & 0x249249u);
            for (unsigned j = 0; j < 4; j++) {
                int a = (int)((d >> (6 * j)) & 7);
                int b = (int)((d >> (6 * j + 3)) & 7);
                r[4 * i + j] = cbd_fix(a, b);
            }
        }
    }
}

/* PRF_eta(s, b) = SHAKE256(s || b, 64*eta), then SamplePolyCBD_eta */
static void prf_cbd(poly r, const uint8_t sigma[32], uint8_t nonce, int eta)
{
    uint8_t in[33], buf[64 * 3];
    memcpy(in, sigma, 32);
    in[32] = nonce;
    shake256(buf, (size_t)(64 * eta), in, sizeof in);
    cbd(r, buf, eta);
    mlkem_cleanse(buf, sizeof buf);
}

/* ------------------------------------------------------------------------ */
/* K-PKE (Alg. 13, 14, 15)                                                  */
/* ------------------------------------------------------------------------ */
static void kpke_keygen(const mlkem_params *p, uint8_t *ek_pke,
                        uint8_t *dk_pke, const uint8_t d[32])
{
    const int k = p->k;
    uint8_t in[33], g[64];
    poly A[KMAX * KMAX], s[KMAX], e[KMAX], t;

    memcpy(in, d, 32);
    in[32] = (uint8_t)k;
    sha3_512(g, in, sizeof in); /* (rho, sigma) = G(d || k) */
    const uint8_t *rho = g, *sigma = g + 32;

    mlkem_gen_matrix(A, rho, k, 0);

    uint8_t nonce = 0;
    for (int i = 0; i < k; i++)
        prf_cbd(s[i], sigma, nonce++, p->eta1);
    for (int i = 0; i < k; i++)
        prf_cbd(e[i], sigma, nonce++, p->eta1);
    for (int i = 0; i < k; i++) {
        mlkem_ntt(s[i]);
        mlkem_ntt(e[i]);
    }

    for (int i = 0; i < k; i++) {
        polyvec_basemul_acc(t, (const poly *)&A[i * KMAX], (const poly *)s, k);
        poly_add(t, t, e[i]);
        byte_encode(ek_pke + POLYBYTES * i, t, 12);
        byte_encode(dk_pke + POLYBYTES * i, s[i], 12);
    }
    memcpy(ek_pke + POLYBYTES * k, rho, 32);

    mlkem_cleanse(g, sizeof g);
    mlkem_cleanse(s, sizeof s);
    mlkem_cleanse(e, sizeof e);
}

static void kpke_encrypt(const mlkem_params *p, uint8_t *c,
                         const uint8_t *ek_pke, const uint8_t m[32],
                         const uint8_t r[32])
{
    const int k = p->k;
    poly AT[KMAX * KMAX], that[KMAX], y[KMAX], e1[KMAX], u[KMAX], e2, v, mu;

    for (int i = 0; i < k; i++)
        byte_decode(that[i], ek_pke + POLYBYTES * i, 12);
    mlkem_gen_matrix(AT, ek_pke + POLYBYTES * k, k, 1);

    uint8_t nonce = 0;
    for (int i = 0; i < k; i++)
        prf_cbd(y[i], r, nonce++, p->eta1);
    for (int i = 0; i < k; i++)
        prf_cbd(e1[i], r, nonce++, p->eta2);
    prf_cbd(e2, r, nonce, p->eta2);

    for (int i = 0; i < k; i++)
        mlkem_ntt(y[i]);

    for (int i = 0; i < k; i++) {
        polyvec_basemul_acc(u[i], (const poly *)&AT[i * KMAX], (const poly *)y, k);
        mlkem_invntt(u[i]);
        poly_add(u[i], u[i], e1[i]);
    }
    polyvec_basemul_acc(v, (const poly *)that, (const poly *)y, k);
    mlkem_invntt(v);
    poly_add(v, v, e2);
    poly_frommsg(mu, m);
    poly_add(v, v, mu);

    for (int i = 0; i < k; i++)
        poly_compress(c + 32 * p->du * i, u[i], p->du);
    poly_compress(c + 32 * p->du * k, v, p->dv);

    mlkem_cleanse(y, sizeof y);
    mlkem_cleanse(e1, sizeof e1);
    mlkem_cleanse(e2, sizeof e2);
    mlkem_cleanse(mu, sizeof mu);
}

static void kpke_decrypt(const mlkem_params *p, uint8_t m[32],
                         const uint8_t *dk_pke, const uint8_t *c)
{
    const int k = p->k;
    poly u[KMAX], shat[KMAX], v, w;

    for (int i = 0; i < k; i++) {
        poly_decompress(u[i], c + 32 * p->du * i, p->du);
        mlkem_ntt(u[i]);
        byte_decode(shat[i], dk_pke + POLYBYTES * i, 12);
    }
    poly_decompress(v, c + 32 * p->du * k, p->dv);

    polyvec_basemul_acc(w, (const poly *)shat, (const poly *)u, k);
    mlkem_invntt(w);
    poly_sub(w, v, w);
    poly_tomsg(m, w);

    mlkem_cleanse(shat, sizeof shat);
    mlkem_cleanse(w, sizeof w);
}

/* ------------------------------------------------------------------------ */
/* ML-KEM with the Fujisaki-Okamoto transform (Alg. 16, 17, 18)             */
/* ------------------------------------------------------------------------ */

/* Type check of ek (FIPS 203 Sec. 7.2): ByteEncode12(ByteDecode12(t)) == t. */
static int check_ek(const mlkem_params *p, const uint8_t *ek)
{
    uint8_t tmp[POLYBYTES];
    poly f;
    for (int i = 0; i < p->k; i++) {
        byte_decode(f, ek + POLYBYTES * i, 12);
        byte_encode(tmp, f, 12);
        if (memcmp(tmp, ek + POLYBYTES * i, POLYBYTES) != 0)
            return -1;
    }
    return 0;
}

int mlkem_keygen_derand(const mlkem_params *p, uint8_t *ek, uint8_t *dk,
                        const uint8_t coins[64])
{
    const size_t kb = (size_t)POLYBYTES * (size_t)p->k;
    /* 1. (ek, s) <- PKE.KeyGen(d) ; dk = (s, ek, H(ek), z) */
    kpke_keygen(p, ek, dk, coins);
    memcpy(dk + kb, ek, p->ek_bytes);
    sha3_256(dk + kb + p->ek_bytes, ek, p->ek_bytes);
    memcpy(dk + kb + p->ek_bytes + 32, coins + 32, 32);
    return 0;
}

int mlkem_keygen(const mlkem_params *p, uint8_t *ek, uint8_t *dk)
{
    uint8_t coins[64];
    if (mlkem_randombytes(coins, sizeof coins) != 0)
        return -1;
    int rc = mlkem_keygen_derand(p, ek, dk, coins);
    mlkem_cleanse(coins, sizeof coins);
    return rc;
}

int mlkem_encaps_derand(const mlkem_params *p, uint8_t *ct, uint8_t *ss,
                        const uint8_t *ek, const uint8_t m[32])
{
    uint8_t buf[64], kr[64];
    if (check_ek(p, ek) != 0)
        return -1;
    /* 2. (K, R) = G(m || H(ek)) ; c = PKE.Enc(ek, m; R) */
    memcpy(buf, m, 32);
    sha3_256(buf + 32, ek, p->ek_bytes);
    sha3_512(kr, buf, sizeof buf);
    kpke_encrypt(p, ct, ek, m, kr + 32);
    memcpy(ss, kr, MLKEM_SSBYTES);
    mlkem_cleanse(buf, sizeof buf);
    mlkem_cleanse(kr, sizeof kr);
    return 0;
}

int mlkem_encaps(const mlkem_params *p, uint8_t *ct, uint8_t *ss,
                 const uint8_t *ek)
{
    uint8_t m[32];
    if (mlkem_randombytes(m, sizeof m) != 0)
        return -1;
    int rc = mlkem_encaps_derand(p, ct, ss, ek, m);
    mlkem_cleanse(m, sizeof m);
    return rc;
}

int mlkem_decaps(const mlkem_params *p, uint8_t *ss, const uint8_t *ct,
                 const uint8_t *dk)
{
    const size_t kb = (size_t)POLYBYTES * (size_t)p->k;
    const uint8_t *dk_pke = dk;
    const uint8_t *ek = dk + kb;
    const uint8_t *h = ek + p->ek_bytes;
    const uint8_t *z = h + 32;

#ifndef MLKEM_SKIP_DK_CHECK
    { /* FIPS 203 Sec. 7.3: hash check of the embedded ek */
        uint8_t hh[32];
        sha3_256(hh, ek, p->ek_bytes);
        if (memcmp(hh, h, 32) != 0)
            return -1;
    }
#endif

    uint8_t m[32], buf[64], kr[64], kbar[32], ct2[MLKEM_MAX_CT_BYTES];

    /* 3. m' = PKE.Dec(s, c) ; (K', R') = G(m' || h) */
    kpke_decrypt(p, m, dk_pke, ct);
    memcpy(buf, m, 32);
    memcpy(buf + 32, h, 32);
    sha3_512(kr, buf, sizeof buf);

    /* Kbar = J(z || c) = SHAKE256(z || c, 32)  (implicit-rejection key) */
    {
        keccak_ctx c;
        keccak_init(&c, SHAKE256_RATE, 0x1f);
        keccak_absorb(&c, z, 32);
        keccak_absorb(&c, ct, p->ct_bytes);
        keccak_finalize(&c);
        keccak_squeeze(&c, kbar, sizeof kbar);
    }

    /* c' = PKE.Enc(ek, m'; R') ; re-encryption check, constant time */
    kpke_encrypt(p, ct2, ek, m, kr + 32);
    int fail = ct_ne(ct, ct2, p->ct_bytes);
    ct_cmov(kr, kbar, 32, fail); /* c != c' -> return Kbar, else K' */
    memcpy(ss, kr, MLKEM_SSBYTES);

    mlkem_cleanse(m, sizeof m);
    mlkem_cleanse(buf, sizeof buf);
    mlkem_cleanse(kr, sizeof kr);
    mlkem_cleanse(kbar, sizeof kbar);
    return 0;
}

/* Written with assistance from Claude (Anthropic) - model: Claude Sonnet 5.5, Nov 2026. */
