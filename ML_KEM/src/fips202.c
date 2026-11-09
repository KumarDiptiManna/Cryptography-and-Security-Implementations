/*
 * fips202.c - compact, endian-independent SHA-3 / SHAKE implementation.
 * Keccak-f[1600] follows the usual "compact" formulation (theta, rho+pi, chi, iota).
 */
#include "fips202.h"

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

static const unsigned KECCAK_ROTC[24] = {1,  3,  6,  10, 15, 21, 28, 36,
                                         45, 55, 2,  14, 27, 41, 56, 8,
                                         25, 43, 62, 18, 39, 61, 20, 44};
static const unsigned KECCAK_PILN[24] = {10, 7,  11, 17, 18, 3, 5,  16,
                                         8,  21, 24, 4,  15, 23, 19, 13,
                                         12, 2,  20, 14, 22, 9,  6,  1};

void keccak_f1600(uint64_t st[25])
{
    uint64_t bc[5], t;
    for (int r = 0; r < 24; r++) {
        /* theta */
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }
        /* rho + pi */
        t = st[1];
        for (int i = 0; i < 24; i++) {
            unsigned j = KECCAK_PILN[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, KECCAK_ROTC[i]);
            t = bc[0];
        }
        /* chi */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        /* iota */
        st[0] ^= KECCAK_RC[r];
    }
}

/* Little-endian lane access, independent of host byte order. */
static inline uint64_t load64(const uint8_t *x)
{
    uint64_t r = 0;
    for (int i = 0; i < 8; i++)
        r |= (uint64_t)x[i] << (8 * i);
    return r;
}
static inline void store64(uint8_t *x, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        x[i] = (uint8_t)(v >> (8 * i));
}
static inline void xor_byte(uint64_t *s, unsigned i, uint8_t b)
{
    s[i >> 3] ^= (uint64_t)b << (8 * (i & 7));
}
static inline uint8_t get_byte(const uint64_t *s, unsigned i)
{
    return (uint8_t)(s[i >> 3] >> (8 * (i & 7)));
}

void keccak_init(keccak_ctx *c, unsigned rate, uint8_t ds)
{
    for (int i = 0; i < 25; i++)
        c->s[i] = 0;
    c->pos = 0;
    c->rate = rate;
    c->ds = ds;
}

void keccak_absorb(keccak_ctx *c, const uint8_t *in, size_t len)
{
    while (len) {
        if ((c->pos & 7) == 0 && len >= 8) {
            c->s[c->pos >> 3] ^= load64(in);
            in += 8;
            len -= 8;
            c->pos += 8;
        } else {
            xor_byte(c->s, c->pos, *in++);
            len--;
            c->pos++;
        }
        if (c->pos == c->rate) {
            keccak_f1600(c->s);
            c->pos = 0;
        }
    }
}

void keccak_finalize(keccak_ctx *c)
{
    xor_byte(c->s, c->pos, c->ds);
    xor_byte(c->s, c->rate - 1, 0x80);
    keccak_f1600(c->s);
    c->pos = 0;
}

void keccak_squeeze(keccak_ctx *c, uint8_t *out, size_t len)
{
    while (len) {
        if (c->pos == c->rate) {
            keccak_f1600(c->s);
            c->pos = 0;
        }
        if ((c->pos & 7) == 0 && len >= 8) {
            store64(out, c->s[c->pos >> 3]);
            out += 8;
            len -= 8;
            c->pos += 8;
        } else {
            *out++ = get_byte(c->s, c->pos);
            len--;
            c->pos++;
        }
    }
}

static void hash_oneshot(uint8_t *out, size_t outlen, const uint8_t *in,
                         size_t inlen, unsigned rate, uint8_t ds)
{
    keccak_ctx c;
    keccak_init(&c, rate, ds);
    keccak_absorb(&c, in, inlen);
    keccak_finalize(&c);
    keccak_squeeze(&c, out, outlen);
}

void sha3_256(uint8_t out[32], const uint8_t *in, size_t n)
{
    hash_oneshot(out, 32, in, n, SHA3_256_RATE, 0x06);
}
void sha3_512(uint8_t out[64], const uint8_t *in, size_t n)
{
    hash_oneshot(out, 64, in, n, SHA3_512_RATE, 0x06);
}
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t n)
{
    hash_oneshot(out, outlen, in, n, SHAKE128_RATE, 0x1f);
}
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t n)
{
    hash_oneshot(out, outlen, in, n, SHAKE256_RATE, 0x1f);
}

/* Written with assistance from Claude (Anthropic) - model: Claude Sonnet 5.5, Nov 2026. */
