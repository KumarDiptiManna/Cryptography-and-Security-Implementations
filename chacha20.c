/*
 * ChaCha20 implementation in C
 * Based on the public domain design by Daniel J. Bernstein (djb)
 * Specification: https://cr.yp.to/chacha/chacha-20080128.pdf
 * RFC 8439: https://www.rfc-editor.org/info/rfc8439/
 * IETF variant: 96-bit nonce and 32-bit block counter
 * This implementation follows the RFC 8439 variant.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>
#endif

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

/* The ChaCha quarter-round operation */
static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

/* Serialize a 32-bit word into little-endian bytes */
static void store32_le(uint8_t *dst, uint32_t w)
{
    dst[0] = (uint8_t)(w);
    dst[1] = (uint8_t)(w >> 8);
    dst[2] = (uint8_t)(w >> 16);
    dst[3] = (uint8_t)(w >> 24);
}

/* Load 4 little-endian bytes into a 32-bit word */
static uint32_t load32_le(const uint8_t *src)
{
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

/*
 * Generating one 64-byte keystream block.
 *
 * key:     32 bytes (256-bit key)
 * counter: 32-bit block counter
 * nonce:   12 bytes (96-bit nonce, per RFC 8439)
 * out:     64-byte output buffer for the keystream block
 */
static void chacha20_block(const uint8_t key[32],
                            uint32_t counter,
                            const uint8_t nonce[12],
                            uint8_t out[64])
{
    /* ChaCha20 constants: "expand 32-byte k" in little-endian words */
    static const uint32_t constants[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    uint32_t state[16];
    uint32_t working[16];
    int i;

    /* Initialize state: constants || key || counter || nonce */
    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];

    for (i = 0; i < 8; i++)
        state[4 + i] = load32_le(key + 4 * i);

    state[12] = counter;

    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    memcpy(working, state, sizeof(state));

    /* 20 rounds = 10 double-rounds (column round + diagonal round) */
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        quarter_round(&working[0], &working[4], &working[8],  &working[12]);
        quarter_round(&working[1], &working[5], &working[9],  &working[13]);
        quarter_round(&working[2], &working[6], &working[10], &working[14]);
        quarter_round(&working[3], &working[7], &working[11], &working[15]);

        /* Diagonal rounds */
        quarter_round(&working[0], &working[5], &working[10], &working[15]);
        quarter_round(&working[1], &working[6], &working[11], &working[12]);
        quarter_round(&working[2], &working[7], &working[8],  &working[13]);
        quarter_round(&working[3], &working[4], &working[9],  &working[14]);
    }

    /* Add the original state back in */
    for (i = 0; i < 16; i++)
        working[i] += state[i];

    /* Serialize to bytes (little-endian) */
    for (i = 0; i < 16; i++)
        store32_le(out + 4 * i, working[i]);
}

/*
 * Encrypt (or decrypt, since XOR is symmetric) a buffer using ChaCha20.
 *
 * key:            32-byte key
 * nonce:          12-byte nonce
 * counter:        initial block counter (usually 0 or 1 depending on convention)
 * in:             input buffer (plaintext or ciphertext)
 * out:            output buffer (same length as input)
 * len:            length of the buffer in bytes
 */
void chacha20_xor(const uint8_t key[32],
                   const uint8_t nonce[12],
                   uint32_t counter,
                   const uint8_t *in,
                   uint8_t *out,
                   size_t len)
{
    uint8_t keystream[64];
    size_t i;

    while (len > 0) {
        chacha20_block(key, counter, nonce, keystream);
        counter++;

        size_t block_len = (len < 64) ? len : 64;

        for (i = 0; i < block_len; i++)
            out[i] = in[i] ^ keystream[i];

        in += block_len;
        out += block_len;
        len -= block_len;
    }
}

/* --------------------- Demo / test driver --------------------- */

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

/*
 * Portable wall-clock timestamp in seconds.
 * Uses QueryPerformanceCounter on Windows, clock_gettime elsewhere.
 */
static double wall_time_seconds(void)
{
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    static int have_freq = 0;
    LARGE_INTEGER now;
    if (!have_freq) {
        QueryPerformanceFrequency(&freq);
        have_freq = 1;
    }
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#endif
}

/*
 * Benchmark ChaCha20 performance two ways:
 *   1. Block-level cycle counting via rdtsc (isolates the permutation core,
 *      excludes XOR/memcpy overhead). x86/x64 only.
 *   2. Wall-clock throughput over a large buffer via chacha20_xor()
 *      (reflects real-world encrypt/decrypt speed, works on any platform).
 */
static void benchmark(void)
{
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};

    /* ---- 1. Block-level cycle count (rdtsc) ---- */
#if defined(__x86_64__) || defined(__i386__)
    {
        uint8_t block[64];
        const int ITERS = 100000;

        /* Warm up: settle branch predictor, caches, CPU frequency scaling */
        for (int i = 0; i < 1000; i++)
            chacha20_block(key, (uint32_t)i, nonce, block);

        double wt0 = wall_time_seconds();
        uint64_t start = __rdtsc();
        for (int i = 0; i < ITERS; i++)
            chacha20_block(key, (uint32_t)i, nonce, block);
        uint64_t end = __rdtsc();
        double wt1 = wall_time_seconds();

        uint64_t total_cycles = end - start;
        double exec_seconds = wt1 - wt0;
        printf("\n--- Block-level cycle count (rdtsc) ---\n");
        printf("Blocks processed: %d\n", ITERS);
        printf("Execution time:   %.6f s\n", exec_seconds);
        printf("Total cycles:     %" PRIu64 "\n", total_cycles);
        printf("Cycles per block: %.1f\n", (double)total_cycles / ITERS);
        printf("Cycles per byte:  %.2f\n", (double)total_cycles / (ITERS * 64));
    }
#else
    printf("\n--- Block-level cycle count (rdtsc) ---\n");
    printf("rdtsc unavailable on this platform (non-x86)\n");
#endif

    /* ---- 2. Wall-clock throughput over a large buffer ---- */
    {
        size_t len = 1 << 20;      /* 1 MiB per iteration */
        int iterations = 200;

        uint8_t *in  = malloc(len);
        uint8_t *out = malloc(len);
        if (!in || !out) {
            fprintf(stderr, "benchmark: allocation failed\n");
            free(in);
            free(out);
            return;
        }
        memset(in, 0xAB, len);

        /* Warm up */
        chacha20_xor(key, nonce, 0, in, out, len);

        double t0 = wall_time_seconds();
        for (int i = 0; i < iterations; i++)
            chacha20_xor(key, nonce, 0, in, out, len);
        double t1 = wall_time_seconds();

        double seconds = t1 - t0;
        double total_bytes = (double)len * iterations;

        printf("\n--- Wall-clock throughput (chacha20_xor) ---\n");
        printf("Bytes processed: %.0f\n", total_bytes);
        printf("Execution time:  %.6f s\n", seconds);
        printf("Throughput:      %.2f MiB/s\n",
               (total_bytes / (1024.0 * 1024.0)) / seconds);

        free(in);
        free(out);
    }
}

int main(void)
{
    /* RFC 8439 Section 2.4.2 test vector */
    uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };

    uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00
    };

    uint32_t counter = 1;

    const char *plaintext =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";

    size_t len = strlen(plaintext);
    uint8_t ciphertext[256];
    uint8_t decrypted[256];

    chacha20_xor(key, nonce, counter, (const uint8_t *)plaintext, ciphertext, len);
    chacha20_xor(key, nonce, counter, ciphertext, decrypted, len);

    printf("Plaintext:  %s\n", plaintext);
    print_hex("Ciphertext", ciphertext, len);
    printf("Decrypted:  %.*s\n", (int)len, decrypted);

    benchmark();

    return 0;
}

// compile : gcc -O2 -Wall -Wextra -o chacha20 chacha20.c

 /*
 * Developed with assistance from Claude (Anthropic, https://claude.ai)
 * for implementation, debugging, and performance analysis.
 */