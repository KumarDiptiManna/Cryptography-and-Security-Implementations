#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>   // for __rdtsc()

#define SBOX_SIZE 256

typedef struct {
    unsigned char S[SBOX_SIZE];
    unsigned char i, j;
} RC4_CTX;

/* Key Scheduling Algorithm (KSA) */
void rc4_ksa(RC4_CTX *ctx, const unsigned char *key, size_t keylen)
{
    int idx;

    for (idx = 0; idx < SBOX_SIZE; idx++)
        ctx->S[idx] = (unsigned char)idx;

    unsigned char j = 0;

    for (idx = 0; idx < SBOX_SIZE; idx++)
    {
        j += ctx->S[idx] + key[idx % keylen];

        unsigned char tmp = ctx->S[idx];
        ctx->S[idx] = ctx->S[j];
        ctx->S[j] = tmp;
    }

    ctx->i = 0;
    ctx->j = 0;
}

/* Pseudo-Random Generation Algorithm (PRGA) */
void rc4_prga(RC4_CTX *ctx, unsigned char *out, size_t len)
{
    unsigned char i = ctx->i;
    unsigned char j = ctx->j;

    for (size_t n = 0; n < len; n++)
    {
        i++;
        j += ctx->S[i];

        unsigned char tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;

        unsigned char t = ctx->S[i] + ctx->S[j];
        out[n] = ctx->S[t];
    }

    ctx->i = i;
    ctx->j = j;
}

int main(void)
{
    // RFC 6229 test vector (56‑bit key)
    unsigned char key[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    size_t keylen = sizeof(key);

    RC4_CTX ctx;

    unsigned long long start, end;

    /* ===========================
       Benchmark KSA
       =========================== */

    start = __rdtsc();

    rc4_ksa(&ctx, key, keylen);

    end = __rdtsc();

    unsigned long long ksa_cycles = end - start;

    double ksa_cycles_per_iteration =
        (double)ksa_cycles / SBOX_SIZE;

    printf("========================================\n");
    printf("RC4 Performance Benchmark\n");
    printf("========================================\n\n");

    printf("KSA Total Cycles          : %llu\n", ksa_cycles);
    printf("KSA Cycles / Iteration    : %.2f\n\n",
           ksa_cycles_per_iteration);

    /* ===========================
       Benchmark PRGA
       =========================== */

    const size_t PRGA_LEN = 1000000;

    unsigned char *output = (unsigned char *)malloc(PRGA_LEN);

    if (output == NULL)
    {
        fprintf(stderr, "Memory allocation failed!\n");
        return 1;
    }

    start = __rdtsc();

    rc4_prga(&ctx, output, PRGA_LEN);

    end = __rdtsc();

    unsigned long long prga_cycles = end - start;

    double prga_cycles_per_byte =
        (double)prga_cycles / PRGA_LEN;

    printf("PRGA Total Cycles         : %llu\n", prga_cycles);
    printf("PRGA Cycles / Byte        : %.2f\n\n",
           prga_cycles_per_byte);

    /* Prevent compiler optimization */
    volatile unsigned char checksum = 0;

    for (size_t i = 0; i < PRGA_LEN; i += 1024)
        checksum ^= output[i];

    printf("Checksum                  : %u\n", checksum);

    free(output);

    return 0;
}

/*
========================================
RC4 Performance Benchmark
========================================

KSA Total Cycles          : 1662
KSA Cycles / Iteration    : 6.49

PRGA Total Cycles         : 6270402
PRGA Cycles / Byte        : 6.27

Checksum                  : 7
*/

//gcc -O2 -march=native -o rc4 rc4.c