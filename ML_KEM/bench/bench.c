/*
 * bench.c - benchmark harness for the C ML-KEM implementation.
 *
 * Methodology
 *   - Each operation is timed per call (batched for very short primitives)
 *     with CLOCK_MONOTONIC; on x86 the TSC is read alongside (ticks ~ cycles at
 *     the nominal frequency, NOT at turbo frequency).
 *   - Warm-up iterations are discarded; S samples are collected.
 *   - Reported: min, median, mean, stddev, 95th percentile (all per op).
 *     The MEDIAN is the headline number (robust against scheduler noise);
 *     MIN is the best-case "undisturbed" figure.
 *   - Timer overhead is calibrated and printed.
 *   - Randomness is excluded: the *_derand entry points are timed, with
 *     inputs changed on every call.
 *   - "decaps (invalid ct)" exercises the implicit-rejection path; it should
 *     cost the same as a valid decaps (constant-time behaviour sanity check).
 *
 * Usage: ./bench_mlkem [-n samples] [-w warmup] [--level 512|768|1024]
 *                      [--pin cpu] [--csv file]
 */
#define _GNU_SOURCE
#include "fips202.h"
#include "mlkem.h"
#include "mlkem_internal.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <sched.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#define HAVE_TSC 1
static inline uint64_t tsc(void) { return __rdtsc(); }
#else
#define HAVE_TSC 0
static inline uint64_t tsc(void) { return 0; }
#endif

#ifndef BUILD_FLAGS
#define BUILD_FLAGS "unknown"
#endif

static volatile uint8_t sink;

static inline double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* ---------------------------------------------------------------------- */
typedef struct {
    double min, median, mean, stddev, p95;
} stats_t;

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static stats_t compute_stats(const double *v, int n)
{
    double *s = malloc((size_t)n * sizeof *s);
    memcpy(s, v, (size_t)n * sizeof *s);
    qsort(s, (size_t)n, sizeof *s, cmp_d);
    stats_t r;
    r.min = s[0];
    r.median = (n & 1) ? s[n / 2] : 0.5 * (s[n / 2 - 1] + s[n / 2]);
    r.p95 = s[(int)(0.95 * (n - 1))];
    double sum = 0;
    for (int i = 0; i < n; i++)
        sum += s[i];
    r.mean = sum / n;
    double var = 0;
    for (int i = 0; i < n; i++)
        var += (s[i] - r.mean) * (s[i] - r.mean);
    r.stddev = n > 1 ? sqrt(var / (n - 1)) : 0;
    free(s);
    return r;
}

/* ---------------------------------------------------------------------- */
typedef void (*bench_fn)(void *ctx);

typedef struct {
    stats_t ns, cyc;
} result_t;

static result_t measure(bench_fn fn, void *ctx, int samples, int warmup, int batch)
{
    double *ns = malloc((size_t)samples * sizeof *ns);
    double *cy = malloc((size_t)samples * sizeof *cy);
    for (int i = 0; i < warmup; i++)
        fn(ctx);
    for (int i = 0; i < samples; i++) {
        uint64_t c0 = tsc();
        double t0 = now_ns();
        for (int b = 0; b < batch; b++)
            fn(ctx);
        double t1 = now_ns();
        uint64_t c1 = tsc();
        ns[i] = (t1 - t0) / batch;
        cy[i] = (double)(c1 - c0) / batch;
    }
    result_t r;
    r.ns = compute_stats(ns, samples);
    r.cyc = compute_stats(cy, samples);
    free(ns);
    free(cy);
    return r;
}

/* ---------------------------------------------------------------------- */
typedef struct {
    const mlkem_params *p;
    uint8_t ek[MLKEM_MAX_EK_BYTES], dk[MLKEM_MAX_DK_BYTES];
    uint8_t ct[MLKEM_MAX_CT_BYTES], badct[MLKEM_MAX_CT_BYTES];
    uint8_t ss[32], m[32], coins[64];
    uint16_t poly[256];
    uint16_t A[16][256];
    uint8_t rho[32];
    uint64_t kst[25];
} ctx_t;

static void b_keygen(void *v)
{
    ctx_t *c = v;
    c->coins[0]++;
    mlkem_keygen_derand(c->p, c->ek, c->dk, c->coins);
    sink ^= c->ek[0];
}
static void b_encaps(void *v)
{
    ctx_t *c = v;
    c->m[0]++;
    mlkem_encaps_derand(c->p, c->ct, c->ss, c->ek, c->m);
    sink ^= c->ss[0];
}
static void b_decaps(void *v)
{
    ctx_t *c = v;
    mlkem_decaps(c->p, c->ss, c->ct, c->dk);
    sink ^= c->ss[0];
}
static void b_decaps_bad(void *v)
{
    ctx_t *c = v;
    mlkem_decaps(c->p, c->ss, c->badct, c->dk);
    sink ^= c->ss[0];
}
static void b_keccak(void *v)
{
    ctx_t *c = v;
    keccak_f1600(c->kst);
    sink ^= (uint8_t)c->kst[0];
}
static void b_ntt(void *v)
{
    ctx_t *c = v;
    mlkem_ntt(c->poly);
    sink ^= (uint8_t)c->poly[0];
}
static void b_invntt(void *v)
{
    ctx_t *c = v;
    mlkem_invntt(c->poly);
    sink ^= (uint8_t)c->poly[0];
}
static void b_matrix(void *v)
{
    ctx_t *c = v;
    c->rho[0]++;
    mlkem_gen_matrix(c->A, c->rho, c->p->k, 0);
    sink ^= (uint8_t)c->A[0][0];
}

/* ---------------------------------------------------------------------- */
static void cpu_info(void)
{
    char line[256];
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        while (fgets(line, sizeof line, f))
            if (!strncmp(line, "model name", 10)) {
                char *p = strchr(line, ':');
                if (p) printf("CPU        :%s", p + 1);
                break;
            }
        fclose(f);
    }
    f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
    if (f) {
        if (fgets(line, sizeof line, f))
            printf("Governor   : %s", line);
        fclose(f);
    }
}

static void usage(void)
{
    puts("usage: bench_mlkem [-n samples] [-w warmup] [--level 512|768|1024] [--pin cpu] [--csv file]");
}

#define PRINT_HDR()                                                                   \
    printf("%-26s %10s %10s %10s %10s %10s %12s %12s\n", "operation", "median(us)",  \
           "mean(us)", "min(us)", "stddev", "p95(us)", "ops/s(med)", HAVE_TSC ? "cycles(med)" : "cycles")

static void report(FILE *csv, const char *scheme, const char *op, int samples, result_t r)
{
    printf("%-26s %10.2f %10.2f %10.2f %10.2f %10.2f %12.0f ", op, r.ns.median / 1e3,
           r.ns.mean / 1e3, r.ns.min / 1e3, r.ns.stddev / 1e3, r.ns.p95 / 1e3,
           1e9 / r.ns.median);
    if (HAVE_TSC)
        printf("%12.0f\n", r.cyc.median);
    else
        printf("%12s\n", "n/a");
    if (csv)
        fprintf(csv, "%s,%s,%d,%.1f,%.1f,%.1f,%.1f,%.1f,%.0f\n", scheme, op, samples,
                r.ns.min, r.ns.median, r.ns.mean, r.ns.stddev, r.ns.p95, r.cyc.median);
}

int main(int argc, char **argv)
{
    int samples = 5000, warmup = 300, level = 0, pin = -1;
    const char *csvpath = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-n") && i + 1 < argc) samples = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) warmup = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--level") && i + 1 < argc) level = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--pin") && i + 1 < argc) pin = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) csvpath = argv[++i];
        else { usage(); return 1; }
    }
    if (samples < 10) samples = 10;

#if defined(__linux__)
    if (pin >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(pin, &set);
        if (sched_setaffinity(0, sizeof set, &set) != 0)
            perror("sched_setaffinity");
    }
#else
    (void)pin;
#endif

    /* timer overhead */
    double *tov = malloc(1000 * sizeof *tov);
    for (int i = 0; i < 1000; i++) {
        double a = now_ns(), b = now_ns();
        tov[i] = b - a;
    }
    stats_t to = compute_stats(tov, 1000);
    free(tov);

    printf("ML-KEM (Kyber) C benchmark\n");
    printf("==========================\n");
    cpu_info();
    printf("Compiler   : %s\n", __VERSION__);
    printf("Build      : %s\n", BUILD_FLAGS);
    printf("Samples    : %d (warm-up %d)%s\n", samples, warmup, pin >= 0 ? "  [pinned]" : "");
    printf("Timer      : clock_gettime(MONOTONIC), overhead ~%.0f ns/call pair (median)\n", to.median);
    printf("Cycles     : %s\n\n", HAVE_TSC ? "x86 TSC ticks (nominal clock, not turbo)" : "not available on this arch");

    FILE *csv = NULL;
    if (csvpath) {
        csv = fopen(csvpath, "w");
        if (csv) fprintf(csv, "scheme,op,samples,min_ns,median_ns,mean_ns,stddev_ns,p95_ns,median_cycles\n");
    }

    /* ---- sizes (compare with the parameter table on the slides) ---- */
    const mlkem_params *sets[] = {&mlkem512, &mlkem768, &mlkem1024};
    printf("Parameter sets and sizes (bytes)\n");
    printf("%-12s %3s %2s %9s %7s %7s %7s %5s\n", "scheme", "cat", "k", "eta1,eta2", "ek", "dk", "ct", "ss");
    for (int i = 0; i < 3; i++) {
        const mlkem_params *p = sets[i];
        printf("%-12s %3d %2d %4d,%-4d %7zu %7zu %7zu %5d   (du,dv)=(%d,%d)\n", p->name,
               p->security_category, p->k, p->eta1, p->eta2, p->ek_bytes, p->dk_bytes,
               p->ct_bytes, MLKEM_SSBYTES, p->du, p->dv);
    }
    printf("\n");

    static ctx_t c;
    for (int i = 0; i < 3; i++) {
        const mlkem_params *p = sets[i];
        if (level && atoi(p->name + 8) != level) continue;
        memset(&c, 0, sizeof c);
        c.p = p;
        for (int j = 0; j < 64; j++) c.coins[j] = (uint8_t)(j * 7 + 1);
        for (int j = 0; j < 32; j++) { c.m[j] = (uint8_t)(j * 5 + 3); c.rho[j] = (uint8_t)j; }
        mlkem_keygen_derand(p, c.ek, c.dk, c.coins);
        mlkem_encaps_derand(p, c.ct, c.ss, c.ek, c.m);
        memcpy(c.badct, c.ct, p->ct_bytes);
        c.badct[0] ^= 1;
        for (int j = 0; j < 256; j++) c.poly[j] = (uint16_t)((j * 13) % MLKEM_Q);
        for (int j = 0; j < 25; j++) c.kst[j] = 0x0123456789abcdefULL * (uint64_t)(j + 1);

        printf("--- %s (NIST category %d) ---\n", p->name, p->security_category);
        PRINT_HDR();
        report(csv, p->name, "keygen", samples, measure(b_keygen, &c, samples, warmup, 1));
        report(csv, p->name, "encaps", samples, measure(b_encaps, &c, samples, warmup, 1));
        report(csv, p->name, "decaps", samples, measure(b_decaps, &c, samples, warmup, 1));
        report(csv, p->name, "decaps (invalid ct)", samples, measure(b_decaps_bad, &c, samples, warmup, 1));
        report(csv, p->name, "  gen_matrix (A_hat)", samples, measure(b_matrix, &c, samples, warmup, 10));
        report(csv, p->name, "  NTT", samples, measure(b_ntt, &c, samples, warmup, 200));
        report(csv, p->name, "  inverse NTT", samples, measure(b_invntt, &c, samples, warmup, 200));
        report(csv, p->name, "  Keccak-f[1600]", samples, measure(b_keccak, &c, samples, warmup, 200));
        printf("\n");
    }
    if (csv) {
        fclose(csv);
        printf("CSV written to %s\n", csvpath);
    }
    printf("Notes: median is the headline figure; min ~ best case; ops/s = 1e9 / median_ns.\n"
           "       For stable numbers: pin to a core (--pin N), use the 'performance' governor,\n"
           "       and close other workloads.\n");
    return 0;
}

/* Written with assistance from Claude (Anthropic) - model: Claude Sonnet 5.5, Nov 2026. */
