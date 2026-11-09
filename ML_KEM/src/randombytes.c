/* randombytes.c - OS CSPRNG access (Linux, macOS/BSD, other POSIX). */
#define _GNU_SOURCE
#include "mlkem.h"

#include <stdio.h>

#if defined(__linux__)
#include <errno.h>
#include <sys/random.h>
int mlkem_randombytes(uint8_t *out, size_t len)
{
    while (len > 0) {
        size_t chunk = len > 256 ? 256 : len; /* getrandom never short-reads <=256 */
        ssize_t r = getrandom(out, chunk, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        out += r;
        len -= (size_t)r;
    }
    return 0;
}
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
#include <stdlib.h>
int mlkem_randombytes(uint8_t *out, size_t len)
{
    arc4random_buf(out, len);
    return 0;
}
#else
int mlkem_randombytes(uint8_t *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return -1;
    size_t n = fread(out, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}
#endif

/* Written with assistance from Claude (Anthropic) - model: Claude Sonnet 5.5, Nov 2026. */
