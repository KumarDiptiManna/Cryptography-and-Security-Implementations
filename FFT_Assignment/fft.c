#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <complex.h>

#define PI 3.14159265358979323846

/* =========================================================================
 * 1. DEFINITION OF FFT (Fast Fourier Transform)
 * -------------------------------------------------------------------------
 * FFT(P, out, n)
 * Converts Coefficient Representation -> Point-Value Representation in O(n log n).
 * P   : Input array of n complex coefficients (n MUST be a power of 2)
 * out : Output array storing evaluated values at n-th roots of unity
 * ========================================================================= */
void FFT(double complex *P, double complex *out, int n) {
    /* Base Case: A degree-0 polynomial evaluation is just its constant term */
    if (n == 1) {
        out[0] = P[0];
        return;
    }

    /* Step A: Split into even-indexed (Pe) and odd-indexed (Po) coefficients */
    double complex *Pe = malloc((n / 2) * sizeof(double complex));
    double complex *Po = malloc((n / 2) * sizeof(double complex));
    for (int i = 0; i < n / 2; i++) {
        Pe[i] = P[2 * i];
        Po[i] = P[2 * i + 1];
    }

    double complex *ye = malloc((n / 2) * sizeof(double complex));
    double complex *yo = malloc((n / 2) * sizeof(double complex));

    /* ---------------------------------------------------------------------
     * RECURSIVE USE OF FFT:
     * Recursively compute FFT on the even half Pe and odd half Po
     * --------------------------------------------------------------------- */
    FFT(Pe, ye, n / 2);   /* Recursively solve even half */
    FFT(Po, yo, n / 2);   /* Recursively solve odd half */

    /* Step B: Combine results via Butterfly Operation using n-th root of unity */
    double complex w_n = cexp(2.0 * PI * I / n);  /* Principal n-th root of unity */
    double complex w = 1.0;
    for (int j = 0; j < n / 2; j++) {
        double complex t = w * yo[j];
        out[j]         = ye[j] + t;   /* Positive butterfly branch */
        out[j + n / 2] = ye[j] - t;   /* Negative butterfly branch */
        w *= w_n;                     /* Advance root of unity power */
    }

    /* Free temporary allocations */
    free(Pe);
    free(Po);
    free(ye);
    free(yo);
}

/* =========================================================================
 * 2. DEFINITION OF IFFT HELPER (Inverse Fast Fourier Transform Core)
 * -------------------------------------------------------------------------
 * Computes unscaled inverse FFT using negative exponent root of unity.
 * ========================================================================= */
void IFFT_Helper(double complex *A, double complex *out, int m) {
    if (m == 1) {
        out[0] = A[0];
        return;
    }

    double complex *Ae = malloc((m / 2) * sizeof(double complex));
    double complex *Ao = malloc((m / 2) * sizeof(double complex));
    for (int i = 0; i < m / 2; i++) {
        Ae[i] = A[2 * i];
        Ao[i] = A[2 * i + 1];
    }

    double complex *ye = malloc((m / 2) * sizeof(double complex));
    double complex *yo = malloc((m / 2) * sizeof(double complex));

    /* ---------------------------------------------------------------------
     * RECURSIVE USE OF IFFT HELPER:
     * Recursively compute Inverse FFT on even (Ae) and odd (Ao) halves
     * --------------------------------------------------------------------- */
    IFFT_Helper(Ae, ye, m / 2);
    IFFT_Helper(Ao, yo, m / 2);

    /* Inverse twiddle factor: negative exponent (-2*PI*I/m) */
    double complex w_m = cexp(-2.0 * PI * I / m);
    double complex w = 1.0;
    for (int j = 0; j < m / 2; j++) {
        double complex t = w * yo[j];
        out[j]         = ye[j] + t;
        out[j + m / 2] = ye[j] - t;
        w *= w_m;
    }

    free(Ae);
    free(Ao);
    free(ye);
    free(yo);
}

/* =========================================================================
 * 3. DEFINITION OF IFFT (Inverse Fast Fourier Transform Wrapper)
 * -------------------------------------------------------------------------
 * Converts Point-Value Representation -> Coefficient Representation in O(n log n).
 * Runs IFFT_Helper and normalizes all entries by scaling factor 1/n.
 * ========================================================================= */
void IFFT(double complex *Pvals, double complex *out, int n) {
    /* Step A: Run butterfly recursion with inverse roots of unity */
    IFFT_Helper(Pvals, out, n);

    /* Step B: Divide by n to complete the inverse DFT formula */
    for (int j = 0; j < n; j++) {
        out[j] /= n;
    }
}

/* Helper function: calculates smallest power of 2 >= x */
int next_pow2(int x) {
    int n = 1;
    while (n < x) n <<= 1;
    return n;
}

/* =========================================================================
 * 4. APPLICATION / USAGE OF FFT AND IFFT: Polynomial Multiplication
 * -------------------------------------------------------------------------
 * Multiplies polynomial A(x) * B(x) = C(x) using the 3-step pipeline:
 *   Step 1: FFT(A) & FFT(B)  [Coefficients -> Point-Values]
 *   Step 2: Pointwise multiply values C_val[i] = A_val[i] * B_val[i]
 *   Step 3: IFFT(C_val)      [Point-Values -> Coefficients]
 * ========================================================================= */
void multiply_polynomials(double *A, int sizeA, double *B, int sizeB, double *result) {
    int resultSize = sizeA + sizeB - 1;      /* Total coefficients in output */
    int n = next_pow2(resultSize);           /* Padded size (power of 2) */

    double complex *fa = calloc(n, sizeof(double complex));
    double complex *fb = calloc(n, sizeof(double complex));
    double complex *Fa = malloc(n * sizeof(double complex));
    double complex *Fb = malloc(n * sizeof(double complex));
    double complex *Fc = malloc(n * sizeof(double complex));
    double complex *fc = malloc(n * sizeof(double complex));

    /* Copy real polynomial coefficients into zero-padded complex arrays */
    for (int i = 0; i < sizeA; i++) fa[i] = A[i];
    for (int i = 0; i < sizeB; i++) fb[i] = B[i];

    /* ---------------------------------------------------------------------
     * USE OF FFT HERE:
     * Evaluate A(x) and B(x) at n-th roots of unity (Coefficient -> Value)
     * --------------------------------------------------------------------- */
    FFT(fa, Fa, n);   /* Converts fa[] to value array Fa[] */
    FFT(fb, Fb, n);   /* Converts fb[] to value array Fb[] */

    /* Pointwise multiplication in frequency domain: O(n) */
    for (int i = 0; i < n; i++) {
        Fc[i] = Fa[i] * Fb[i];
    }

    /* ---------------------------------------------------------------------
     * USE OF IFFT HERE:
     * Interpolate Fc[] back to polynomial coefficients (Value -> Coefficient)
     * --------------------------------------------------------------------- */
    IFFT(Fc, fc, n);  /* Converts value array Fc[] to coefficient array fc[] */

    /* Extract real parts and round off floating-point noise */
    for (int i = 0; i < resultSize; i++) {
        result[i] = round(creal(fc[i]) * 1e6) / 1e6;
    }

    free(fa); free(fb); free(Fa); free(Fb); free(Fc); free(fc);
}

/* =========================================================================
 * 5. MAIN FUNCTION (Triggers the FFT & IFFT pipeline)
 * ========================================================================= */
int main(void) {
    double A[] = {2, 3, 1};   /* A(x) = 2 + 3x + x^2 */
    double B[] = {1, 0, 2};   /* B(x) = 1 + 0x + 2x^2 */
    int sizeA = 3, sizeB = 3;
    int resultSize = sizeA + sizeB - 1;

    double *C = malloc(resultSize * sizeof(double));

    /* Triggers multiply_polynomials, which internally executes FFT and IFFT */
    multiply_polynomials(A, sizeA, B, sizeB, C);

    printf("A(x) coefficients: ");
    for (int i = 0; i < sizeA; i++) printf("%g ", A[i]);
    printf("\nB(x) coefficients: ");
    for (int i = 0; i < sizeB; i++) printf("%g ", B[i]);
    printf("\nC(x) = A(x) * B(x) coefficients: ");
    for (int i = 0; i < resultSize; i++) printf("%g ", C[i]);
    printf("\n(Expected: 2 3 5 6 2)\n");

    free(C);
    return 0;
}

/*
 * Reference: B. Samanta, "Fast Fourier Transform (FFT)".
 * FFT() and IFFT() implement Algorithm 1 and Algorithm 2 from this document.
 * Developed with assistance from Claude (Anthropic, https://claude.ai)
 * for implementation, debugging, and performance analysis.
 *
 * Compile:  gcc -o fft.exe fft.c -lm
 * Run:      .\fft.exe
 */