#include <stdio.h>
#include <time.h>

unsigned int gcd(unsigned int a, unsigned int b)
{
    unsigned int r;

    while (b != 0)
    {
        r = a % b;
        a = b;
        b = r;
    }

    return a;
}

int main()
{
    unsigned int a, b, result;
    clock_t start, end;
    long iterations = 1000000;

    printf("Enter two numbers:\n ");
    scanf("%u %u", &a, &b);

    // Timing code using clock() (developed with assistance from Claude Sonnet 5)
    start = clock();

    for (long i = 0; i < iterations; i++)
    {
        result = gcd(a, b);
    }

    end = clock();

    double total_time = (double)(end - start) / CLOCKS_PER_SEC;

    printf("gcd of %u and %u is %u\n", a, b, result);
    printf("Total clock cycles for %ld runs: %ld\n",
           iterations, (long)(end - start));
    printf("Total time: %f seconds\n", total_time);
    printf("Average time per call: %e seconds\n",
           total_time / iterations);

    return 0;
}