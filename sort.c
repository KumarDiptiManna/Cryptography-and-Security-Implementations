#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* ---------------- Merge Sort ---------------- */

void merge(int arr[], int left, int mid, int right)
{
    int n1 = mid - left + 1;
    int n2 = right - mid;

    int *L = (int *)malloc(n1 * sizeof(int));
    int *R = (int *)malloc(n2 * sizeof(int));

    for (int i = 0; i < n1; i++) L[i] = arr[left + i];
    for (int j = 0; j < n2; j++) R[j] = arr[mid + 1 + j];

    int i = 0, j = 0, k = left;

    while (i < n1 && j < n2)
    {
        if (L[i] <= R[j]) arr[k++] = L[i++];
        else arr[k++] = R[j++];
    }
    while (i < n1) arr[k++] = L[i++];
    while (j < n2) arr[k++] = R[j++];

    free(L);
    free(R);
}

void mergeSort(int arr[], int left, int right)
{
    if (left < right)
    {
        int mid = left + (right - left) / 2;
        mergeSort(arr, left, mid);
        mergeSort(arr, mid + 1, right);
        merge(arr, left, mid, right);
    }
}

/* ---------------- Quick Sort ---------------- */

void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

int partition(int arr[], int low, int high)
{
    int pivot = arr[high];
    int i = low - 1;

    for (int j = low; j < high; j++)
    {
        if (arr[j] < pivot)
        {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);
    return i + 1;
}

void quickSort(int arr[], int low, int high)
{
    if (low < high)
    {
        int pi = partition(arr, low, high);
        quickSort(arr, low, pi - 1);
        quickSort(arr, pi + 1, high);
    }
}

/* ---------------- Heap Sort ---------------- */

void heapify(int arr[], int n, int i)
{
    int largest = i;
    int left = 2 * i + 1;
    int right = 2 * i + 2;

    if (left < n && arr[left] > arr[largest])
        largest = left;

    if (right < n && arr[right] > arr[largest])
        largest = right;

    if (largest != i)
    {
        swap(&arr[i], &arr[largest]);
        heapify(arr, n, largest);
    }
}

void heapSort(int arr[], int n)
{
    for (int i = n / 2 - 1; i >= 0; i--)
        heapify(arr, n, i);

    for (int i = n - 1; i > 0; i--)
    {
        swap(&arr[0], &arr[i]);
        heapify(arr, i, 0);
    }
}

/* ---------------- Helper functions ---------------- */

void generateRandomArray(int arr[], int n)
{
    for (int i = 0; i < n; i++)
        arr[i] = rand() % 1000000;
}

int isSorted(int arr[], int n)
{
    for (int i = 1; i < n; i++)
        if (arr[i - 1] > arr[i])
            return 0;
    return 1;
}

/* ---------------- Main ---------------- */

int main()
{
    int n;
    printf("Enter number of elements to sort:\n");
    scanf("%d", &n);

    int *original = (int *)malloc(n * sizeof(int));
    int *arr = (int *)malloc(n * sizeof(int));

    srand(42);  /* fixed seed so all three sorts get the SAME random data, for a fair comparison */
    generateRandomArray(original, n);

    long repeats = 1000000 / n;   /* scale repeats so total work stays roughly constant */
    if (repeats < 1) repeats = 1;

    clock_t start, end;
    double time_taken;

    /* ---- Merge Sort ---- */
    start = clock();
    for (long r = 0; r < repeats; r++)
    {
        memcpy(arr, original, n * sizeof(int));
        mergeSort(arr, 0, n - 1);
    }
    end = clock();
    time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("\nMerge Sort:\n");
    printf("  Sorted correctly: %s\n", isSorted(arr, n) ? "Yes" : "No");
    printf("  Repeats: %ld\n", repeats);
    printf("  Total clock ticks: %ld\n", (long)(end - start));
    printf("  Total time: %f seconds\n", time_taken);
    printf("  Average time per sort: %e seconds\n", time_taken / repeats);

    /* ---- Quick Sort ---- */
    start = clock();
    for (long r = 0; r < repeats; r++)
    {
        memcpy(arr, original, n * sizeof(int));
        quickSort(arr, 0, n - 1);
    }
    end = clock();
    time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("\nQuick Sort:\n");
    printf("  Sorted correctly: %s\n", isSorted(arr, n) ? "Yes" : "No");
    printf("  Repeats: %ld\n", repeats);
    printf("  Total clock ticks: %ld\n", (long)(end - start));
    printf("  Total time: %f seconds\n", time_taken);
    printf("  Average time per sort: %e seconds\n", time_taken / repeats);

    /* ---- Heap Sort ---- */
    start = clock();
    for (long r = 0; r < repeats; r++)
    {
        memcpy(arr, original, n * sizeof(int));
        heapSort(arr, n);
    }
    end = clock();
    time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("\nHeap Sort:\n");
    printf("  Sorted correctly: %s\n", isSorted(arr, n) ? "Yes" : "No");
    printf("  Repeats: %ld\n", repeats);
    printf("  Total clock ticks: %ld\n", (long)(end - start));
    printf("  Total time: %f seconds\n", time_taken);
    printf("  Average time per sort: %e seconds\n", time_taken / repeats);

    free(original);
    free(arr);

    return 0;
}

/*
 * Developed with assistance from Claude (Anthropic, https://claude.ai)
 * for implementation, debugging, and performance analysis.
 */