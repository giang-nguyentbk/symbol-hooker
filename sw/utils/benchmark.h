#include <stdio.h>
#include <time.h>

#define START_BENCHMARK(start) \
struct timespec start; \
clock_gettime(CLOCK_MONOTONIC, &start)

#define END_BENCHMARK(start, end, duration) \
struct timespec end; \
clock_gettime(CLOCK_MONOTONIC, &end); \
long duration = ((end.tv_sec - start.tv_sec) * 1e9) + (end.tv_nsec - start.tv_nsec)

#define PRINT_BENCHMARK(duration, label) \
printf("[BENCHMARK] %s took %ld ns\n", label, duration)