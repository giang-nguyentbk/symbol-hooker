#include <stdio.h>
#include <time.h>

#define INIT_BENCHMARK(start, end, duration) \
struct timespec start = {0}; \
struct timespec end = {0}; \
long duration = 0;

#define START_BENCHMARK(start) \
clock_gettime(CLOCK_MONOTONIC, &start)

#define END_BENCHMARK(start, end, duration) \
clock_gettime(CLOCK_MONOTONIC, &end); \
duration = ((end.tv_sec - start.tv_sec) * 1e9) + (end.tv_nsec - start.tv_nsec)

#define PRINT_BENCHMARK(duration, label) \
printf("[BENCHMARK] %s took %ld ns\n", label, duration)