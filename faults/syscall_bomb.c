#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    double seconds = argc > 1 ? strtod(argv[1], NULL) : 5.0;
    double start = now_seconds();
    unsigned long long calls = 0;
    struct stat info;
    if (seconds <= 0 || seconds > 3600) return 2;
    while (now_seconds() - start < seconds) {
        if (fstatat(AT_FDCWD, "/proc/self/stat", &info, 0) != 0) {
            perror("fstatat");
            return 1;
        }
        ++calls;
    }
    double elapsed = now_seconds() - start;
    printf("calls=%llu elapsed_s=%.3f rate_per_s=%.0f\n",
           calls, elapsed, calls / elapsed);
    return 0;
}
