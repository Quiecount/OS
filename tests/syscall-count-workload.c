#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static void *worker(void *unused)
{
    (void)unused;
    for (int i = 0; i < 20000; ++i)
        (void)syscall(SYS_getpid);
    return NULL;
}

int main(int argc, char **argv)
{
    int n = argc == 2 ? atoi(argv[1]) : 1;
    pthread_t threads[8];
    if (n < 1 || n > 8) return 2;
    /* Capture PID before the monitored loop; include this one syscall. */
    long pid = syscall(SYS_getpid);
    for (int i = 0; i < n; ++i)
        if (pthread_create(&threads[i], NULL, worker, NULL)) return 3;
    for (int i = 0; i < n; ++i)
        if (pthread_join(threads[i], NULL)) return 4;
    printf("{\"pid\":%ld,\"id\":%d,\"expected\":%d}\n",
           pid, SYS_getpid, 20000 * n + 1);
    return 0;
}
