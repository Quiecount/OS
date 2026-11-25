// 有界锁竞争：同锁 8 个线程，临界区暂停 1ms，退出时 join 全部线程。
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#define NTHREADS 8
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool stopping;
static volatile sig_atomic_t interrupted;
static unsigned long counter;
static void on_signal(int signal_number) { (void)signal_number; interrupted = 1; }
static double seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
static void *worker(void *unused)
{
    (void)unused;
    while (!atomic_load(&stopping)) {
        pthread_mutex_lock(&lock);
        ++counter;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}
int main(int argc, char **argv)
{
    char *tail;
    const char *argument = argc == 2 ? argv[1] : "60";
    errno = 0;
    unsigned long duration = strtoul(argument, &tail, 10);
    if (argc > 2 || argument[0] < '0' || argument[0] > '9' || *tail || errno || !duration || duration > 86400) {
        fputs("用法：lock_workload [秒数1..86400]\n", stderr); return 1;
    }
    pthread_t threads[NTHREADS];
    unsigned int created = 0;
    int result = 0;
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal);
    printf("lock_workload pid=%ld lock=%p threads=%d duration=%lu\n", (long)getpid(), (void *)&lock, NTHREADS, duration);
    fflush(stdout);
    for (; created < NTHREADS; created++) {
        int error = pthread_create(&threads[created], NULL, worker, NULL);
        if (error) { fprintf(stderr, "pthread_create: %d\n", error); result = 1; break; }
    }
    double deadline = seconds() + duration;
    while (!result && !interrupted && seconds() < deadline) {
        struct timespec delay = {.tv_nsec = 50000000};
        nanosleep(&delay, NULL);
    }
    atomic_store(&stopping, 1);
    for (unsigned int i = 0; i < created; i++) if (pthread_join(threads[i], NULL)) result = 1;
    printf("completed critical_sections=%lu\n", counter);
    pthread_mutex_destroy(&lock);
    return result;
}
