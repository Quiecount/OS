/* 有界、可核对样本数的真实内核工作负载；不依赖伪造 JSON。 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static int lock_word, mismatch_word;
static pthread_barrier_t barrier;
static void *waiter(void *unused)
{
    (void)unused;
    for (int op = 0; op <= 9; op += 9) {
        for (int i = 0; i < 3; i++) {
            struct timespec limit = {.tv_nsec = 40000000};
            if (op == 9) {
                clock_gettime(CLOCK_MONOTONIC, &limit);
                limit.tv_nsec += 40000000;
                if (limit.tv_nsec >= 1000000000) { limit.tv_nsec -= 1000000000; limit.tv_sec++; }
            }
            pthread_barrier_wait(&barrier);
            long ret = syscall(SYS_futex, &lock_word, op | FUTEX_PRIVATE_FLAG, 0, &limit, NULL, FUTEX_BITSET_MATCH_ANY);
            if (ret != -1 || errno != ETIMEDOUT) _exit(10);
        }
    }
    return NULL;
}
static int run_lock(void)
{
    pthread_t threads[4];
    if (pthread_barrier_init(&barrier, NULL, 4)) return 1;
    for (int i = 0; i < 10; i++) {
        if (syscall(SYS_futex, &mismatch_word, FUTEX_WAIT_PRIVATE, 1, NULL, NULL, 0) != -1 || errno != EAGAIN) return 2;
    }
    if (syscall(SYS_futex, &mismatch_word, FUTEX_WAKE_PRIVATE, 4, NULL, NULL, 0) != 0) return 3;
    for (int i = 0; i < 4; i++) if (pthread_create(&threads[i], NULL, waiter, NULL)) _exit(4);
    for (int i = 0; i < 4; i++) if (pthread_join(threads[i], NULL)) return 5;
    pthread_barrier_destroy(&barrier); return 0;
}
static int run_io(const char *filename)
{
    int fd = open(filename, O_CREAT | O_EXCL | O_WRONLY | O_DIRECT, 0600);
    if (fd < 0) { perror("open O_DIRECT"); return 1; }
    void *buffer = NULL;
    if (posix_memalign(&buffer, 4096, 65536)) { close(fd); return 1; }
    memset(buffer, 0x5a, 65536);
    int result = 0;
    for (int i = 0; i < 64; i++) if (write(fd, buffer, 65536) != 65536) { perror("write"); result = 1; break; }
    if (fsync(fd)) result = 1;
    free(buffer); close(fd); return result;
}
static int run_memory(int oom)
{
    size_t size = oom ? 128UL << 20 : 16UL << 20;
    if (!oom) {
        void *bad = mmap(NULL, 1UL << 62, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (bad != MAP_FAILED) { munmap(bad, 1UL << 62); return 3; }
    }
    void *blocks[2];
    for (int j = 0; j < (oom ? 1 : 2); j++) {
        blocks[j] = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (blocks[j] == MAP_FAILED) return 1;
        /* 禁用本 VMA 的 THP，才能用 4KiB 页核对缺页下界；不改系统全局配置。 */
        if (!oom && madvise(blocks[j], size, MADV_NOHUGEPAGE)) return 2;
        volatile char *p = blocks[j];
        for (size_t i = 0; i < size; i += 4096) p[i] = 1;
        struct timespec wait = {.tv_sec = 1, .tv_nsec = 300000000};
        nanosleep(&wait, NULL);
    }
    for (int j = 0; j < (oom ? 1 : 2); j++) munmap(blocks[j], size);
    return 0;
}
int main(int argc, char **argv)
{
    if (argc < 2) return 1;
    printf("{\"pid\":%ld,\"lock\":\"%p\",\"mismatch\":\"%p\"}\n", (long)getpid(), (void *)&lock_word, (void *)&mismatch_word);
    fflush(stdout);
    if (getchar() != 'g') return 1;
    if (!strcmp(argv[1], "io") && argc == 3) return run_io(argv[2]);
    if (!strcmp(argv[1], "mem")) return run_memory(0);
    if (!strcmp(argv[1], "oom")) return run_memory(1);
    if (!strcmp(argv[1], "lock")) return run_lock();
    return 1;
}
