// 场景5 量化校准源：确定性 timeout-futex 注入器
// 原理：FUTEX_WAIT 传入 *addr==expected 的地址 + 相对 timeout → 线程必然睡满 timeout
//       后以 ETIMEDOUT 返回。每次调用 = 一个时长精确已知的完整 futex enter→exit。
// 真值：事件数 = threads × loops；每事件 duration_ns ≈ timeout_us × 1000（hrtimer 精度 + 唤醒延迟）
// 所有线程共用同一个静态 word：校准事件共享同一 uaddr，便于从 JSONL 中过滤系统噪声。
// 用法：./build/futex_calib [threads=4] [loops=2500] [timeout_us=1000]
// 真值摘要输出到 stderr（JSON），供 tests/quant_stats.py 解析。
#include <errno.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

static uint32_t word = 0; /* futex 要求 32 位对齐；static 保证对齐且地址固定 */

struct job {
    int loops;
    long timeout_us;
};

static long futex_wait(uint32_t *addr, uint32_t expected, const struct timespec *rel)
{
    return syscall(SYS_futex, addr, FUTEX_WAIT, expected, rel, NULL, 0);
}

static void *worker(void *arg)
{
    struct job *j = arg;
    struct timespec rel = { j->timeout_us / 1000000L,
                            (j->timeout_us % 1000000L) * 1000L };
    for (int i = 0; i < j->loops; i++) {
        /* word 恒为 0、expected=0 → 必然睡满 rel，超时返回 ETIMEDOUT */
        futex_wait(&word, 0, &rel);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int threads = argc > 1 ? atoi(argv[1]) : 4;
    int loops = argc > 2 ? atoi(argv[2]) : 2500;
    long timeout_us = argc > 3 ? atol(argv[3]) : 1000;

    if (threads <= 0 || loops <= 0 || timeout_us <= 0) {
        fprintf(stderr, "参数必须为正整数\n");
        return 1;
    }

    struct job j = { loops, timeout_us };
    pthread_t t[64];
    if (threads > 64) threads = 64;

    for (int i = 0; i < threads; i++)
        pthread_create(&t[i], NULL, worker, &j);
    for (int i = 0; i < threads; i++)
        pthread_join(t[i], NULL);

    fprintf(stderr,
            "{\"expect_events\": %d, \"timeout_us\": %ld, \"uaddr\": \"0x%lx\"}\n",
            threads * loops, timeout_us, (unsigned long)&word);
    return 0;
}
