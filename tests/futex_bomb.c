// 场景5 极限吞吐微基准：FUTEX_WAKE 洪泛
// 原理：对无等待者的地址循环 FUTEX_WAKE，内核走快速路径立即返回——每次调用都是
//       最快的 futex。探针挂载时 enter/exit 各跑一次（map update/lookup/delete +
//       2×ktime + 阈值比较），但 duration < 阈值不上报 → 纯测探针固定开销。
// 用法：./build/futex_bomb [seconds=5]
// 输出（stdout，JSON）：每秒 wake 次数。开/关探针各跑数轮对比 = 极限吞吐损失。
// 注意：这是不停调用 futex 的极限微基准，不能直接解释为真实业务都会下降同比例。
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static uint32_t word = 0;

int main(int argc, char **argv)
{
    double seconds = argc > 1 ? atof(argv[1]) : 5.0;
    if (seconds <= 0) seconds = 5.0;

    struct timespec a, b;
    unsigned long n = 0;

    clock_gettime(CLOCK_MONOTONIC, &a);
    for (;;) {
        syscall(SYS_futex, &word, FUTEX_WAKE, 1, NULL, NULL, 0);
        n++;
        clock_gettime(CLOCK_MONOTONIC, &b);
        double el = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
        if (el >= seconds) {
            printf("{\"wakes\": %lu, \"seconds\": %.3f, \"wake_per_sec\": %.0f}\n",
                   n, el, n / el);
            break;
        }
    }
    return 0;
}
