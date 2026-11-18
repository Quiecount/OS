// 场景1 故障注入：syscall bomb —— 高频 stat 系统调用，制造 syscall 热点
// 观测方式：加载 syscall_hotspot 探针后运行本程序，观察事件洪流
#include <stdio.h>
#include <sys/stat.h>

int main(void)
{
    unsigned long n = 0;
    struct stat st;

    printf("[syscall_bomb] 高频 stat 注入中，Ctrl+C 结束\n");
    for (;;) {
        if (stat("/tmp", &st) == 0) {
            n++;
            if (n % 500000 == 0)
                printf("[syscall_bomb] 已执行 %lu 次 stat\n", n);
        }
    }
    return 0;
}
