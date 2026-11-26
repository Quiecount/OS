// 场景5 故障注入：锁竞争 —— 8 个线程抢同一把 pthread 互斥锁
// 底层走 futex 系统调用，供 lock_contention 探针观测
// 观测方式：加载 lock_contention 探针后运行本程序，观察同锁地址的等待事件
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define NTHREADS 8

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long counter;

static void *worker(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&lock);     /* 临界区极短：制造纯锁竞争 */
        counter++;
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

int main(void)
{
    pthread_t t[NTHREADS];

    for (int i = 0; i < NTHREADS; i++)
        pthread_create(&t[i], NULL, worker, NULL);

    printf("[lock_contention] %d 线程抢 1 把锁，Ctrl+C 结束\n", NTHREADS);
    for (;;) {
        sleep(5);
        printf("[lock_contention] counter=%lu\n", counter);
    }
    return 0;
}
