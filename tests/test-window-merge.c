/* Regression: a drained key can be recreated before get_next_key(NULL).
 * CPU must see one process row or a zero-runtime fragment resets CPU_HOG. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "window_merge.h"

int main(void)
{
    struct cpu_row cpu[5] = {
        {.pid=10417, .stats={.runq_samples=94, .runq_total_ns=9000,
                            .offcpu_total_ns=80000, .offcpu_samples=96}},
        {.pid=20, .stats={.runq_samples=1}},
        {.pid=10417, .stats={.runq_samples=1, .runq_total_ns=1000,
                            .offcpu_total_ns=20000, .offcpu_samples=2}},
        {.pid=10, .stats={.runq_samples=4}},
        {.pid=20, .stats={.runq_samples=2}},
    };
    cpu[0].stats.runq_buckets[300]=94;
    cpu[2].stats.runq_buckets[300]=1;
    size_t n=merge_cpu_rows(cpu, 5);
    assert(n==3 && cpu[0].pid==10 && cpu[1].pid==20 && cpu[2].pid==10417);
    assert(cpu[1].stats.runq_samples==3);
    assert(cpu[2].stats.runq_samples==95 && cpu[2].stats.runq_total_ns==10000);
    assert(cpu[2].stats.offcpu_total_ns==100000 && cpu[2].stats.offcpu_samples==98);
    assert(cpu[2].stats.runq_buckets[300]==95);
    /* One /proc delta is now assigned once, rather than followed by a zero row. */
    cpu[2].stats.runtime_ns=870000000;
    double streak=0;
    for (int window=0; window<10; ++window)
        for (size_t i=0; i<n; ++i)
            if (cpu[i].pid==10417)
                streak=cpu[i].stats.runtime_ns>800000000 ? streak+1 : 0;
    assert(streak==10);
    assert(merge_cpu_rows(cpu, n)==n);
    assert(merge_cpu_rows(cpu, 0)==0);

    struct syscall_row calls[4] = {
        {.key={2,39}, .value={.calls=100, .total_ns=300}},
        {.key={2,257}, .value={.calls=7, .total_ns=200}},
        {.key={1,39}, .value={.calls=4, .total_ns=50}},
        {.key={2,39}, .value={.calls=5, .total_ns=20}},
    };
    calls[0].value.buckets[11]=100;
    calls[3].value.buckets[12]=5;
    n=merge_syscall_rows(calls, 4);
    assert(n==3 && calls[0].key.pid==1 && calls[1].key.syscall_id==39);
    assert(calls[1].value.calls==105 && calls[1].value.total_ns==320);
    assert(calls[1].value.buckets[11]==100 && calls[1].value.buckets[12]==5);
    assert(calls[2].value.calls==7);
    puts("WINDOW_MERGE_REGRESSION_OK");
    return 0;
}
