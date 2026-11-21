#include <assert.h>
#include <math.h>
#include <stdio.h>
#include "cpu_rules.h"

int main(void)
{
    /* Exhaustively compare the integer tail rule against nearest-rank P99
     * in a sorted population: all low values first, all high values last. */
    for (unsigned long long n=0; n<=1000; ++n)
        for (unsigned long long high=0; high<=n; ++high) {
            unsigned long long rank=(99*n+99)/100;
            assert(runq_p99_exceeds(n, high)==(n>=20 && rank>n-high));
        }
    assert(!runq_p99_exceeds(189, 1));
    assert(runq_p99_exceeds(189, 2));
    assert(!runq_p99_exceeds(100, 1));
    assert(runq_p99_exceeds(100, 2));
    assert(!runq_p99_exceeds(20, 21));
    /* Four-core workload read 100ms late: dividing by the loop's nominal
     * one second produces 440%; the actual sample interval yields 400%. */
    assert(fabs(cpu_interval_percent(4400000000ULL,1000000000,2100000000)-400.0)<1e-9);
    assert(cpu_interval_percent(100,0,1000)==0);
    assert(cpu_interval_percent(100,1000,1000)==0);
    assert(cpu_interval_percent(100,1001,1000)==0);
    puts("CPU_RULE_BOUNDARIES_OK");
    return 0;
}
