#include <assert.h>
#include <stdio.h>
#include "latency_hist.h"
static void check(unsigned long long value)
{
    unsigned int slot = latency_bucket(value);
    assert(slot < OSMEDIC_FINE_SLOTS);
    if (slot == OSMEDIC_FINE_SLOTS - 1) return;
    unsigned long long upper = latency_upper_ns(slot);
    assert(value <= upper);
    if (slot) assert(value > latency_upper_ns(slot - 1));
    if (value >= 8) assert((double)(upper - value) / value <= 0.125);
}
int main(void)
{
    for (unsigned int slot = 0; slot < OSMEDIC_FINE_SLOTS - 1; ++slot) {
        unsigned long long upper = latency_upper_ns(slot);
        check(upper); check(upper + 1);
        if (upper) check(upper - 1);
    }
    for (unsigned long long n = 0; n < 1000000; ++n) check(n);
    puts("HISTOGRAM_BOUNDARIES_OK");
}
