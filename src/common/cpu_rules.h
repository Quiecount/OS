#ifndef OSMEDIC_CPU_RULES_H
#define OSMEDIC_CPU_RULES_H

/* nearest-rank P99 > threshold iff more than floor(N/100) observations
 * strictly exceed it. Histogram bucket rounding must not decide this rule. */
static inline int runq_p99_exceeds(unsigned long long samples,
                                  unsigned long long over_threshold)
{
    return samples >= 20 && over_threshold <= samples && over_threshold > samples / 100;
}

static inline double cpu_interval_percent(unsigned long long runtime_ns,
                                          unsigned long long start_ns,
                                          unsigned long long end_ns)
{
    return start_ns && end_ns > start_ns ? 100.0 * runtime_ns / (end_ns - start_ns) : 0;
}
#endif
