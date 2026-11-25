/* 场景 3–5 的内部 map 布局；对外事件前缀仍由 events.h 定义。 */
#ifndef OSMEDIC_STAGE2_H
#define OSMEDIC_STAGE2_H
#include "events.h"
#define P2_ROWS 4096
#define P2_STACK_DEPTH 32
struct p2_process {
    unsigned long long start_ns;
    unsigned int pid, pad;
};
struct p2_mem_stats {
    struct ev_common c;
    unsigned long long faults, mmap_calls, mmap_bytes, mmap_failures, addr;
};
struct p2_mmap {
    struct p2_process process;
    unsigned long long length;
};
struct p2_lock_key {
    unsigned long long start_ns, addr;
    unsigned int pid, pad;
};
struct p2_wait {
    struct ev_lock e;
    unsigned long long started_ns, offcpu_start_ns;
};
#endif
