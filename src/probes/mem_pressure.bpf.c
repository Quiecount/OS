// 探针（场景4 骨架）：内存压力 —— 观测用户态缺页异常
// 挂载点：tracepoint/exceptions/page_fault_user（x86_64；名字随架构有差异，
//         动工前 `bpftrace -l 'tracepoint:exceptions:*'` 实测确认）
// 骨架现状：逐事件提交；阶段 2 补缺页速率窗口统计 / mmap 大块申请 / OOM 事件
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/exceptions/page_fault_user")
int trace_page_fault(void *ctx)
{
    struct ev_mem e = {};

    e.c.ts_ns = bpf_ktime_get_ns();
    e.c.pid = bpf_get_current_pid_tgid() >> 32;
    e.c.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.c.comm, sizeof(e.c.comm));
    e.addr = 0;                     // TODO(阶段2)：从 ctx 取缺页地址并统计速率

    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}
