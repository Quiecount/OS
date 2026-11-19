// 探针（场景3 骨架）：I/O 延迟 —— 观测块设备请求下发
// 挂载点：tracepoint/block/block_rq_issue（请求提交给设备驱动时触发）
// 骨架现状：只提交事件（delta_ns=0）；阶段 2 需再挂 block_rq_complete，
//           用 hash map 配对 issue/complete 计算每次 I/O 的真实延迟
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 骨架阶段 ctx 字段不访问（block tracepoint 的结构名随内核版本有差异，
// 阶段 2 动工前先在目标内核上 `bpftrace -l 'tracepoint:block:*'` 实测确认）
SEC("tracepoint/block/block_rq_issue")
int trace_block_issue(void *ctx)
{
    struct ev_io e = {};

    e.c.ts_ns = bpf_ktime_get_ns();                 // issue 时刻 = 延迟起点
    e.c.pid = bpf_get_current_pid_tgid() >> 32;
    e.c.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e.c.comm, sizeof(e.c.comm));
    e.delta_ns = 0;                                 // TODO(阶段2)：配对后填真实延迟

    bpf_ringbuf_submit(&e, sizeof(e), 0);
    return 0;
}
