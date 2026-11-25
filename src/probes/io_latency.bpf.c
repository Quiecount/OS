// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "stage2.h"
char LICENSE[] SEC("license") = "GPL";
const volatile __u32 target_pid;
__u64 tracking_failures, ringbuf_dropped, partial_completions, requeues, active_requests;
struct pending_io { struct ev_io e; __u64 started_ns; };
struct device_key { __u32 major, minor; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32768);
    __type(key, __u64); __type(value, struct pending_io);
} starts SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
    __type(key, struct device_key); __type(value, __u64);
} queues SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } events SEC(".maps");

static __always_inline void release_request(struct pending_io *p)
{
    struct device_key d = {p->e.major, p->e.minor};
    __u64 *depth = bpf_map_lookup_elem(&queues, &d);
    if (depth) __sync_fetch_and_sub(depth, 1);
    __sync_fetch_and_sub(&active_requests, 1);
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(record_issue, struct request *rq)
{
    __u64 key = (__u64)rq, zero = 0;
    struct pending_io p = {}, *old;
    struct device_key d = {};
    __u64 *depth;
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    struct gendisk *disk = BPF_CORE_READ(rq, q, disk);
    p.e.c.pid = bpf_get_current_pid_tgid() >> 32;
    if (target_pid && p.e.c.pid != target_pid) return 0;
    p.e.operation = BPF_CORE_READ(rq, cmd_flags) & 0xff;
    p.e.bytes = BPF_CORE_READ(rq, __data_len);
    if (p.e.operation > 1 || !p.e.bytes || !disk) return 0;
    p.e.process_start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
    p.e.c.uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(p.e.c.comm, sizeof(p.e.c.comm));
    p.e.major = d.major = BPF_CORE_READ(disk, major);
    p.e.minor = d.minor = BPF_CORE_READ(disk, first_minor);
    bpf_core_read_str(p.e.disk, sizeof(p.e.disk), &disk->disk_name);
    bpf_map_update_elem(&queues, &d, &zero, BPF_NOEXIST);
    depth = bpf_map_lookup_elem(&queues, &d);
    if (!depth) { __sync_fetch_and_add(&tracking_failures, 1); return 0; }
    old = bpf_map_lookup_elem(&starts, &key);
    if (old) {
        release_request(old); bpf_map_delete_elem(&starts, &key);
        __sync_fetch_and_add(&requeues, 1);
    }
    p.e.queue_depth = __sync_fetch_and_add(depth, 1) + 1;
    p.started_ns = bpf_ktime_get_ns();
    __sync_fetch_and_add(&active_requests, 1);
    if (bpf_map_update_elem(&starts, &key, &p, BPF_ANY)) {
        __sync_fetch_and_sub(depth, 1);
        __sync_fetch_and_sub(&active_requests, 1);
        __sync_fetch_and_add(&tracking_failures, 1);
    }
    return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(record_complete, struct request *rq, blk_status_t error, unsigned int nr_bytes)
{
    __u64 key = (__u64)rq;
    struct pending_io *p = bpf_map_lookup_elem(&starts, &key);
    if (!p) return 0;
    if (error) p->e.error = error;
    /* tracepoint 位于 rq->__data_len 扣减之前；部分完成不提前结束计时。 */
    if (BPF_CORE_READ(rq, bio) && nr_bytes < BPF_CORE_READ(rq, __data_len)) {
        __sync_fetch_and_add(&partial_completions, 1); return 0;
    }
    p->e.c.ts_ns = bpf_ktime_get_ns();
    p->e.delta_ns = p->e.c.ts_ns - p->started_ns;
    if (bpf_ringbuf_output(&events, &p->e, sizeof(p->e), 0))
        __sync_fetch_and_add(&ringbuf_dropped, 1);
    release_request(p);
    bpf_map_delete_elem(&starts, &key);
    return 0;
}

SEC("tp_btf/block_rq_requeue")
int BPF_PROG(record_requeue, struct request *rq)
{
    __u64 key = (__u64)rq;
    struct pending_io *p = bpf_map_lookup_elem(&starts, &key);
    if (p) {
        release_request(p); bpf_map_delete_elem(&starts, &key);
        __sync_fetch_and_add(&requeues, 1);
    }
    return 0;
}
