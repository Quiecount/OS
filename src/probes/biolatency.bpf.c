#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "osmedic.h"

char LICENSE[] SEC("license") = "GPL";

#define OSMEDIC_REQ_OP_MASK 0xff

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, unsigned long long);
    __type(value, struct io_start);
} starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct io_hist_key);
    __type(value, unsigned long long);
} histogram SEC(".maps");

static __always_inline unsigned int latency_slot(unsigned long long latency_us)
{
    unsigned int slot = OSMEDIC_HIST_SLOTS - 1;

#pragma unroll
    for (int i = 0; i < OSMEDIC_HIST_SLOTS - 1; i++) {
        if (latency_us <= (1ULL << i)) {
            slot = i;
            break;
        }
    }
    return slot;
}

SEC("raw_tp/block_rq_issue")
int trace_block_issue(struct bpf_raw_tracepoint_args *ctx)
{
    struct request *request = (struct request *)ctx->args[0];
    struct request_queue *queue;
    struct gendisk *disk;
    struct io_start start = {};
    unsigned long long request_key = (unsigned long long)request;
    unsigned long long pid_tgid;
    unsigned int flags;

    if (!request)
        return 0;

    queue = BPF_CORE_READ(request, q);
    if (!queue)
        return 0;
    disk = BPF_CORE_READ(queue, disk);
    if (!disk)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    start.started_ns = bpf_ktime_get_ns();
    start.pid = pid_tgid >> 32;
    start.bytes = BPF_CORE_READ(request, __data_len);
    flags = BPF_CORE_READ(request, cmd_flags);
    start.op = flags & OSMEDIC_REQ_OP_MASK;
    start.major = BPF_CORE_READ(disk, major);
    start.minor = BPF_CORE_READ(disk, first_minor);
    bpf_get_current_comm(start.comm, sizeof(start.comm));
    bpf_core_read_str(start.disk, sizeof(start.disk), &disk->disk_name);

    bpf_map_update_elem(&starts, &request_key, &start, BPF_ANY);
    return 0;
}

SEC("raw_tp/block_rq_complete")
int trace_block_complete(struct bpf_raw_tracepoint_args *ctx)
{
    struct request *request = (struct request *)ctx->args[0];
    unsigned long long request_key = (unsigned long long)request;
    struct io_start *start;
    struct io_hist_key key = {};
    unsigned long long latency_us;
    unsigned long long initial = 1;
    unsigned long long *count;

    if (!request)
        return 0;

    start = bpf_map_lookup_elem(&starts, &request_key);
    if (!start)
        return 0;

    latency_us = (bpf_ktime_get_ns() - start->started_ns) / 1000;
    key.major = start->major;
    key.minor = start->minor;
    key.slot = latency_slot(latency_us);
    __builtin_memcpy(key.disk, start->disk, sizeof(key.disk));

    count = bpf_map_lookup_elem(&histogram, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    else
        bpf_map_update_elem(&histogram, &key, &initial, BPF_NOEXIST);

    bpf_map_delete_elem(&starts, &request_key);
    return 0;
}
