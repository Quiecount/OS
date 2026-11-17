// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "io_latency.h"

char LICENSE[] SEC("license") = "GPL";

const volatile bool filter_device = false;
const volatile __u32 target_major = 0;
const volatile __u32 target_minor = 0;
__u64 tracking_failures = 0;
__u64 partial_completions = 0;
__u64 requeued_requests = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, struct io_start);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, IO_LATENCY_OPERATIONS);
	__type(key, __u32);
	__type(value, struct io_histogram);
} histograms SEC(".maps");

/* tp_btf 使用同名 block tracepoint 的原始参数，获取稳定的请求指针。 */
SEC("tp_btf/block_rq_issue")
int BPF_PROG(record_issue, struct request *rq)
{
	__u64 key = (__u64)rq;
	struct io_start start = {};
	struct gendisk *disk;
	__u32 major, minor;

	/* Linux 6.6 的 REQ_OP_BITS 为 8；其余位为请求标志。 */
	start.operation = BPF_CORE_READ(rq, cmd_flags) & 0xff;
	if (start.operation != REQ_OP_READ && start.operation != REQ_OP_WRITE)
		return 0;
	start.bytes = BPF_CORE_READ(rq, __data_len);
	if (!start.bytes)
		return 0;
	if (filter_device) {
		disk = BPF_CORE_READ(rq, q, disk);
		if (!disk)
			return 0;
		major = BPF_CORE_READ(disk, major);
		minor = BPF_CORE_READ(disk, first_minor);
		if (major != target_major || minor != target_minor)
			return 0;
	}
	start.timestamp_ns = bpf_ktime_get_ns();
	if (bpf_map_update_elem(&starts, &key, &start, BPF_ANY))
		__sync_fetch_and_add(&tracking_failures, 1);
	return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(record_complete, struct request *rq, blk_status_t error, unsigned int nr_bytes)
{
	__u64 key = (__u64)rq;
	struct io_start *start, sample;
	struct io_histogram *histogram;
	__u64 latency;
	__u32 remaining, slot, operation;

	start = bpf_map_lookup_elem(&starts, &key);
	if (!start)
		return 0;
	if (error)
		start->had_error = 1;
	remaining = BPF_CORE_READ(rq, __data_len);
	if (!io_completion_is_final(nr_bytes, remaining, BPF_CORE_READ(rq, bio) != NULL)) {
		__sync_fetch_and_add(&partial_completions, 1);
		return 0;
	}
	sample = *start;
	bpf_map_delete_elem(&starts, &key);
	operation = sample.operation;
	histogram = bpf_map_lookup_elem(&histograms, &operation);
	if (!histogram)
		return 0;
	latency = bpf_ktime_get_ns() - sample.timestamp_ns;
	slot = io_latency_slot(latency);
	__sync_fetch_and_add(&histogram->slots[slot], 1);
	__sync_fetch_and_add(&histogram->bytes, sample.bytes);
	__sync_fetch_and_add(&histogram->latency_total_ns, latency);
	if (sample.had_error)
		__sync_fetch_and_add(&histogram->errors, 1);
	return 0;
}

/* 重入队后删除旧计时，下一次 issue 会开启新的下发尝试。 */
SEC("tp_btf/block_rq_requeue")
int BPF_PROG(record_requeue, struct request *rq)
{
	__u64 key = (__u64)rq;

	if (bpf_map_lookup_elem(&starts, &key)) {
		bpf_map_delete_elem(&starts, &key);
		__sync_fetch_and_add(&requeued_requests, 1);
	}
	return 0;
}
