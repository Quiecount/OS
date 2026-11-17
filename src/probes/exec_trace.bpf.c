// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* 基于 libbpf-bootstrap bootstrap.bpf.c 的 exec/ringbuf 示例改造。 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "exec_trace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 target_pid = 0;
__u64 dropped_events = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* 仅在 exec 成功后触发，也涵盖 execveat；失败调用不生成启动事件。 */
SEC("tp/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *task;
	struct exec_event *event;
	__u32 filename_offset;

	if (target_pid && target_pid != pid)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&dropped_events, 1);
		return 0;
	}

	/* 直接初始化 ringbuf 内存，避免把完整事件放在 BPF 栈上。 */
	__builtin_memset(event, 0, sizeof(*event));
	task = (struct task_struct *)bpf_get_current_task();
	event->timestamp_ns = bpf_ktime_get_ns();
	event->pid = pid;
	event->ppid = BPF_CORE_READ(task, real_parent, tgid);
	event->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	/* __data_loc 的低 16 位为字符串相对 tracepoint 上下文的偏移。 */
	filename_offset = BPF_CORE_READ(ctx, __data_loc_filename) & 0xffff;
	event->filename_result = bpf_probe_read_kernel_str(event->filename,
				 sizeof(event->filename), (void *)ctx + filename_offset);
	bpf_ringbuf_submit(event, 0);
	return 0;
}
