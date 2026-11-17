#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "osmedic.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *event;
    unsigned long long pid_tgid;
    unsigned long long uid_gid;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    event->ktime_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (unsigned int)pid_tgid;
    event->uid = (unsigned int)uid_gid;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    event->filename_len = bpf_probe_read_user_str(
        event->filename, sizeof(event->filename), (const void *)ctx->args[0]);
    if (event->filename_len < 0) {
        event->filename_len = 0;
        event->filename[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}
