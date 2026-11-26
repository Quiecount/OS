// 探针（场景5）：锁竞争 —— futex 进出配对计时，定位"哪把锁、哪些线程在排队"
// 挂载点（3 个程序）：
//   syscalls/sys_enter_futex  —— 记录起始时刻/锁地址/操作码到 hash map
//   syscalls/sys_exit_futex   —— 配对算耗时，>= 阈值才提交事件（防事件洪峰）
//   sched/sched_process_exit  —— 清理线程死在 futex 里遗留的孤儿记录
// 设计详见 docs/开发指南_场景5_锁竞争.md（含砍单说明：栈聚合为打磨期增强）
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// futex 命令码（内核 ABI 固定值，vmlinux.h 不含用户可见常量，此处自行定义）
#define FUTEX_WAIT 0
#define FUTEX_WAIT_BITSET 9

#include "events.h"

// 上报阈值。struct cfg 必须保持为本探针唯一的 .rodata 变量（位于偏移 0），
// 加载器在 load 前整体改写它的初始值实现 --threshold-us 运行时调参；
// 后续新增配置项一律并入本 struct，禁止出现第二个 .rodata 变量
struct cfg {
    unsigned long long threshold_ns;
};
const volatile struct cfg cfg = {
    .threshold_ns = 100000,      // 默认 100µs：过滤掉快速 futex（无竞争 WAIT / WAKE）
};

// 事件队列：BPF 环形缓冲区（内核态写、用户态读）
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 配对表：tid → futex 进入时刻与参数
// 一个线程同一时刻只处于一个 futex 调用中，tid 作 key 无歧义
struct futex_start {
    unsigned long long ts_ns;    // sys_enter_futex 时刻
    unsigned long uaddr;         // 锁地址
    unsigned long op;            // 操作码
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);  // 表满时 update 失败 = 该次调用不计时（可接受）
    __type(key, __u32);          // tid = pid_tgid 低 32 位
    __type(value, struct futex_start);
} starts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_futex")
int trace_futex_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct futex_start s = {};
    unsigned int cmd = (unsigned int)(ctx->args[1]) & 0x7F;  // 剥掉 PRIVATE(128)/REALTIME(256) 标志位
    __u32 tid = bpf_get_current_pid_tgid();     // 低 32 位 = tid

    // 只对会睡眠的 WAIT 类操作计时：WAKE/REQUEUE 等不睡，配对计时无意义，
    // 且高频 WAKE 下 enter 的 map 写入是纯开销（量化测试实证：占吞吐损失大头）
    if (cmd != FUTEX_WAIT && cmd != FUTEX_WAIT_BITSET)
        return 0;

    s.ts_ns = bpf_ktime_get_ns();
    s.uaddr = (unsigned long)ctx->args[0];      // futex(uaddr, op, ...)
    s.op = (unsigned long)ctx->args[1];
    bpf_map_update_elem(&starts, &tid, &s, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int trace_futex_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct futex_start *s;
    struct ev_lock *e;
    unsigned long long start_ts, delta;
    unsigned long uaddr, op;
    __u32 tid = bpf_get_current_pid_tgid();

    (void)ctx;
    s = bpf_map_lookup_elem(&starts, &tid);
    if (!s)
        return 0;                    // 无进入记录（加载器中途启动 / 表满丢弃）

    // 先拷贝再删除：delete 后槽位可能被其他 CPU 复用，原指针不可再读
    start_ts = s->ts_ns;
    uaddr = s->uaddr;
    op = s->op;
    bpf_map_delete_elem(&starts, &tid);   // 无论是否上报都删除，防表泄漏

    delta = bpf_ktime_get_ns() - start_ts;
    if (delta < cfg.threshold_ns)
        return 0;                    // 快速 futex 不上报，把事件量压到"慢调用"级别

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;                    // ringbuf 满：丢弃（有损设计，可接受）
    __builtin_memset(e, 0, sizeof(*e));   // reserve 不清零，防泄露内核残留字节

    e->c.ts_ns = bpf_ktime_get_ns();       // ts = exit 时刻；enter 时刻 = ts - duration
    e->c.pid = bpf_get_current_pid_tgid() >> 32;
    e->c.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->c.comm, sizeof(e->c.comm));
    e->uaddr = uaddr;
    e->op = (int)op;
    e->duration_ns = delta;
    e->tid = bpf_get_current_pid_tgid();   // 低 32 位 = tid（排队者是线程，pid 区分不了）
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 兜底：线程在 futex 等待中被杀时，starts 里会留下孤儿记录
SEC("tracepoint/sched/sched_process_exit")
int trace_thread_exit(void *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid();

    (void)ctx;
    bpf_map_delete_elem(&starts, &tid);   // key 不存在时返回 -ENOENT，无害
    return 0;
}
