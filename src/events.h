// 事件契约：全部场景的事件结构定义（内核态探针与用户态加载器共享）
// 约定：所有场景事件的前 4 个字段统一为 ev_common，便于 analysis 层统一处理
// 数据通路：探针填结构 → ringbuf → 加载器打印为 JSON Lines → analysis/collector.py
#ifndef EVENTS_H
#define EVENTS_H

// 通用事件头：每个场景事件都以它开头
struct ev_common {
    unsigned long long ts_ns;   // 事件时间戳，bpf_ktime_get_ns()
    unsigned int pid;           // 进程 ID
    unsigned int uid;           // 用户 ID
    char comm[16];              // 进程名
};

// 场景 0（模板，已完整实现）：进程启动 execsnoop
struct ev_exec {
    struct ev_common c;
    char filename[128];         // 被执行的程序路径
};

// 场景 1：高频/高耗时系统调用热点
struct ev_syscall {
    struct ev_common c;
    long id;                    // syscall 号
    // TODO(阶段2)：改为 map 聚合（key={pid,id}，value=次数/延迟），
    //              ringbuf 逐事件提交仅作骨架演示，事件量会很大
};

// 场景 2：CPU 异常占用 / 调度延迟
struct ev_cpu {
    struct ev_common c;
    int prev_pid;               // sched_switch：被换下的进程
    int next_pid;               // sched_switch：换上的进程
    // TODO(阶段2)：runqlat 直方图（sched_wakeup→sched_switch 配对计时）、
    //              off-cpu 等待时长统计、每进程 CPU 占比
};

// 场景 3：I/O 延迟抖动 / 阻塞等待
struct ev_io {
    struct ev_common c;
    unsigned long long delta_ns;    // issue→complete 延迟（骨架恒为 0）
    // TODO(阶段2)：block_rq_issue 在 hash map 记起始时间（key=请求标识），
    //              block_rq_complete 里取差值；按进程/设备聚合直方图与分位数
};

// 场景 4：内存抖动 / OOM 风险
struct ev_mem {
    struct ev_common c;
    unsigned long addr;         // 缺页地址
    // TODO(阶段2)：缺页速率统计（按时间窗口计数）、sys_enter_mmap 大块申请、
    //              oom/oom_mark_victim 事件（OOM 直接证据）
};

// 场景 5：锁竞争
struct ev_lock {
    struct ev_common c;
    unsigned long uaddr;        // futex 锁地址（用户态地址）
    int op;                     // futex 操作码
    // TODO(阶段2)：sys_enter_futex / sys_exit_futex 配对计时；
    //              off-cpu 等待栈聚合，定位"哪把锁、哪些线程在排队"
};

#endif /* EVENTS_H */
