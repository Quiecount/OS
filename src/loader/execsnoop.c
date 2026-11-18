// 探针① execsnoop 的用户态加载器
// 职责：把编译好的探针装进内核（open → load → attach）→ 从 ringbuf 收事件 → 打印
// 这个骨架（四步生命周期）会被后续所有探针复用
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "event.h"

static volatile sig_atomic_t exiting = 0;  // Ctrl+C 退出标志

static void on_sigint(int sig) { exiting = 1; }

// ringbuf 回调：每收到一个事件，内核数据被拷贝到 data 指向这里
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("%-8u %-8u %-16.16s %s\n", e->pid, e->uid, e->comm, e->filename);
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link   *link = NULL;
    struct bpf_map    *map  = NULL;
    struct ring_buffer *rb  = NULL;
    int err = 0;

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    // ① open：读取编译好的 BPF 目标文件（注意是相对路径，必须在仓库根目录运行）
    obj = bpf_object__open_file("build/execsnoop.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "[错误] 打不开 build/execsnoop.bpf.o —— 先在仓库根目录 make，并在根目录运行\n");
        return 1;
    }

    // ② load：交给内核 Verifier 安检 + JIT 编译成机器码
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[错误] 加载失败（errno=%d）——检查是否 sudo；上方 verifier 日志会写明拒绝原因\n", err);
        goto cleanup;
    }

    // 找到探针程序，挂载到它声明的 tracepoint 插座上
    prog = bpf_object__find_program_by_name(obj, "trace_execve");
    if (!prog) {
        fprintf(stderr, "[错误] BPF 目标里找不到名为 trace_execve 的程序\n");
        err = 1;
        goto cleanup;
    }
    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "[错误] 挂载 tracepoint 失败\n");
        err = 1;
        goto cleanup;
    }

    // 把 events map 绑定到回调函数
    map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "[错误] 找不到 events map\n");
        err = 1;
        goto cleanup;
    }
    rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[错误] 创建 ring buffer 失败\n");
        err = 1;
        goto cleanup;
    }

    printf("%-8s %-8s %-16s %s\n", "PID", "UID", "COMM", "FILENAME");
    printf("按 Ctrl+C 退出\n");

    // ③ poll：每 100ms 轮询一次（兼顾响应速度与加载器自身 CPU 占用）
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* 毫秒 */);
        if (err == -EINTR) { err = 0; break; }  // 被信号打断 = 正常退出
        if (err < 0) {
            fprintf(stderr, "[错误] ringbuf poll 失败: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return err ? 1 : 0;
}
