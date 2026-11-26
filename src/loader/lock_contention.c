// 场景5 lock_contention 的用户态加载器
// 职责：装探针（enter/exit/线程退出清理 共 3 个程序）→ 从 ringbuf 收慢 futex 事件
//       → 按接口契约 B 输出 JSON Lines（stdout 纯 JSONL，提示走 stderr）
// CLI：--duration N     采集 N 秒自动退出（默认无限，Ctrl+C 退出）
//      --pretty        人类表格输出到 stdout（默认 JSONL）
//      --threshold-us U 只上报耗时 >= U 微秒的 futex（默认 100，改写探针 .rodata）
// 设计详见 docs/开发指南_场景5_锁竞争.md §四
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "events.h"

static volatile sig_atomic_t exiting = 0;   // Ctrl+C / --duration 到时 退出标志
static int pretty = 0;

static void on_sigint(int sig) { exiting = 1; }

// JSON 字符串转义：comm 来自内核（最多 15 字符），可能含引号/反斜杠/控制字符
static void json_escape(const char *in, char *out, size_t out_sz)
{
    size_t i, o = 0;

    for (i = 0; in[i] != '\0' && o + 7 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];

        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            o += (size_t)snprintf(out + o, out_sz - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

// ringbuf 回调：每收到一个慢 futex 事件，按契约打印一行 JSON
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct ev_lock *e = data;
    char comm[16 * 6 + 8];   // 转义后最坏 6 倍 + 余量

    (void)ctx;
    if (data_sz < sizeof(*e))
        return 0;
    json_escape(e->c.comm, comm, sizeof(comm));

    if (pretty) {
        printf("%-8u %-16.15s %-4d %-20s %12llu us\n",
               e->c.pid, comm, e->op, "lock",
               e->duration_ns / 1000);
    } else {
        // uaddr 必须 hex 字符串：64 位地址超 JSON number 安全整数范围（契约 §2.3）
        printf("{\"scene\":\"lock\",\"ts_ns\":%llu,\"pid\":%u,\"uid\":%u,"
               "\"comm\":\"%s\",\"uaddr\":\"0x%llx\",\"op\":%d,"
               "\"duration_ns\":%llu,\"tid\":%u}\n",
               e->c.ts_ns, e->c.pid, e->c.uid, comm,
               (unsigned long long)e->uaddr, e->op, e->duration_ns, e->tid);
    }
    return 0;
}

// load 前改写探针 .rodata（struct cfg 偏移 0）实现 --threshold-us 运行时调参
// 注意：set_initial_value 后缓冲区需保持有效到 load 完成，故不 free（进程短命，可接受）
static int set_threshold(struct bpf_object *obj, unsigned long long threshold_ns)
{
    struct bpf_map *ro = bpf_object__find_map_by_name(obj, ".rodata");
    const void *init;
    void *copy;
    size_t sz = 0;

    if (!ro) {
        fprintf(stderr, "[警告] 探针无 .rodata 段，沿用编译期默认阈值\n");
        return -1;
    }
    init = bpf_map__initial_value(ro, &sz);
    if (!init || sz < sizeof(threshold_ns)) {
        fprintf(stderr, "[警告] .rodata 尺寸异常，沿用编译期默认阈值\n");
        return -1;
    }
    copy = malloc(sz);
    if (!copy)
        return -1;
    memcpy(copy, init, sz);
    memcpy(copy, &threshold_ns, sizeof(threshold_ns));
    if (bpf_map__set_initial_value(ro, copy, sz)) {
        fprintf(stderr, "[警告] 阈值写入失败，沿用编译期默认阈值\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link   *links[3] = { NULL, NULL, NULL };
    struct bpf_map    *map  = NULL;
    struct ring_buffer *rb  = NULL;
    const char *prog_names[3] = { "trace_futex_enter", "trace_futex_exit", "trace_thread_exit" };
    unsigned long long threshold_ns = 100000;   // 默认 100µs
    long duration_sec = 0;
    time_t deadline = 0;
    int i, err = 0;

    // CLI 解析（保持与骨架同风格，不引 getopt）
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pretty")) {
            pretty = 1;
        } else if (!strcmp(argv[i], "--duration") && i + 1 < argc) {
            duration_sec = atol(argv[++i]);
        } else if (!strcmp(argv[i], "--threshold-us") && i + 1 < argc) {
            threshold_ns = (unsigned long long)atol(argv[++i]) * 1000;
        } else {
            fprintf(stderr, "[用法] %s [--duration N] [--pretty] [--threshold-us U]\n", argv[0]);
            return 1;
        }
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    // ① open：读取 BPF 目标（相对路径，必须在仓库根目录运行）
    obj = bpf_object__open_file("build/lock_contention.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "[错误] 打不开 build/lock_contention.bpf.o —— 先在仓库根目录 make\n");
        return 1;
    }

    // load 前注入阈值（.rodata 初始值改写）
    set_threshold(obj, threshold_ns);

    // ② load：Verifier 安检 + JIT
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[错误] 加载失败（errno=%d）——检查是否 root；上方 verifier 日志会写明拒绝原因\n", err);
        goto cleanup;
    }

    // 挂载 3 个程序到各自声明的 tracepoint
    for (i = 0; i < 3; i++) {
        prog = bpf_object__find_program_by_name(obj, prog_names[i]);
        if (!prog) {
            fprintf(stderr, "[错误] BPF 目标里找不到 %s\n", prog_names[i]);
            err = 1;
            goto cleanup;
        }
        links[i] = bpf_program__attach(prog);
        if (!links[i]) {
            fprintf(stderr, "[错误] 挂载 %s 失败\n", prog_names[i]);
            err = 1;
            goto cleanup;
        }
    }

    // events map 绑定到回调
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

    // 人类提示一律走 stderr，保证 stdout 管道纯净（契约 §2.1）
    if (pretty) {
        printf("%-8s %-16s %-4s %-20s %12s\n", "PID", "COMM", "OP", "SCENE", "WAIT(us)");
    }
    fprintf(stderr, "[提示] lock_contention 采集慢 futex（>= %llu µs）", threshold_ns / 1000);
    if (duration_sec > 0) {
        deadline = time(NULL) + duration_sec;
        fprintf(stderr, "，%ld 秒后自动退出\n", duration_sec);
    } else {
        fprintf(stderr, "，按 Ctrl+C 退出\n");
    }

    // ③ poll：每 100ms 轮询
    while (!exiting) {
        if (deadline && time(NULL) >= deadline)
            break;
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "[错误] ringbuf poll 失败: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    for (i = 0; i < 3; i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return err ? 1 : 0;
}
