// execsnoop：遵守 docs/接口契约.md，默认仅向 stdout 输出 JSON Lines。
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "events.h"
#include "json_output.h"

static volatile sig_atomic_t exiting;
static bool pretty;

static void on_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static int log_libbpf(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static unsigned long long monotonic_ns(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static int handle_event(void *ctx, void *data, size_t size)
{
    const struct ev_exec *event = data;

    (void)ctx;
    /* 契约只允许尾部追加字段；接受未来带有附加字段的事件。 */
    if (size < sizeof(*event)) {
        fprintf(stderr, "[execsnoop] short event: %zu bytes\n", size);
        return -EINVAL;
    }
    if (pretty) {
        printf("%-20llu %-8u %-8u ", event->c.ts_ns, event->c.pid, event->c.uid);
        write_json_string(stdout, event->c.comm, sizeof(event->c.comm));
        fputc(' ', stdout);
        write_json_string(stdout, event->filename, sizeof(event->filename));
        fputc('\n', stdout);
    } else {
        printf("{\"scene\":\"exec\",\"ts_ns\":%llu,\"pid\":%u,\"uid\":%u,\"comm\":",
               event->c.ts_ns, event->c.pid, event->c.uid);
        write_json_string(stdout, event->c.comm, sizeof(event->c.comm));
        fputs(",\"filename\":", stdout);
        write_json_string(stdout, event->filename, sizeof(event->filename));
        fputs("}\n", stdout);
    }
    return fflush(stdout) == EOF || ferror(stdout) ? -EIO : 0;
}

static void usage(FILE *file, const char *program)
{
    fprintf(file, "Usage: %s [--duration SECONDS] [--pretty]\n"
            "  --duration N  Stop after N seconds (1..86400); default: until Ctrl+C\n"
            "  --pretty      Human-readable table instead of JSON Lines\n"
            "  --help        Show help\n", program);
}

int main(int argc, char **argv)
{
    static const struct option options[] = {
        {"duration", required_argument, NULL, 'd'},
        {"pretty", no_argument, NULL, 'p'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    struct bpf_object *obj = NULL;
    struct bpf_program *program;
    struct bpf_link *link = NULL;
    struct bpf_map *map;
    struct ring_buffer *ring = NULL;
    struct sigaction action = {.sa_handler = on_signal};
    unsigned long duration = 0;
    unsigned long long deadline = 0;
    int option, err = 0;

    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'd': {
            char *end;
            bool invalid = !*optarg;

            for (const char *p = optarg; *p; p++)
                if (*p < '0' || *p > '9') invalid = true;
            errno = 0;
            duration = strtoul(optarg, &end, 10);
            if (invalid || errno || *end || duration < 1 || duration > 86400) {
                fprintf(stderr, "Invalid duration: %s\n", optarg);
                return 1;
            }
            break;
        }
        case 'p': pretty = true; break;
        case 'h': usage(stdout, argv[0]); return 0;
        default: usage(stderr, argv[0]); return 1;
        }
    }
    if (optind != argc) { usage(stderr, argv[0]); return 1; }

    libbpf_set_print(log_libbpf);
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
        signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("Set signal handlers");
        return 1;
    }
    obj = bpf_object__open_file("build/execsnoop.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "[execsnoop] cannot open build/execsnoop.bpf.o; run make from repo root\n");
        return 1;
    }
    err = bpf_object__load(obj);
    if (err) goto cleanup;
    map = bpf_object__find_map_by_name(obj, "events");
    program = bpf_object__find_program_by_name(obj, "trace_execve");
    if (!map || !program) { err = -ENOENT; goto cleanup; }
    ring = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (!ring) { err = -(errno ? errno : EIO); goto cleanup; }
    link = bpf_program__attach(program);
    if (!link) { err = -(errno ? errno : EIO); goto cleanup; }
    if (duration)
        deadline = monotonic_ns() + duration * 1000000000ULL;
    if (pretty)
        puts("TS_NS                PID      UID      COMM FILENAME");
    fprintf(stderr, "[execsnoop] ready; Ctrl+C to stop\n");
    fflush(stderr);

    while (!exiting && (!deadline || monotonic_ns() < deadline)) {
        err = ring_buffer__poll(ring, 100);
        if (err == -EINTR) { err = 0; continue; }
        if (err < 0) break;
    }
    bpf_link__destroy(link);
    link = NULL;
    if (err >= 0)
        err = ring_buffer__consume(ring);
    if (fflush(stdout) == EOF || ferror(stdout))
        err = -EIO;

cleanup:
    if (err < 0)
        fprintf(stderr, "[execsnoop] failed: %s\n", strerror(-err));
    ring_buffer__free(ring);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}
