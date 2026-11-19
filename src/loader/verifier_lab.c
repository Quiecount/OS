/* 阶段 1 教学工具：仅尝试加载并打印 Verifier 日志，不挂载、不 pin。 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

int main(int argc, char **argv)
{
    struct bpf_object *object;
    char *log;
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s BPF_OBJECT\n", argv[0]);
        return 2;
    }
    log = calloc(1, 256 * 1024);
    if (!log)
        return 2;
    LIBBPF_OPTS(bpf_object_open_opts, options,
        .kernel_log_buf = log,
        .kernel_log_size = 256 * 1024,
        .kernel_log_level = 1,
    );
    object = bpf_object__open_file(argv[1], &options);
    if (!object) {
        fprintf(stderr, "Cannot open BPF object (errno=%d)\n", errno);
        free(log);
        return 2;
    }
    err = bpf_object__load(object);
    fprintf(stderr, "%s\n", log);
    puts(err ? "VERIFIER_REJECTED" : "VERIFIER_ACCEPTED");
    bpf_object__close(object);
    free(log);
    return err ? 1 : 0;
}
