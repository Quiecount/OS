#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "quality_reference.skel.h"
struct sample { unsigned long long ns; unsigned int kind, tid; };
static volatile sig_atomic_t stop;
static void finish(int signum) { (void)signum; stop = 1; }
static int event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size != sizeof(struct sample)) return -1;
    struct sample *s = data;
    printf("%u %llu\n", s->kind, s->ns);
    return 0;
}
int main(int argc, char **argv)
{
    signal(SIGINT, finish);
    signal(SIGTERM, finish);
    if (argc != 4) return 2;
    struct quality_reference_bpf *b = quality_reference_bpf__open();
    if (!b) return 3;
    b->rodata->target_pid = strtoul(argv[1], NULL, 10);
    b->rodata->syscall_id = strtoul(argv[2], NULL, 10);
    int rc = 4;
    struct ring_buffer *ring = NULL;
    if (quality_reference_bpf__load(b) || quality_reference_bpf__attach(b)) goto done;
    ring = ring_buffer__new(bpf_map__fd(b->maps.events), event, NULL, NULL);
    if (!ring) goto done;
    fprintf(stderr, "READY\n"); fflush(stderr);
    struct timespec start, now; clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        int polled = ring_buffer__poll(ring, 50);
        if (polled < 0 && !stop) goto done;
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (!stop && now.tv_sec - start.tv_sec < atoi(argv[3]));
    ring_buffer__consume(ring);
    unsigned int key = 0; unsigned long long dropped = 0;
    if (bpf_map_lookup_elem(bpf_map__fd(b->maps.lost), &key, &dropped) || dropped) goto done;
    rc = 0;
done:
    ring_buffer__free(ring); quality_reference_bpf__destroy(b);
    return rc;
}
