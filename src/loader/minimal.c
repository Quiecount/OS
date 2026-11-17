// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "minimal.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	(void)level;
	return vfprintf(stderr, format, args);
}

int main(void)
{
	struct minimal_bpf *skel;
	int err;

	/* 设置 libbpf 日志回调。 */
	libbpf_set_print(libbpf_print_fn);

	/* 打开 skeleton，在加载前设置需要观测的进程。 */
	skel = minimal_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->bss->my_pid = getpid();

	/* 加载并通过内核 Verifier 检查。 */
	err = minimal_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = minimal_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* 每秒 write() 一次，触发自己的探针；Ctrl+C 结束程序。 */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	minimal_bpf__destroy(skel);
	return -err;
}
