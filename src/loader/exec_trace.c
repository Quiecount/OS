#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "exec_trace.h"
#include "exec_trace.skel.h"

static volatile sig_atomic_t exiting;
static bool verbose;

struct output_state {
	FILE *file;
	uint64_t written;
};

static void handle_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static int log_libbpf(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

/* 检查单个 UTF-8 字符，防止文件名中的非法字节破坏 JSON 编码。 */
static size_t utf8_length(const unsigned char *s, size_t remaining)
{
	size_t length;
	unsigned int codepoint;

	if (s[0] >= 0xc2 && s[0] <= 0xdf) {
		length = 2;
		codepoint = s[0] & 0x1f;
	} else if (s[0] >= 0xe0 && s[0] <= 0xef) {
		length = 3;
		codepoint = s[0] & 0x0f;
	} else if (s[0] >= 0xf0 && s[0] <= 0xf4) {
		length = 4;
		codepoint = s[0] & 0x07;
	} else {
		return 0;
	}
	if (length > remaining)
		return 0;
	for (size_t i = 1; i < length; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return 0;
		codepoint = (codepoint << 6) | (s[i] & 0x3f);
	}
	if ((length == 3 && codepoint < 0x800) ||
	    (length == 4 && codepoint < 0x10000) ||
	    (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
		return 0;
	return length;
}

static void write_json_string(FILE *file, const char *value, size_t capacity)
{
	const unsigned char *s = (const unsigned char *)value;
	size_t length = strnlen(value, capacity);

	fputc('"', file);
	for (size_t i = 0; i < length;) {
		unsigned char c = s[i];
		size_t utf8;

		if (c == '"' || c == '\\') {
			fputc('\\', file);
			fputc(c, file);
		} else if (c < 0x20) {
			fprintf(file, "\\u%04x", c);
		} else if (c < 0x80) {
			fputc(c, file);
		} else if ((utf8 = utf8_length(s + i, length - i)) != 0) {
			fwrite(s + i, 1, utf8, file);
			i += utf8;
			continue;
		} else {
			fprintf(file, "\\u%04x", c);
		}
		i++;
	}
	fputc('"', file);
}

static int handle_event(void *ctx, void *data, size_t size)
{
	struct output_state *out = ctx;
	const struct exec_event *event = data;
	FILE *file = out->file;

	if (size != sizeof(*event)) {
		fprintf(stderr, "Unexpected exec event size: %zu\n", size);
		return -EINVAL;
	}
	fprintf(file, "{\"event\":\"process_exec\",\"timestamp_ns\":%" PRIu64
		",\"clock\":\"monotonic\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":",
		(uint64_t)event->timestamp_ns, event->pid, event->ppid, event->uid);
	write_json_string(file, event->comm, sizeof(event->comm));
	fputs(",\"filename\":", file);
	write_json_string(file, event->filename, sizeof(event->filename));
	fprintf(file, ",\"filename_truncated\":%s,\"filename_error\":%s}\n",
		event->filename_result == EXEC_FILENAME_LEN ? "true" : "false",
		event->filename_result < 0 ? "true" : "false");
	/* 每条记录刷新；磁盘满或管道断开必须报告失败。 */
	if (fflush(file) == EOF || ferror(file))
		return -EIO;
	out->written++;
	return 0;
}

static void usage(FILE *file, const char *program)
{
	fprintf(file, "Usage: %s [-o FILE|-] [-p PID] [-v] [-h]\n"
		"Trace successful exec events as JSON Lines (default: stdout).\n"
		"  -o, --output FILE   Append events to FILE; '-' selects stdout\n"
		"  -p, --pid PID       Only trace this process ID (TGID)\n"
		"  -v, --verbose       Show libbpf debug messages on stderr\n", program);
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{"output", required_argument, NULL, 'o'},
		{"pid", required_argument, NULL, 'p'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};
	struct exec_trace_bpf *skel = NULL;
	struct ring_buffer *ring = NULL;
	struct output_state out = {.file = stdout};
	const char *output_path = "-";
	struct sigaction action = {.sa_handler = handle_signal};
	__u32 pid = 0;
	int option, err = 0;

	while ((option = getopt_long(argc, argv, "o:p:vh", options, NULL)) != -1) {
		switch (option) {
		case 'o': output_path = optarg; break;
		case 'v': verbose = true; break;
		case 'h': usage(stdout, argv[0]); return 0;
		case 'p': {
			char *end;
			unsigned long value;

			errno = 0;
			value = strtoul(optarg, &end, 10);
			if (errno || *end || end == optarg || value == 0 || value > INT_MAX) {
				fprintf(stderr, "Invalid PID: %s\n", optarg);
				return 1;
			}
			pid = value;
			break;
		}
		default: usage(stderr, argv[0]); return 1;
		}
	}
	if (optind != argc) {
		usage(stderr, argv[0]);
		return 1;
	}
	libbpf_set_print(log_libbpf);
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
	    signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		perror("Set signal handlers");
		return 1;
	}
	if (strcmp(output_path, "-") != 0) {
		out.file = fopen(output_path, "a");
		if (!out.file) {
			perror("Open output");
			return 1;
		}
	}
	skel = exec_trace_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open exec_trace skeleton\n");
		err = -1;
		goto cleanup;
	}
	skel->rodata->target_pid = pid;
	err = exec_trace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load exec_trace; check BPF privileges and kernel BTF\n");
		goto cleanup;
	}
	ring = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &out, NULL);
	if (!ring) {
		fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
		err = -1;
		goto cleanup;
	}
	err = exec_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach sched:sched_process_exec\n");
		goto cleanup;
	}
	fprintf(stderr, "Tracing successful exec events; pid=%u; Ctrl+C to stop\n", pid);
	fflush(stderr);
	while (!exiting) {
		err = ring_buffer__poll(ring, 100);
		if (err == -EINTR) {
			err = 0;
			continue;
		}
		if (err < 0)
			break;
	}
	/* 先解除挂载，再消费剩余记录，避免退出时丢掉已入队的事件。 */
	exec_trace_bpf__detach(skel);
	if (err >= 0)
		err = ring_buffer__consume(ring);
	fprintf(stderr, "events_written=%" PRIu64 " ringbuf_dropped=%" PRIu64 "\n",
		out.written, (uint64_t)skel->bss->dropped_events);

cleanup:
	if (err < 0)
		fprintf(stderr, "exec_trace failed: %s\n", strerror(-err));
	ring_buffer__free(ring);
	exec_trace_bpf__destroy(skel);
	if (out.file != stdout && fclose(out.file) == EOF) {
		perror("Close output");
		err = -EIO;
	}
	return err < 0 ? 1 : 0;
}
