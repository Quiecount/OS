#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "io_latency.h"
#include "io_latency.skel.h"

static volatile sig_atomic_t exiting;
static bool verbose;

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

static int parse_unsigned(const char *text, unsigned long maximum, unsigned long *value)
{
	char *end;

	if (!*text)
		return -1;
	for (const char *p = text; *p; p++)
		if (*p < '0' || *p > '9')
			return -1;
	errno = 0;
	*value = strtoul(text, &end, 10);
	return errno || *end || *value > maximum ? -1 : 0;
}

static int parse_device(const char *text, __u32 *major, __u32 *minor)
{
	char *copy = strdup(text), *colon;
	unsigned long first, second;
	int err = -1;

	if (!copy)
		return -1;
	colon = strchr(copy, ':');
	if (colon) {
		*colon++ = '\0';
		if (!parse_unsigned(copy, 4095, &first) &&
		    !parse_unsigned(colon, 1048575, &second)) {
			*major = first;
			*minor = second;
			err = 0;
		}
	}
	free(copy);
	return err;
}

static uint64_t monotonic_ns(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static int write_snapshot(struct io_latency_bpf *skel, FILE *file,
			 struct io_histogram *per_cpu, int ncpus, uint64_t start_ns,
			 bool filter, __u32 major, __u32 minor, bool final)
{
	uint64_t end_ns = monotonic_ns();

	for (__u32 operation = 0; operation < IO_LATENCY_OPERATIONS; operation++) {
		struct io_histogram total = {};
		uint64_t count = 0;

		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.histograms), &operation, per_cpu))
			return -errno;
		for (int cpu = 0; cpu < ncpus; cpu++) {
			for (int slot = 0; slot < IO_LATENCY_SLOTS; slot++)
				total.slots[slot] += per_cpu[cpu].slots[slot];
			total.bytes += per_cpu[cpu].bytes;
			total.latency_total_ns += per_cpu[cpu].latency_total_ns;
			total.errors += per_cpu[cpu].errors;
		}
		for (int slot = 0; slot < IO_LATENCY_SLOTS; slot++)
			count += total.slots[slot];
		fprintf(file, "{\"event\":\"block_io_latency\",\"clock\":\"monotonic\","
			"\"window\":{\"start_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64 "},"
			"\"cumulative\":true,\"final\":%s,\"device\":",
			start_ns, end_ns, final ? "true" : "false");
		if (filter)
			fprintf(file, "{\"major\":%u,\"minor\":%u}", major, minor);
		else
			fputs("null", file);
		fprintf(file, ",\"operation\":\"%s\",\"requests\":%" PRIu64
			",\"bytes\":%" PRIu64 ",\"latency_total_ns\":%" PRIu64
			",\"errors\":%" PRIu64 ",\"bucket_scale\":\"log2_us\",\"histogram\":[",
			operation == 0 ? "read" : "write", count, (uint64_t)total.bytes,
			(uint64_t)total.latency_total_ns, (uint64_t)total.errors);
		for (int slot = 0; slot < IO_LATENCY_SLOTS; slot++)
			fprintf(file, "%s%" PRIu64, slot ? "," : "", (uint64_t)total.slots[slot]);
		fputs("]}\n", file);
	}
	if (fflush(file) == EOF || ferror(file))
		return -EIO;
	return 0;
}

static void usage(FILE *file, const char *program)
{
	fprintf(file, "Usage: %s [-d MAJOR:MINOR] [-i SECONDS] [-n COUNT] [-o FILE|-] [-v]\n"
		"  -d, --device DEV    Whole-disk device number; default: all devices\n"
		"  -i, --interval SEC  Snapshot interval, 1..3600 (default: 1)\n"
		"  -n, --count COUNT   Number of snapshots, 1..1000000 (default: until Ctrl+C)\n"
		"  -o, --output FILE   Append JSON Lines to FILE (default: stdout)\n"
		"  -v, --verbose       Show libbpf debug logs on stderr\n"
		"  -h, --help          Show help\n", program);
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{"device", required_argument, NULL, 'd'},
		{"interval", required_argument, NULL, 'i'},
		{"count", required_argument, NULL, 'n'},
		{"output", required_argument, NULL, 'o'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};
	struct io_latency_bpf *skel = NULL;
	struct io_histogram *per_cpu = NULL;
	struct sigaction action = {.sa_handler = handle_signal};
	const char *output_path = "-";
	FILE *output = stdout;
	unsigned long interval = 1, snapshots = 0, emitted = 0;
	__u32 major = 0, minor = 0;
	bool filter = false;
	uint64_t start_ns;
	int option, ncpus, err = 0;

	_Static_assert(sizeof(struct io_histogram) % 8 == 0, "per-CPU value alignment");
	while ((option = getopt_long(argc, argv, "d:i:n:o:vh", options, NULL)) != -1) {
		switch (option) {
		case 'd':
			if (parse_device(optarg, &major, &minor)) {
				fprintf(stderr, "Invalid device: %s\n", optarg);
				return 1;
			}
			filter = true;
			break;
		case 'i':
		case 'n': {
			unsigned long value;

			if (parse_unsigned(optarg, option == 'i' ? 3600 : 1000000, &value) || !value) {
				fprintf(stderr, "Invalid %s: %s\n", option == 'i' ? "interval" : "count", optarg);
				return 1;
			}
			if (option == 'i') interval = value;
			else snapshots = value;
			break;
		}
		case 'o': output_path = optarg; break;
		case 'v': verbose = true; break;
		case 'h': usage(stdout, argv[0]); return 0;
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
	if (strcmp(output_path, "-")) {
		output = fopen(output_path, "a");
		if (!output) {
			perror("Open output");
			return 1;
		}
	}
	ncpus = libbpf_num_possible_cpus();
	if (ncpus < 1) { err = -EINVAL; goto cleanup; }
	per_cpu = calloc(ncpus, sizeof(*per_cpu));
	if (!per_cpu) { err = -ENOMEM; goto cleanup; }
	skel = io_latency_bpf__open();
	if (!skel) { err = -(errno ? errno : EIO); goto cleanup; }
	skel->rodata->filter_device = filter;
	skel->rodata->target_major = major;
	skel->rodata->target_minor = minor;
	err = io_latency_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Check BPF privileges, kernel BTF and block tracepoint BTF support\n");
		goto cleanup;
	}
	start_ns = monotonic_ns();
	err = io_latency_bpf__attach(skel);
	if (err) goto cleanup;
	fprintf(stderr, "Tracing block IO latency; interval=%lu; Ctrl+C to stop\n", interval);
	fflush(stderr);
	while (!exiting) {
		struct timespec deadline;
		uint64_t deadline_ns = start_ns + (emitted + 1) * interval * 1000000000ULL;

		deadline.tv_sec = deadline_ns / 1000000000ULL;
		deadline.tv_nsec = deadline_ns % 1000000000ULL;
		while (!exiting) {
			err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
			if (err != EINTR) break;
		}
		if (exiting) { err = 0; break; }
		if (err) { err = -err; break; }
		if (snapshots && emitted + 1 >= snapshots) break;
		err = write_snapshot(skel, output, per_cpu, ncpus, start_ns, filter, major, minor, false);
		if (err) break;
		emitted++;
	}
	/* 停止写入后再读最终快照，使直方图和累计指标稳定。 */
	io_latency_bpf__detach(skel);
	if (!err)
		err = write_snapshot(skel, output, per_cpu, ncpus, start_ns, filter, major, minor, true);
	{
		__u64 key, next;
		unsigned int unfinished = 0;
		int fd = bpf_map__fd(skel->maps.starts);

		if (!bpf_map_get_next_key(fd, NULL, &key)) {
			do { unfinished++; next = key; }
			while (!bpf_map_get_next_key(fd, &next, &key));
		}
		fprintf(stderr, "tracking_failures=%" PRIu64 " partial_completions=%" PRIu64
			" requeued_requests=%" PRIu64 " unfinished=%u\n",
			(uint64_t)skel->bss->tracking_failures, (uint64_t)skel->bss->partial_completions,
			(uint64_t)skel->bss->requeued_requests, unfinished);
	}

cleanup:
	if (err)
		fprintf(stderr, "io_latency failed: %s\n", strerror(-err));
	io_latency_bpf__destroy(skel);
	free(per_cpu);
	if (output != stdout && fclose(output) == EOF) {
		perror("Close output");
		err = -EIO;
	}
	return err ? 1 : 0;
}
