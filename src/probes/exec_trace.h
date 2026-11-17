#ifndef OSMEDIC_EXEC_TRACE_H
#define OSMEDIC_EXEC_TRACE_H

/* __u32 等类型由内核 vmlinux.h 或用户态 linux/types.h 提供。 */
#define EXEC_COMM_LEN 16
#define EXEC_FILENAME_LEN 256

struct exec_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__s32 filename_result;
	char comm[EXEC_COMM_LEN];
	char filename[EXEC_FILENAME_LEN];
};

#endif
