#ifndef OSMEDIC_COMMON_H
#define OSMEDIC_COMMON_H

#define OSMEDIC_COMM_LEN 16
#define OSMEDIC_PATH_LEN 256
#define OSMEDIC_DISK_LEN 32
#define OSMEDIC_HIST_SLOTS 26

struct exec_event {
    unsigned long long ktime_ns;
    unsigned int pid;
    unsigned int tid;
    unsigned int uid;
    int filename_len;
    char comm[OSMEDIC_COMM_LEN];
    char filename[OSMEDIC_PATH_LEN];
};

struct io_start {
    unsigned long long started_ns;
    unsigned long long bytes;
    unsigned int pid;
    unsigned int major;
    unsigned int minor;
    unsigned int op;
    char comm[OSMEDIC_COMM_LEN];
    char disk[OSMEDIC_DISK_LEN];
};

struct io_hist_key {
    unsigned int major;
    unsigned int minor;
    unsigned int slot;
    char disk[OSMEDIC_DISK_LEN];
};

#endif
