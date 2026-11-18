// 两端共享的事件结构体：内核态探针填写 → ringbuf → 用户态加载器读取
// 注意：两边字段布局必须完全一致（一个字节都不能差），所以放在公共头文件里
#ifndef EVENT_H
#define EVENT_H

struct event {
    unsigned int pid;       // 进程 ID
    unsigned int uid;       // 用户 ID
    char comm[16];          // 进程名（内核 comm 字段上限 16 字节）
    char filename[128];     // 被执行的程序路径（超长路径会被截断）
};

#endif /* EVENT_H */
