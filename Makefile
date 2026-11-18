# 太卡了先生 · 构建脚本
# 用法（在 openEuler 虚拟机、仓库根目录下）：
#   make                     编译全部探针 + execsnoop 加载器 + 故障注入工具
#   sudo ./build/execsnoop   运行探针①（其余场景的加载器随阶段 2 逐个补齐）
#   make clean               清理产物与自动生成的 vmlinux.h

BUILD  := build
CLANG  ?= clang
CC     ?= gcc

# 自动发现 src/probes/ 下全部探针源码，一一编译成 BPF 目标
BPF_OBJS := $(patsubst src/probes/%.bpf.c,$(BUILD)/%.bpf.o,$(wildcard src/probes/*.bpf.c))

# 故障注入用 C 程序（纯用户态）
FAULT_BINS := $(BUILD)/syscall_bomb $(BUILD)/lock_contention

.PHONY: all clean

all: $(BPF_OBJS) $(BUILD)/execsnoop $(FAULT_BINS)

# 从当前内核 BTF 自动生成内核类型头（只在缺失时执行；git 不跟踪）
src/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# eBPF 探针：clang 交叉编译到 BPF 目标（产物是字节码，不是本机机器码）
$(BUILD)/%.bpf.o: src/probes/%.bpf.c src/events.h src/vmlinux.h
	@mkdir -p $(BUILD)
	$(CLANG) -O2 -g -target bpf -Isrc -c $< -o $@

# 探针① 的用户态加载器（其余场景加载器按此模板在阶段 2 补齐）
$(BUILD)/execsnoop.o: src/loader/execsnoop.c src/events.h
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall -Isrc -c $< -o $@

$(BUILD)/execsnoop: $(BUILD)/execsnoop.o $(BUILD)/execsnoop.bpf.o
	$(CC) $< -o $@ -lbpf -lelf -lz

# 故障注入工具
$(BUILD)/syscall_bomb: faults/syscall_bomb.c
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall $< -o $@

$(BUILD)/lock_contention: faults/lock_contention.c
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall -pthread $< -o $@

clean:
	rm -rf $(BUILD) src/vmlinux.h
