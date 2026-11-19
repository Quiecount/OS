# 太卡了先生 · 构建脚本
# 用法（在 openEuler 虚拟机、仓库根目录下）：
#   make                     编译全部探针 + execsnoop 加载器 + 故障注入工具
#   sudo ./build/execsnoop   运行探针①（其余场景的加载器随阶段 2 逐个补齐）
#   make clean               清理产物与自动生成的 vmlinux.h

BUILD  := build
CLANG  ?= clang
CC     ?= gcc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
LIBBPF_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS ?= $(shell $(PKG_CONFIG) --libs libbpf)
CFLAGS ?= -O2 -g -Wall -Wextra
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

# 自动发现 src/probes/ 下全部探针源码，一一编译成 BPF 目标
BPF_OBJS := $(patsubst src/probes/%.bpf.c,$(BUILD)/%.bpf.o,$(wildcard src/probes/*.bpf.c))

# 故障注入用 C 程序（纯用户态）
FAULT_BINS := $(BUILD)/syscall_bomb $(BUILD)/lock_contention

.PHONY: all clean check

all: $(BPF_OBJS) $(BUILD)/execsnoop $(FAULT_BINS)

# 从当前内核 BTF 自动生成内核类型头（只在缺失时执行；git 不跟踪）
src/vmlinux.h: $(VMLINUX_BTF)
	$(BPFTOOL) btf dump file $< format c > $@

# eBPF 探针：clang 交叉编译到 BPF 目标（产物是字节码，不是本机机器码）
$(BUILD)/%.bpf.o: src/probes/%.bpf.c src/events.h src/vmlinux.h
	@mkdir -p $(BUILD)
	$(CLANG) -O2 -g -target bpf $(LIBBPF_CFLAGS) -Isrc -MMD -MP -c $< -o $@

# 探针① 的用户态加载器（其余场景加载器按此模板在阶段 2 补齐）
$(BUILD)/execsnoop.o: src/loader/execsnoop.c src/events.h src/loader/json_output.h
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LIBBPF_CFLAGS) -Isrc -MMD -MP -c $< -o $@

$(BUILD)/execsnoop: $(BUILD)/execsnoop.o $(BUILD)/execsnoop.bpf.o
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@ $(LIBBPF_LIBS)

# 故障注入工具
$(BUILD)/syscall_bomb: faults/syscall_bomb.c
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -o $@

$(BUILD)/lock_contention: faults/lock_contention.c
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread $< $(LDFLAGS) -o $@

check: all
	python3 tests/test_execsnoop.py ExecsnoopTest.test_cli_validation
	$(MAKE) -C src check-io-math

clean:
	rm -rf $(BUILD) src/vmlinux.h

-include $(wildcard $(BUILD)/*.d)
.DELETE_ON_ERROR:
