# 太卡了先生 · 构建脚本
# 用法（在 openEuler 虚拟机、仓库根目录下）：
#   make                     编译全部探针 + 已实现的加载器 + 故障注入工具
#   make clean               清理产物与自动生成的 vmlinux.h

BUILD  := build
CLANG  ?= clang
CC     ?= gcc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/riscv64/riscv/')
USER_CFLAGS := -g -O2 -Wall -Wextra -Werror $(shell $(PKG_CONFIG) --cflags libbpf)
USER_LIBS := $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

# 自动发现 src/probes/ 下全部探针源码，一一编译成 BPF 目标
BPF_OBJS := $(patsubst src/probes/%.bpf.c,$(BUILD)/%.bpf.o,$(wildcard src/probes/*.bpf.c))

# 故障注入用 C 程序（纯用户态）
FAULT_BINS := $(BUILD)/syscall_bomb $(BUILD)/lock_contention

.PHONY: all clean check
.SECONDARY:

all: $(BPF_OBJS) $(BUILD)/execsnoop $(BUILD)/syscall_hotspot $(BUILD)/cpu_hog $(FAULT_BINS)

# 从当前内核 BTF 自动生成内核类型头（只在缺失时执行；git 不跟踪）
src/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# eBPF 探针：clang 交叉编译到 BPF 目标（产物是字节码，不是本机机器码）
$(BUILD)/%.bpf.o: src/probes/%.bpf.c src/events.h src/vmlinux.h src/common/osmedic.h
	@mkdir -p $(BUILD)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror -Isrc -Isrc/common -c $< -o $@

$(BUILD)/%.skel.h: $(BUILD)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/syscall_hotspot $(BUILD)/cpu_hog: $(BUILD)/%: src/loader/%.c $(BUILD)/%.skel.h src/common/osmedic.h src/common/monitor_util.h
	$(CC) $(USER_CFLAGS) -I$(BUILD) -Isrc -Isrc/common $< -o $@ $(USER_LIBS)

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

check: all
	@test -x $(BUILD)/syscall_hotspot && test -x $(BUILD)/cpu_hog
	@echo "STAGE2_BUILD_OK"

clean:
	rm -rf $(BUILD) src/vmlinux.h
