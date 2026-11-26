# 太卡了先生 · 构建脚本
# 用法（在 openEuler 虚拟机、仓库根目录下）：
#   make                     编译全部探针 + 加载器（execsnoop/lock_contention）+ 故障注入工具
#   sudo ./build/execsnoop        运行探针①（表格输出）
#   sudo ./build/lock_contention  运行场景5 加载器（JSONL 输出，--help 见接口契约 §2.5）
#   make clean               清理产物与自动生成的 vmlinux.h

BUILD  := build
CLANG  ?= clang
CC     ?= gcc

# 自动发现 src/probes/ 下全部探针源码，一一编译成 BPF 目标
BPF_OBJS := $(patsubst src/probes/%.bpf.c,$(BUILD)/%.bpf.o,$(wildcard src/probes/*.bpf.c))

# 故障注入用 C 程序（纯用户态）
# lock_bomb：原名 lock_contention，让位给场景5 加载器 build/lock_contention（见开发指南_场景5 §3.3）
FAULT_BINS := $(BUILD)/syscall_bomb $(BUILD)/lock_bomb

# 量化测试用 C 程序（tests/run_quant.sh 一键序列的组成部分）
# futex_calib：确定性 timeout-futex 校准源（计数/延迟/P99 真值）
# futex_bomb：FUTEX_WAKE 洪泛微基准（极限吞吐损失）
TEST_BINS := $(BUILD)/futex_calib $(BUILD)/futex_bomb

.PHONY: all clean

all: $(BPF_OBJS) $(BUILD)/execsnoop $(BUILD)/lock_contention $(FAULT_BINS) $(TEST_BINS)

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

# 场景5 的用户态加载器（其余场景加载器按此模板补齐）
$(BUILD)/lock_contention.o: src/loader/lock_contention.c src/events.h
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall -Isrc -c $< -o $@

$(BUILD)/lock_contention: $(BUILD)/lock_contention.o $(BUILD)/lock_contention.bpf.o
	$(CC) $< -o $@ -lbpf -lelf -lz

# 故障注入工具
$(BUILD)/syscall_bomb: faults/syscall_bomb.c
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall $< -o $@

$(BUILD)/lock_bomb: faults/lock_bomb.c
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall -pthread $< -o $@

# 量化测试工具
$(BUILD)/futex_calib: tests/futex_calib.c
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall -pthread $< -o $@

$(BUILD)/futex_bomb: tests/futex_bomb.c
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall $< -o $@

clean:
	rm -rf $(BUILD) src/vmlinux.h
