# 太卡了先生 · 构建脚本
# 用法（在 openEuler 虚拟机、仓库根目录下）：
#   make                     编译全部探针 + 已实现的加载器 + 故障注入工具
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
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/riscv64/riscv/')
USER_CFLAGS := $(CFLAGS) -Werror $(LIBBPF_CFLAGS)
USER_LIBS := $(LIBBPF_LIBS) -lelf -lz

# 自动发现 src/probes/ 下全部探针源码，一一编译成 BPF 目标
BPF_OBJS := $(patsubst src/probes/%.bpf.c,$(BUILD)/%.bpf.o,$(wildcard src/probes/*.bpf.c))

# 故障注入用 C 程序（纯用户态）
FAULT_BINS := $(BUILD)/syscall_bomb $(BUILD)/lock_workload

.PHONY: all clean check check-verifier check-stage1
.SECONDARY:

STAGE2_BINS := $(addprefix $(BUILD)/,syscall_hotspot cpu_hog io_latency mem_pressure lock_contention)
all: $(BPF_OBJS) $(BUILD)/execsnoop $(STAGE2_BINS) $(FAULT_BINS)

.PHONY: quality-tools quality-unit
quality-tools: check $(BUILD)/quality-workload $(BUILD)/quality-reference quality-unit

quality-unit: $(BUILD)/test-window-merge $(BUILD)/test-latency-hist $(BUILD)/test-cpu-rules
	./$(BUILD)/test-window-merge
	./$(BUILD)/test-latency-hist
	./$(BUILD)/test-cpu-rules

$(BUILD)/test-cpu-rules: tests/test-cpu-rules.c src/common/cpu_rules.h
	@mkdir -p $(BUILD)
	$(CC) $(USER_CFLAGS) -Isrc/common $< -o $@

$(BUILD)/test-window-merge: tests/test-window-merge.c src/common/window_merge.h src/common/osmedic.h src/common/latency_hist.h
	@mkdir -p $(BUILD)
	$(CC) $(USER_CFLAGS) -Isrc/common $< -o $@

$(BUILD)/test-latency-hist: tests/test-latency-hist.c src/common/latency_hist.h
	@mkdir -p $(BUILD)
	$(CC) $(USER_CFLAGS) -Isrc/common $< -o $@

$(BUILD)/quality-workload: tests/quality-workload.c
	$(CC) $(USER_CFLAGS) -pthread $< -o $@

$(BUILD)/quality-reference: tests/quality-reference.c $(BUILD)/quality_reference.skel.h
	$(CC) $(USER_CFLAGS) -Ibuild $< -o $@ $(USER_LIBS)

$(BUILD)/stage2_workload: tests/stage2_workload.c
	@mkdir -p $(BUILD)
	$(CC) $(USER_CFLAGS) -fno-omit-frame-pointer -pthread $< -o $@

.PHONY: check-stage2
check-stage2: all quality-unit $(BUILD)/stage2_workload
	PYTHONDONTWRITEBYTECODE=1 python3 tests/test_stage2.py
	bash tests/stage2-two-scenarios.sh

# 从当前内核 BTF 自动生成内核类型头（只在缺失时执行；git 不跟踪）
src/vmlinux.h: $(VMLINUX_BTF)
	$(BPFTOOL) btf dump file $< format c > $@

# eBPF 探针：clang 交叉编译到 BPF 目标（产物是字节码，不是本机机器码）
$(BUILD)/%.bpf.o: src/probes/%.bpf.c src/events.h src/vmlinux.h src/common/osmedic.h src/common/latency_hist.h
	@mkdir -p $(BUILD)
	$(CLANG) -O2 -g -target bpf $(LIBBPF_CFLAGS) -D__TARGET_ARCH_$(ARCH) -Wall -Werror -Isrc -Isrc/common -MMD -MP -c $< -o $@

$(BUILD)/%.skel.h: $(BUILD)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD)/syscall_hotspot $(BUILD)/cpu_hog: $(BUILD)/%: src/loader/%.c $(BUILD)/%.skel.h src/common/osmedic.h src/common/monitor_util.h src/loader/json_output.h src/common/proc_cpu.h src/common/latency_hist.h src/common/window_merge.h src/common/cpu_rules.h
	$(CC) $(USER_CFLAGS) -I$(BUILD) -Isrc -Isrc/common $< -o $@ $(USER_LIBS)

$(BUILD)/io_latency $(BUILD)/mem_pressure $(BUILD)/lock_contention: $(BUILD)/%: src/loader/stage2.c $(addprefix $(BUILD)/,io_latency.skel.h mem_pressure.skel.h lock_contention.skel.h) src/common/stage2.h src/common/monitor_util.h src/loader/json_output.h
	$(CC) $(USER_CFLAGS) -DOSMEDIC_NAME='"$*"' -I$(BUILD) -Isrc -Isrc/common $< -o $@ $(USER_LIBS)

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

$(BUILD)/lock_workload: faults/lock_contention.c
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread $< $(LDFLAGS) -o $@

check: all
	python3 tests/test_execsnoop.py ExecsnoopTest.test_cli_validation
	$(MAKE) -C src check-io-math
	@test -x $(BUILD)/syscall_hotspot && test -x $(BUILD)/cpu_hog
	@echo "STAGE2_BUILD_OK"

$(BUILD)/verifier_lab: src/loader/verifier_lab.c
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LIBBPF_CFLAGS) $< $(LDFLAGS) -o $@ $(LIBBPF_LIBS)

check-verifier: $(BUILD)/verifier_lab
	PYTHONDONTWRITEBYTECODE=1 python3 tests/verifier_lab.py

check-stage1:
	PYTHONDONTWRITEBYTECODE=1 python3 tests/stage1_acceptance.py

clean:
	rm -rf $(BUILD) src/vmlinux.h

-include $(wildcard $(BUILD)/*.d)
.DELETE_ON_ERROR:
