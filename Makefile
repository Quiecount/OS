CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

BUILD_DIR := build
COMMON_DIR := src/common
PROBE_DIR := src/probes
LOADER_DIR := src/loader
VMLINUX := $(BUILD_DIR)/vmlinux.h

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/riscv64/riscv/')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror \
	-I$(BUILD_DIR) -I$(COMMON_DIR)
USER_CFLAGS := -g -O2 -Wall -Wextra -Werror $(shell $(PKG_CONFIG) --cflags libbpf)
USER_LDLIBS := $(shell $(PKG_CONFIG) --libs libbpf) -lelf -lz

PROGRAMS := execsnoop biolatency
BINARIES := $(addprefix $(BUILD_DIR)/,$(PROGRAMS))

.PHONY: all clean check help
.SECONDARY:

all: $(BINARIES)

$(BUILD_DIR):
	mkdir -p $@

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD_DIR)/%.bpf.o: $(PROBE_DIR)/%.bpf.c $(COMMON_DIR)/osmedic.h $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/%: $(LOADER_DIR)/%.c $(BUILD_DIR)/%.skel.h $(COMMON_DIR)/osmedic.h
	$(CC) $(USER_CFLAGS) -I$(BUILD_DIR) -I$(COMMON_DIR) $< -o $@ $(USER_LDLIBS)

check: all
	@for binary in $(BINARIES); do test -x "$$binary"; done
	@echo "STAGE1_BUILD_OK"

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "make        编译两支 eBPF 探针和用户态加载器"
	@echo "make check  编译并检查产物"
	@echo "make clean  删除构建产物"
	@echo "sudo bash scripts/stage1-smoke.sh  运行阶段1端到端验收"
