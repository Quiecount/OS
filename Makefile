# 太卡了先生 · 构建脚本
# 用法（在 openEuler 虚拟机、仓库根目录下）：
#   make                     编译
#   sudo ./build/execsnoop   运行探针①
#   make clean               清理产物与生成的 vmlinux.h

BUILD  := build
CLANG  ?= clang
CC     ?= gcc

.PHONY: all clean

all: $(BUILD)/execsnoop

# 从当前内核 BTF 自动生成内核类型头（只在文件缺失时执行；git 不跟踪）
src/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# ① 编译 eBPF 探针：clang 交叉编译到 BPF 目标（产物是字节码，不是本机机器码）
$(BUILD)/execsnoop.bpf.o: src/probes/execsnoop.bpf.c src/event.h src/vmlinux.h
	@mkdir -p $(BUILD)
	$(CLANG) -O2 -g -target bpf -Isrc -c $< -o $@

# ② 编译用户态加载器
$(BUILD)/execsnoop.o: src/loader/execsnoop.c src/event.h
	@mkdir -p $(BUILD)
	$(CC) -O2 -Wall -Isrc -c $< -o $@

# ③ 链接加载器（libbpf 依赖 libelf 和 zlib）
$(BUILD)/execsnoop: $(BUILD)/execsnoop.o $(BUILD)/execsnoop.bpf.o
	$(CC) $< -o $@ -lbpf -lelf -lz

clean:
	rm -rf $(BUILD) src/vmlinux.h
