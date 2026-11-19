# 阶段 0 / 1：使用系统工具链构建学习探针。
OUTPUT := .output
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
LIBBPF_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS ?= $(shell $(PKG_CONFIG) --libs libbpf)
CFLAGS ?= -g -O2 -Wall -Wextra
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
APPS := minimal exec_trace io_latency

.PHONY: all $(APPS) clean check-io-math
all: $(APPS)
minimal: $(OUTPUT)/minimal
exec_trace: $(OUTPUT)/exec_trace
io_latency: $(OUTPUT)/io_latency

$(OUTPUT):
	mkdir -p $@

$(OUTPUT)/vmlinux.h: $(VMLINUX_BTF) | $(OUTPUT)
	$(BPFTOOL) btf dump file $< format c > $@

$(OUTPUT)/exec_trace.bpf.o: probes/exec_trace.h $(OUTPUT)/vmlinux.h
# 保留阶段 1 学习版；场景 3 的同名框架探针由根目录 Makefile 构建。
$(OUTPUT)/io_latency.bpf.o: probes/io_latency_learning.bpf.c probes/io_latency.h $(OUTPUT)/vmlinux.h | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf $(LIBBPF_CFLAGS) -I$(OUTPUT) -Iprobes -c $< -o $@

$(OUTPUT)/%.bpf.o: probes/%.bpf.c | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf $(LIBBPF_CFLAGS) -I$(OUTPUT) -Iprobes -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/exec_trace: probes/exec_trace.h
$(OUTPUT)/io_latency: probes/io_latency.h

$(OUTPUT)/%: loader/%.c $(OUTPUT)/%.skel.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LIBBPF_CFLAGS) -I$(OUTPUT) -Iprobes $< $(LDFLAGS) $(LIBBPF_LIBS) -o $@

$(OUTPUT)/test_io_latency_math: ../tests/test_io_latency_math.c probes/io_latency.h | $(OUTPUT)
	$(CC) $(CPPFLAGS) -std=c11 -O2 -Wall -Wextra -Werror -Iprobes $< -o $@

check-io-math: $(OUTPUT)/test_io_latency_math
	./$(OUTPUT)/test_io_latency_math

clean:
	$(RM) $(addprefix $(OUTPUT)/,$(APPS) $(addsuffix .bpf.o,$(APPS)) $(addsuffix .skel.h,$(APPS))) $(OUTPUT)/vmlinux.h $(OUTPUT)/test_io_latency_math

.DELETE_ON_ERROR:
.SECONDARY:
