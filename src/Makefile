# 阶段 0 / 1：使用系统工具链构建学习探针。
OUTPUT := .output
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
LIBBPF_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS ?= $(shell $(PKG_CONFIG) --libs libbpf)
CFLAGS ?= -g -O2 -Wall -Wextra
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
APPS := minimal exec_trace

.PHONY: all $(APPS) clean
all: $(APPS)
minimal: $(OUTPUT)/minimal
exec_trace: $(OUTPUT)/exec_trace

$(OUTPUT):
	mkdir -p $@

$(OUTPUT)/vmlinux.h: $(VMLINUX_BTF) | $(OUTPUT)
	$(BPFTOOL) btf dump file $< format c > $@

$(OUTPUT)/exec_trace.bpf.o: probes/exec_trace.h $(OUTPUT)/vmlinux.h

$(OUTPUT)/%.bpf.o: probes/%.bpf.c | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf $(LIBBPF_CFLAGS) -I$(OUTPUT) -Iprobes -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/exec_trace: probes/exec_trace.h

$(OUTPUT)/%: loader/%.c $(OUTPUT)/%.skel.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LIBBPF_CFLAGS) -I$(OUTPUT) -Iprobes $< $(LDFLAGS) $(LIBBPF_LIBS) -o $@

clean:
	$(RM) $(addprefix $(OUTPUT)/,$(APPS) $(addsuffix .bpf.o,$(APPS)) $(addsuffix .skel.h,$(APPS))) $(OUTPUT)/vmlinux.h

.DELETE_ON_ERROR:
.SECONDARY:
