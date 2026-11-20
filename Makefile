# Compiler and eBPF tool configuration
CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
USER_CFLAGS := -O2 -Wall -Wextra -I/usr/local/include -I/usr/include
USER_LDFLAGS := -L/usr/local/lib64 -L/usr/local/lib -L/usr/lib64 -Wl,-rpath,/usr/local/lib64:/usr/local/lib:/usr/lib64 -lbpf -lelf -lz

# Builds all binaries
all: collector logger stress_test

# Generates kernel type definitions from BTF
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compiles eBPF kernel bytecode
monitor.bpf.o: monitor.bpf.c vmlinux.h event.h
	$(CLANG) $(BPF_CFLAGS) -c monitor.bpf.c -o monitor.bpf.o

# Generates libbpf skeleton header
monitor.skel.h: monitor.bpf.o
	$(BPFTOOL) gen skeleton monitor.bpf.o > monitor.skel.h

# Builds user-space eBPF collector
collector: collector.c monitor.skel.h event.h
	$(CC) $(USER_CFLAGS) collector.c -o collector $(USER_LDFLAGS)

# Builds single-writer cryptographic logging daemon
logger: logger.c
	$(CC) -O2 -Wall logger.c -o logger -lcrypto

# Builds multi-threaded concurrency stress test
stress_test: stress_test.c
	$(CC) -O2 -Wall -pthread stress_test.c -o stress_test

# Removes all generated headers, object files, and binaries
clean:
	rm -f vmlinux.h monitor.bpf.o monitor.skel.h collector logger stress_test