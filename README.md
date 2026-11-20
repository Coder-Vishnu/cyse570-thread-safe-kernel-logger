# CYSE 570 Final Project: Thread-Safe Kernel Logging
**Team:** Manavi Kumar and Vishnu Venkatesan 
**Topic:** 7. Thread-Safe Kernel Logging (Audit integrity, tamper resistance)

## Project Overview
This project implements a thread-safe and tamper-evident audit logging system that tracks file access activity in real time on Linux. An eBPF program monitors `openat` system calls and collects details including the process ID, user ID, process name, timestamp, and file path. Events are transferred lock-free from the kernel to a single-writer user space logging service through a BPF ring buffer and Unix domain socket. The logging service organizes the records into a SHA-256 hash chain, signs checkpoints using HMAC-SHA-256, and can detect and identify the first log entry that's changed during verification.

## Repository Structure
- `event.h`: Shared event data structure used by both kernel eBPF code and user space.
- `monitor.bpf.c`: Kernel-space eBPF `tracepoint/syscalls/sys_enter_openat` hook, PID exclusion map, per-CPU event counters, and 2 MB `BPF_MAP_TYPE_RINGBUF`.
- `collector.c`: User-space `libbpf` ring-buffer consumer that filters/sanitizes paths and forwards events to `logs/logger.sock`.
- `logger.c`: Single-writer user-space daemon performing SHA-256 hash chaining, HMAC-SHA-256 protected checkpoints, and tamper localization.
- `stress_test.c`: Multi-threaded `pthreads` benchmark tool for generating concurrent `openat` workloads.
- `Makefile`: Single-command build configuration generating `vmlinux.h`, the eBPF skeleton, and all executables.

## Prerequisites
- **OS / Kernel:** Linux (Ubuntu 20.04 / 22.04 / 24.04) with kernel `>= 5.8` and BTF enabled (`/sys/kernel/btf/vmlinux`).
- **Packages:** `clang`, `llvm`, `bpftool` (`linux-tools-$(uname -r)`), `libbpf` (`>= 1.0`), `gcc`, `make`, `libssl-dev`, `libelf-dev`, and `zlib1g-dev`.

Install dependencies on Ubuntu:
```bash
sudo apt update
sudo apt install -y git clang llvm linux-tools-common linux-tools-$(uname -r) gcc make libssl-dev pkg-config libelf-dev zlib1g-dev