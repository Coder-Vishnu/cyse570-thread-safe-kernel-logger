# CYSE 570 Final Project: Thread-Safe Kernel Logging
**Team:** Manavi Kumar and Vishnu Venkatesan 
**Topic:** 7. Thread-Safe Kernel Logging (Audit integrity, tamper resistance)

## Project Overview
This project implements a thread-safe and tamper-evident audit logging system that tracks file access activity in real time on Linux. An eBPF program monitors `openat` system calls and collects details including the process ID, user ID, process name, timestamp, and file path. Events are transferred lock-free from the kernel to a single-writer user space logging service through a BPF ring buffer and Unix domain socket. The logging service organizes the records into a SHA-256 hash chain, signs checkpoints using HMAC-SHA-256, and can detect and identify the first log entry that was modified during verification.

## Repository Structure
- `event.h`: Shared event data structure used by both kernel eBPF code and user space.
- `monitor.bpf.c`: Kernel-space eBPF `tracepoint/syscalls/sys_enter_openat` program that skips excluded PIDs, tracks events with per-CPU counters, and writes records to a 2 MB ring buffer (`BPF_MAP_TYPE_RINGBUF`) for lock-free transfer to user space.
- `collector.c`: User-space `libbpf` program that reads events from the ring buffer, filters paths, and forwards them to `logs/logger.sock`.
- `logger.c`: Single-writer user-space daemon performing SHA-256 hash chaining, HMAC-SHA-256 protected checkpoints, and tamper localization.
- `stress_test.c`: Multi-threaded `pthreads` program that generates concurrent `openat` file-access workloads.
- `Makefile`: Single-command build configuration generating `vmlinux.h`, the eBPF skeleton, and all executables.

## Prerequisites
- **OS / Kernel:** Linux (Ubuntu 20.04 / 22.04 / 24.04) with kernel `>= 5.8` and BTF enabled (`/sys/kernel/btf/vmlinux`).
- **Packages:** `clang`, `llvm`, `bpftool` (`linux-tools-$(uname -r)`), `libbpf` (`>= 1.0`), `gcc`, `make`, `libssl-dev`, `libelf-dev`, and `zlib1g-dev`.

Install dependencies on Ubuntu:
```bash
sudo apt update
sudo apt install -y git clang llvm linux-tools-common linux-tools-$(uname -r) gcc make libssl-dev pkg-config libelf-dev zlib1g-dev
```

## Build Instructions
Compile the eBPF bytecode, skeleton header, and all user-space executables (`collector`, `logger`, and `stress_test`) with:
```bash
make

## How to Run

### 1. Live Kernel Capture and Cryptographic Logging
Open three terminals in the project directory (`~/cyse570-thread-safe-kernel-logger`):

- **Terminal 1 (Start the single-writer logging daemon):**
  ```bash
  ./logger daemon
  ```

- **Terminal 2 (Start the eBPF collector and connect it to the daemon socket):**
  ```bash
  sudo ./collector --filter /tmp/cyse570_demo --socket logs/logger.sock --exclude-pid $(pgrep -x logger)
  ```
  *(Note: `--exclude-pid $(pgrep -x logger)` prevents the eBPF program from logging the daemon's own file operations.)*

- **Terminal 3 (Trigger real file accesses and verify the hash chain):**
  ```bash
  mkdir -p /tmp/cyse570_demo
  touch /tmp/cyse570_demo/file1.txt /tmp/cyse570_demo/file2.txt
  cat /tmp/cyse570_demo/file1.txt
  ./logger verify
  cat logs/events.log
  ```
  Expected verification output:
  ```text
  PASS: log hash chain and checkpoint verified
  Verified entries: 3
  ```

---

### 2. Multi-Threaded Concurrency Stress Test
To test concurrent file-access capture and hash chaining without event loss, start from a clean log state across three terminals:

- **Terminal 1 (Reset previous test logs and start the daemon):**
  ```bash
  rm -rf logs checkpoints
  ./logger daemon
  ```

- **Terminal 2 (Start the eBPF collector in quiet mode):**
  ```bash
  sudo ./collector --filter /tmp/cyse570_stress --socket logs/logger.sock --exclude-pid $(pgrep -x logger) --quiet
  ```

- **Terminal 3 (Run 8 concurrent threads × 50 `openat` operations = 400 total events):**
  ```bash
  ./stress_test /tmp/cyse570_stress 8 50
  ./logger verify
  ```
  Expected verification output:
  ```text
  PASS: log hash chain and checkpoint verified
  Verified entries: 400
  ```

- **View Kernel Ring-Buffer Telemetry:**
  Press `Ctrl+C` in **Terminal 2** to stop the collector and print kernel capture/drop statistics:
  ```text
  --- eBPF Ring Buffer Telemetry ---
  Kernel events captured  : <total system openat calls>
  Kernel events dropped   : 0
  Userspace events matched: 400
  Daemon logged (OK)      : 400
  Daemon errors (FAIL)    : 0
  ```

---

### 3. Tamper Detection and Localization Demo
With valid entries stored in `logs/events.log` from either test above, simulate an unauthorized modification to entry `2` and re-run verification:

```bash
sed -i '2s|/tmp/|/tmp/tampered_|' logs/events.log
./logger verify
```
Expected output pinpointing the exact compromised sequence number:
```text
FAIL: first inconsistent entry near sequence 2
```

---

### 4. Cleanup Between Runs
Press `Ctrl+C` in the daemon and collector terminals to stop both processes, then remove temporary logs and test directories:
```bash
rm -rf logs checkpoints /tmp/cyse570_demo /tmp/cyse570_stress
```