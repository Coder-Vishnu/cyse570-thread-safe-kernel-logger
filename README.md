# cyse570-thread-safe-kernel-logger
## Architecture Overview
- `monitor.bpf.c` / `event.h`: Kernel-space eBPF `sys_enter_openat` tracepoint hook using a lockless `BPF_MAP_TYPE_RINGBUF`.
- `collector.c`: User-space `libbpf` consumer forwarding kernel events over a Unix domain socket (`logs/logger.sock`).
- `logger.c`: Single-writer user-space daemon performing SHA-256 hash chaining, HMAC-protected checkpoints, and tamper localization.
- `stress_test.c`: Multi-threaded `pthreads` concurrency benchmark harness.
