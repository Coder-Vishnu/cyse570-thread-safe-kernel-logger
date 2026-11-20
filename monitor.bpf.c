#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Lockless 2 MB ring buffer for sending file-access events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024); 
} events SEC(".maps");

// Set of PIDs to ignore so the collector and logger do not log themselves
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u8);
} excluded_pids SEC(".maps");

// Per-CPU counters tracking captured events (index 0) and dropped events (index 1)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");

// Updates the captured or dropped event counter
static __always_inline void bump_stat(u32 idx) {
    u64 *val = bpf_map_lookup_elem(&stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

// Captures file-open syscalls in the kernel and submits them to the ring buffer
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (bpf_map_lookup_elem(&excluded_pids, &pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bump_stat(1); 
        return 0;
    }

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->uid = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    bump_stat(0);
    return 0;
}