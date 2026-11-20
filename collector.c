#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "event.h"
#include "monitor.skel.h"

static volatile sig_atomic_t exiting = 0;
static const char *path_filter = NULL;
static const char *socket_path = NULL;
static int quiet_mode = 0;

static unsigned long long userspace_seen = 0;
static unsigned long long daemon_ok = 0;
static unsigned long long daemon_fail = 0;

// Stops the collector loop when Ctrl+C or SIGTERM is received
static void sig_handler(int sig) {
    (void)sig;
    exiting = 1;
}

// Replaces spaces, newlines, or pipe characters so the daemon parser accepts the path
static void sanitize_path(const char *src, char *dst, size_t dst_sz) {
    size_t i = 0;
    if (!src || src[0] == '\0') {
        snprintf(dst, dst_sz, "<empty>");
        return;
    }
    for (; src[i] != '\0' && i + 1 < dst_sz; i++) {
        char c = src[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '|')
            dst[i] = '_';
        else
            dst[i] = c;
    }
    dst[i] = '\0';
}

// Sends a single captured file-access event to the logging daemon over a Unix socket
static int forward_to_daemon(unsigned int pid, unsigned int uid, const char *raw_path) {
    char safe_path[MAX_FILENAME_LEN];
    sanitize_path(raw_path, safe_path, sizeof(safe_path));

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    char msg[512];
    int n = snprintf(msg, sizeof(msg), "%u %u %s\n", pid, uid, safe_path);
    if (n <= 0 || write(fd, msg, (size_t)n) != n) {
        close(fd);
        return -1;
    }

    char resp[32] = {0};
    ssize_t r = read(fd, resp, sizeof(resp) - 1);
    close(fd);

    return (r > 0 && strncmp(resp, "OK", 2) == 0) ? 0 : -1;
}

// Processes each event read from the BPF ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct event))
        return 0;

    const struct event *e = data;
    if (path_filter && strncmp(e->filename, path_filter, strlen(path_filter)) != 0)
        return 0;

    userspace_seen++;
    if (!quiet_mode) {
        printf("[%llu] PID=%u UID=%u COMM=%-15s FILE=%s\n",
               e->timestamp_ns, e->pid, e->uid, e->comm, e->filename);
    }

    if (socket_path) {
        if (forward_to_daemon(e->pid, e->uid, e->filename) == 0)
            daemon_ok++;
        else
            daemon_fail++;
    }
    return 0;
}

// Reads per-CPU kernel maps to report total captured and dropped events
static void print_kernel_stats(int stats_fd) {
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return;

    unsigned long long values[ncpus];
    unsigned long long captured = 0, dropped = 0;
    unsigned int k0 = 0, k1 = 1;

    if (bpf_map_lookup_elem(stats_fd, &k0, values) == 0) {
        for (int i = 0; i < ncpus; i++)
            captured += values[i];
    }
    if (bpf_map_lookup_elem(stats_fd, &k1, values) == 0) {
        for (int i = 0; i < ncpus; i++)
            dropped += values[i];
    }

    printf("\n--- eBPF Ring Buffer Telemetry ---\n");
    printf("Kernel events captured  : %llu\n", captured);
    printf("Kernel events dropped   : %llu\n", dropped);
    printf("Userspace events matched: %llu\n", userspace_seen);
    if (socket_path) {
        printf("Daemon logged (OK)      : %llu\n", daemon_ok);
        printf("Daemon errors (FAIL)    : %llu\n", daemon_fail);
    }
}

// Loads the eBPF program, attaches the tracepoint, and polls the ring buffer
int main(int argc, char **argv) {
    unsigned int extra_excludes[64];
    int exclude_count = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--filter") && i + 1 < argc) {
            path_filter = argv[++i];
        } else if (!strcmp(argv[i], "--socket") && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (!strcmp(argv[i], "--exclude-pid") && i + 1 < argc && exclude_count < 63) {
            extra_excludes[exclude_count++] = (unsigned int)atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--quiet")) {
            quiet_mode = 1;
        } else {
            fprintf(stderr, "Usage: %s [--filter PREFIX] [--socket PATH] [--exclude-pid PID] [--quiet]\n", argv[0]);
            return 1;
        }
    }

    struct monitor_bpf *skel = monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    int excl_fd = bpf_map__fd(skel->maps.excluded_pids);
    unsigned int self_pid = (unsigned int)getpid();
    unsigned char one = 1;
    bpf_map_update_elem(excl_fd, &self_pid, &one, BPF_ANY);
    for (int i = 0; i < exclude_count; i++) {
        bpf_map_update_elem(excl_fd, &extra_excludes[i], &one, BPF_ANY);
    }

    if (monitor_bpf__attach(skel) != 0) {
        fprintf(stderr, "Failed to attach BPF tracepoint\n");
        monitor_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        monitor_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("eBPF collector active (filter=%s, socket=%s). Press Ctrl+C to stop...\n",
           path_filter ? path_filter : "ALL",
           socket_path ? socket_path : "NONE");

    while (!exiting) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    print_kernel_stats(bpf_map__fd(skel->maps.stats));
    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    return 0;
}