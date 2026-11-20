#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

// Arguments passed to each concurrent worker thread
struct worker_args {
    int tid;
    int ops;
    const char *dir;
    pthread_barrier_t *barrier;
    long success;
    long failed;
};

// Opens and closes files repeatedly after waiting at the start barrier
static void *worker(void *arg) {
    struct worker_args *w = (struct worker_args *)arg;
    char path[512];

    pthread_barrier_wait(w->barrier);

    for (int i = 0; i < w->ops; i++) {
        snprintf(path, sizeof(path), "%s/t%d_op%d.txt", w->dir, w->tid, i);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            close(fd);
            w->success++;
        } else {
            w->failed++;
        }
    }
    return NULL;
}

// Creates multiple threads to test concurrent file access
int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <target_dir> <num_threads> <ops_per_thread>\n", argv[0]);
        return 1;
    }

    const char *dir = argv[1];
    int num_threads = atoi(argv[2]);
    int ops_per_thread = atoi(argv[3]);

    if (num_threads <= 0 || ops_per_thread <= 0) {
        fprintf(stderr, "Threads and ops_per_thread must be > 0\n");
        return 1;
    }

    mkdir(dir, 0755);

    pthread_t *threads = calloc((size_t)num_threads, sizeof(pthread_t));
    struct worker_args *args = calloc((size_t)num_threads, sizeof(struct worker_args));
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, (unsigned int)num_threads + 1);

    for (int i = 0; i < num_threads; i++) {
        args[i].tid = i;
        args[i].ops = ops_per_thread;
        args[i].dir = dir;
        args[i].barrier = &barrier;
        pthread_create(&threads[i], NULL, worker, &args[i]);
    }

    struct timespec t0, t1;
    pthread_barrier_wait(&barrier);
    clock_gettime(CLOCK_MONOTONIC, &t0);

    long total_ok = 0, total_fail = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        total_ok += args[i].success;
        total_fail += args[i].failed;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    double ops_sec = elapsed > 0 ? total_ok / elapsed : 0.0;

    printf("--- Concurrency Stress Test Results ---\n");
    printf("Threads            : %d\n", num_threads);
    printf("Total openat ops   : %ld (failed: %ld)\n", total_ok, total_fail);
    printf("Elapsed time       : %.4f s\n", elapsed);
    printf("Throughput         : %.2f ops/sec\n", ops_sec);

    pthread_barrier_destroy(&barrier);
    free(threads);
    free(args);
    return 0;
}