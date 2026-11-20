#ifndef __EVENT_H
#define __EVENT_H

// Maximum lengths for captured file paths and process names
#define MAX_FILENAME_LEN 256
#define TASK_COMM_LEN 16

// Shared event structure passed from the kernel ring buffer to user space
struct event {
    unsigned long long timestamp_ns;
    unsigned int pid;
    unsigned int uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif 