#ifndef __EVENT_H
#define __EVENT_H

#define MAX_FILENAME_LEN 256
#define TASK_COMM_LEN 16

struct event {
    unsigned long long timestamp_ns;
    unsigned int pid;
    unsigned int uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif 