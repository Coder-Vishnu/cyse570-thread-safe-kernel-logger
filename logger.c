#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

// File paths for the log, checkpoint, secret key, and daemon socket
#define LOG "logs/events.log"
#define CP "checkpoints/checkpoint.dat"
#define KEY "checkpoints/secret.key"
#define SOCK "logs/logger.sock"
#define LOCK "logs/logger.lock"
#define ZERO "0000000000000000000000000000000000000000000000000000000000000000"
static volatile sig_atomic_t running = 1;

// Stops the daemon when it receives a termination signal
static void stop(int s) {
    (void)s;
    running = 0;
}

// Converts hash bytes into a readable hexadecimal string
static void hex(const unsigned char *in, size_t n, char *out) {
    for (size_t i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", in[i]);
    out[2 * n] = '\0';
}

// Calculates the SHA-256 hash of the provided data
static void sha(const char *s, char out[65]) {
    unsigned char h[32];
    SHA256((const unsigned char *)s, strlen(s), h);
    hex(h, 32, out);
}

// Creates or reads the secret key used to authenticate checkpoints
static int keyread(unsigned char k[32], int create) {
    int fd = open(KEY, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT && create) {
        unsigned char tmp[32];
        if (RAND_bytes(tmp, 32) != 1)
            return 0;
        fd = open(KEY, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (fd < 0)
            return 0;
        int ok = write(fd, tmp, 32) == 32 && fsync(fd) == 0;
        close(fd);
        if (!ok)
            return 0;
        fd = open(KEY, O_RDONLY | O_NOFOLLOW);
    }
    if (fd < 0)
        return 0;
    struct stat st;
    int ok = fstat(fd, &st) == 0 &&
             S_ISREG(st.st_mode) &&
             st.st_uid == geteuid() &&
             (st.st_mode & 077) == 0 &&
             st.st_size == 32 &&
             read(fd, k, 32) == 32;
    close(fd);
    return ok;
}

// Generates an HMAC-SHA-256 value using the secret key
static int mac(const char *s, const unsigned char key[32], char out[65]) {
    unsigned char h[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    if (!HMAC(EVP_sha256(), key, 32,
              (const unsigned char *)s,
              strlen(s), h, &n) || n != 32)
        return 0;
    hex(h, 32, out);
    return 1;
}

// Saves the latest sequence number and hash with an HMAC
static int checkpoint(long seq, const char hash[65]) {
    unsigned char key[32];
    char data[256], sig[65];
    if (!keyread(key, 1))
        return 0;
    snprintf(data, sizeof(data), "%ld|%s", seq, hash);
    if (!mac(data, key, sig))
        return 0;
    int fd = open(CP ".tmp",
                  O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return 0;
    char line[400];
    int n = snprintf(line, sizeof(line), "%s|%s\n", data, sig);
    int ok = write(fd, line, n) == n && fsync(fd) == 0;
    close(fd);
    if (!ok || rename(CP ".tmp", CP) != 0)
        return 0;
    return 1;
}

// Reads the checkpoint and checks whether its HMAC is valid
static int readcp(long *seq, char hash[65]) {
    FILE *f = fopen(CP, "r");
    if (!f)
        return 0;
    char line[512], sig[65], extra, data[256], expected[65];
    int ok = fgets(line, sizeof(line), f) != NULL;
    fclose(f);
    if (!ok ||
        sscanf(line, "%ld|%64[0-9a-f]|%64[0-9a-f]%c",
               seq, hash, sig, &extra) != 4 ||
        extra != '\n' ||
        *seq < 1 ||
        strlen(hash) != 64 ||
        strlen(sig) != 64)
        return 0;
    unsigned char key[32];
    if (!keyread(key, 0))
        return 0;
    snprintf(data, sizeof(data), "%ld|%s", *seq, hash);
    return mac(data, key, expected) &&
           CRYPTO_memcmp(sig, expected, 64) == 0;
}

// Checks the log sequence, hash chain, and checkpoint for tampering
static int verify(void) {
    long cpseq, seq = 0, n;
    char cphash[65], prev[65] = ZERO;
    char seen[65] = "";
    char line[2048], body[2048];
    char stored[65], calc[65];
    if (!readcp(&cpseq, cphash)) {
        puts("FAIL: checkpoint missing or invalid");
        return 1;
    }
    FILE *f = fopen(LOG, "r");
    if (!f) {
        puts("FAIL: log missing");
        return 1;
    }
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (!len || line[len - 1] != '\n')
            goto corrupt;
        char *last = strrchr(line, '|');
        if (!last || strlen(last + 1) != 65)
            goto corrupt;
        memcpy(stored, last + 1, 64);
        stored[64] = '\0';
        for (int i = 0; i < 64; i++) {
            if (!strchr("0123456789abcdef", stored[i]))
                goto corrupt;
        }
        *last = '\0';
        snprintf(body, sizeof(body), "%s", line);
        char *previous = strrchr(body, '|');
        if (!previous ||
            strlen(previous + 1) != 64 ||
            strcmp(previous + 1, prev) != 0)
            goto corrupt;
        if (sscanf(body, "%ld|", &n) != 1 ||
            n != seq + 1)
            goto corrupt;
        sha(body, calc);
        if (strcmp(calc, stored) != 0)
            goto corrupt;
        seq = n;
        strcpy(prev, stored);
        if (seq == cpseq)
            strcpy(seen, stored);
    }
    if (ferror(f))
        goto corrupt;
    fclose(f);
    if (seq != cpseq || strcmp(seen, cphash) != 0) {
        printf("FAIL: checkpoint mismatch or log truncation "
               "(checkpoint sequence %ld, log sequence %ld)\n",
               cpseq, seq);
        return 1;
    }
    printf("PASS: log hash chain and checkpoint verified\n");
    printf("Verified entries: %ld\n", seq);
    return 0;

// Reports the first log entry where verification failed
corrupt:
    fclose(f);
    printf("FAIL: first inconsistent entry near sequence %ld\n", seq + 1);
    return 1;
}

// Verifies the log before adding a new event and updating the checkpoint
static int append_event(int pid, int uid, const char *filename) {
    if (strlen(filename) > 700 ||
        strpbrk(filename, "|\n\r")) {
        puts("FAIL: invalid filename");
        return 1;
    }
    long seq = 0;
    char prev[65] = ZERO;
    char body[1024], hash[65];
    struct stat st;
    if (stat(LOG, &st) == 0 && st.st_size > 0) {
        if (verify() != 0)
            return 1;
        if (!readcp(&seq, prev))
            return 1;
    } else if (access(CP, F_OK) == 0) {
        puts("FAIL: checkpoint exists but log missing/empty");
        return 1;
    }
    snprintf(body, sizeof(body),
             "%ld|%ld|%d|%d|%s|%s",
             seq + 1, (long)time(NULL),
             pid, uid, filename, prev);
    sha(body, hash);
    FILE *f = fopen(LOG, "a");
    if (!f)
        return 1;
    int ok = fprintf(f, "%s|%s\n", body, hash) > 0;
    if (fflush(f) != 0 || fsync(fileno(f)) != 0)
        ok = 0;
    if (fclose(f) != 0)
        ok = 0;
    if (!ok || !checkpoint(seq + 1, hash)) {
        puts("FAIL: write/checkpoint error");
        return 1;
    }
    printf("Logged event %ld: %s\n", seq + 1, filename);
    return 0;
}

// Runs the single-writer daemon and processes events one at a time
static int serve(void) {
    int lockfd = open(LOCK, O_RDWR | O_CREAT, 0600);
    if (lockfd < 0 ||
        flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        puts("FAIL: another logger daemon is running");
        return 1;
    }
    if (access(LOG, F_OK) == 0 ||
        access(CP, F_OK) == 0) {
        struct stat st;
        if (stat(LOG, &st) != 0 ||
            st.st_size > 0 ||
            access(CP, F_OK) == 0) {
            if (verify() != 0)
                return 1;
        }
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCK);
    unlink(SOCK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 16) != 0) {
        perror("socket");
        close(fd);
        return 1;
    }
    chmod(SOCK, 0600);
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    puts("Daemon running. In another terminal use:");
    puts("./logger send PID UID FILENAME");
    fflush(stdout);
    while (running) {
        int c = accept(fd, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        char buf[1024];
        ssize_t n = read(c, buf, sizeof(buf) - 1);
        int result = 1;
        if (n > 0) {
            buf[n] = '\0';
            int pid, uid;
            char path[768], extra;
            if (sscanf(buf, "%d %d %767s %c",
                       &pid, &uid, path, &extra) == 3)
                result = append_event(pid, uid, path);
        }
        const char *response = result == 0 ? "OK\n" : "FAIL\n";
        write(c, response, strlen(response));
        close(c);
    }
    close(fd);
    unlink(SOCK);
    close(lockfd);
    return 0;
}

// Sends a simulated event to the daemon through a Unix socket
static int send_event(int pid, int uid, const char *path) {
    if (strlen(path) > 700 ||
        strpbrk(path, " \t\r\n|")) {
        puts("FAIL: path must not contain whitespace or pipes");
        return 1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCK);
    if (connect(fd, (struct sockaddr *)&addr,
                sizeof(addr)) != 0) {
        puts("FAIL: daemon not running");
        close(fd);
        return 1;
    }
    char msg[1024];
    int n = snprintf(msg, sizeof(msg),
                     "%d %d %s\n", pid, uid, path);
    if (write(fd, msg, n) != n) {
        close(fd);
        return 1;
    }
    char response[32] = {0};
    n = read(fd, response, sizeof(response) - 1);
    close(fd);
    if (n <= 0)
        return 1;
    printf("Daemon response: %s", response);
    return strncmp(response, "OK", 2) != 0;
}

// Creates the required directories and runs the selected command
int main(int argc, char **argv) {
    umask(077);
    mkdir("logs", 0700);
    mkdir("checkpoints", 0700);
    if (argc == 2 && !strcmp(argv[1], "daemon"))
        return serve();
    if (argc == 2 && !strcmp(argv[1], "verify"))
        return verify();
    if (argc == 5 && !strcmp(argv[1], "send"))
        return send_event(atoi(argv[2]),
                          atoi(argv[3]),
                          argv[4]);
    puts("Usage:");
    puts("./logger daemon");
    puts("./logger verify");
    puts("./logger send PID UID FILENAME");
    return 1;
}
