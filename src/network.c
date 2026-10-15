#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "network.h"
#include "storage.h"
#include "vault.h"

/* Protocol (one request per connection):
 *   PUT <name> <len>\n<len bytes>   ->  OK\n
 *   GET <name>\n                    ->  OK <len>\n<len bytes>
 *   DEL <name>\n                    ->  OK\n
 * Errors:  ERR <reason>\n
 */
#define MAX_LINE 160

int network_listen(const char *addr, int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, addr, &a.sin_addr) != 1) { close(fd); errno = EINVAL; return -1; }

    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0 || listen(fd, 16) < 0) {
        int e = errno; close(fd); errno = e; return -1;
    }
    return fd;
}

static int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t w = send(fd, p, len, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; len -= (size_t)w;
    }
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t r = recv(fd, buf, len, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }   /* includes receive timeout */
        if (r == 0) return -1;
        buf += r; len -= (size_t)r;
    }
    return 0;
}

/* Reads up to '\n'. Returns 0 on success, -1 on error/oversize. */
static int read_line(int fd, char *line, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        if (recv_all(fd, (uint8_t *)&c, 1) != 0) return -1;
        if (c == '\n') { line[n] = '\0'; return 0; }
        if (c == '\r') continue;
        line[n++] = c;
    }
    return -1;
}

static void reply_err(int fd, const char *why) {
    char m[64];
    int n = snprintf(m, sizeof m, "ERR %s\n", why);
    send_all(fd, m, (size_t)n);
}

static void reply_errno(int fd) {
    switch (errno) {
    case EINVAL:   reply_err(fd, "invalid"); break;
    case ENOENT:   reply_err(fd, "not found"); break;
    case EBADMSG:  reply_err(fd, "integrity check failed"); break;
    default:       reply_err(fd, "internal"); break;
    }
}

static void handle_request(int fd) {
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };      /* slow-client / slowloris protection */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    char line[MAX_LINE];
    if (read_line(fd, line, sizeof line) != 0) { reply_err(fd, "bad request"); return; }

    char cmd[8], name[STORAGE_MAX_NAME + 2], extra[2];
    unsigned long long len = 0;

    if (sscanf(line, "PUT %65s %llu %1s", name, &len, extra) == 2) {
        if (sanitize_filename(name) != 0 || len > VAULT_MAX_PLAIN) { reply_err(fd, "invalid"); return; }
        uint8_t *data = malloc(len ? len : 1);
        if (!data) { reply_err(fd, "internal"); return; }
        if (recv_all(fd, data, (size_t)len) != 0) { free(data); reply_err(fd, "short body"); return; }
        if (vault_put(name, data, (size_t)len) == 0) send_all(fd, "OK\n", 3);
        else reply_errno(fd);
        explicit_bzero(data, len);
        free(data);
    } else if (sscanf(line, "%7s %65s %1s", cmd, name, extra) == 2 && strcmp(cmd, "GET") == 0) {
        if (sanitize_filename(name) != 0) { reply_err(fd, "invalid"); return; }
        uint8_t *out = malloc(VAULT_MAX_PLAIN);
        if (!out) { reply_err(fd, "internal"); return; }
        size_t n;
        if (vault_get(name, out, &n) == 0) {
            char hdr[32];
            int h = snprintf(hdr, sizeof hdr, "OK %zu\n", n);
            if (send_all(fd, hdr, (size_t)h) == 0) send_all(fd, out, n);
        } else {
            reply_errno(fd);
        }
        explicit_bzero(out, VAULT_MAX_PLAIN);
        free(out);
    } else if (sscanf(line, "%7s %65s %1s", cmd, name, extra) == 2 && strcmp(cmd, "DEL") == 0) {
        if (sanitize_filename(name) != 0) { reply_err(fd, "invalid"); return; }
        if (vault_delete(name) == 0) send_all(fd, "OK\n", 3);
        else reply_errno(fd);
    } else {
        reply_err(fd, "bad request");
    }
}

/* After an early rejection the client may still be sending its body. Closing with
 * unread data makes the kernel send RST, which can destroy our error reply, so
 * half-close and briefly drain before the caller closes. */
void network_handle_client(int fd) {
    handle_request(fd);
    shutdown(fd, SHUT_WR);

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    uint8_t sink[4096];
    size_t drained = 0;
    while (drained < 64 * 1024) {
        ssize_t r = recv(fd, sink, sizeof sink, 0);
        if (r <= 0) break;
        drained += (size_t)r;
    }
}
