#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "storage.h"

static int vault_fd = -1;

int storage_init(const char *dir) {
    vault_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return vault_fd < 0 ? -1 : 0;
}

int sanitize_filename(const char *name) {
    if (name == NULL || name[0] == '\0' || name[0] == '.') return -1;
    size_t n = strnlen(name, STORAGE_MAX_NAME + 1);
    if (n > STORAGE_MAX_NAME) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) return -1;
    }
    return 0;
}

static int check(const char *name) {
    if (vault_fd < 0) { errno = EBADF; return -1; }
    if (sanitize_filename(name) != 0) { errno = EINVAL; return -1; }
    return 0;
}

/* Write to a temp file, fsync, then rename: readers never see a half-written file. */
int storage_save_file(const char *name, const unsigned char *data, size_t len) {
    if (check(name) != 0) return -1;

    char tmp[STORAGE_MAX_NAME + 32];
    snprintf(tmp, sizeof tmp, ".tmp.%ld", (long)getpid());   /* leading '.' can never collide with a valid name */

    int fd = openat(vault_fd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 && errno == EEXIST) {                          /* stale temp from a crashed run */
        unlinkat(vault_fd, tmp, 0);
        fd = openat(vault_fd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    }
    if (fd < 0) return -1;

    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            int e = errno; close(fd); unlinkat(vault_fd, tmp, 0); errno = e;
            return -1;
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0 || close(fd) != 0) {
        int e = errno; unlinkat(vault_fd, tmp, 0); errno = e;
        return -1;
    }
    if (renameat(vault_fd, tmp, vault_fd, name) != 0) {
        int e = errno; unlinkat(vault_fd, tmp, 0); errno = e;
        return -1;
    }
    return 0;
}

int storage_retrieve_file(const char *name, unsigned char *buf, size_t max_len, size_t *out_len) {
    if (check(name) != 0) return -1;

    int fd = openat(vault_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int e = S_ISREG(st.st_mode) ? errno : EINVAL; close(fd); errno = e; return -1;
    }
    if ((unsigned long long)st.st_size > max_len) { close(fd); errno = EFBIG; return -1; }

    size_t off = 0;
    while (off < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + off, (size_t)st.st_size - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno; close(fd); errno = e; return -1;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
    close(fd);
    *out_len = off;
    return 0;
}

int storage_delete_file(const char *name) {
    if (check(name) != 0) return -1;
    return unlinkat(vault_fd, name, 0);
}
