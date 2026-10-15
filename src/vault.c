#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include "storage.h"
#include "vault.h"

/* On-disk layout:  "VLT1" | nonce(12) | ciphertext | tag(16)
 * The magic and the file name are authenticated as AAD, so a stored blob
 * cannot be swapped under a different name without detection. */
#define MAGIC      "VLT1"
#define MAGIC_LEN  4
#define HDR_LEN    (MAGIC_LEN + CRYPT_NONCE_LEN)
#define OVERHEAD   (HDR_LEN + CRYPT_TAG_LEN)

static uint8_t master_key[CRYPT_KEY_LEN];
static int key_loaded;

int vault_load_key(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    if (st.st_mode & 077) { close(fd); errno = EACCES; return -1; }   /* must be 0600 / 0400 */
    if (st.st_size != CRYPT_KEY_LEN) { close(fd); errno = EINVAL; return -1; }
    ssize_t r = read(fd, master_key, CRYPT_KEY_LEN);
    close(fd);
    if (r != CRYPT_KEY_LEN) { errno = EIO; return -1; }
    key_loaded = 1;
    return 0;
}

static void build_aad(const char *name, uint8_t *aad, size_t *aad_len) {
    size_t n = strlen(name);
    memcpy(aad, MAGIC, MAGIC_LEN);
    memcpy(aad + MAGIC_LEN, name, n);
    *aad_len = MAGIC_LEN + n;
}

int vault_put(const char *name, const uint8_t *data, size_t len) {
    if (!key_loaded) { errno = EINVAL; return -1; }
    if (sanitize_filename(name) != 0 || len > VAULT_MAX_PLAIN) { errno = EINVAL; return -1; }

    uint8_t *blob = malloc(OVERHEAD + len);
    if (!blob) return -1;

    memcpy(blob, MAGIC, MAGIC_LEN);
    uint8_t *nonce = blob + MAGIC_LEN;
    /* Fresh random 96-bit nonce per write: never reuse a (key, nonce) pair. */
    if (getrandom(nonce, CRYPT_NONCE_LEN, 0) != CRYPT_NONCE_LEN) { free(blob); errno = EIO; return -1; }

    uint8_t aad[MAGIC_LEN + STORAGE_MAX_NAME];
    size_t aad_len;
    build_aad(name, aad, &aad_len);

    aead_encrypt(master_key, nonce, aad, aad_len, data, len, blob + HDR_LEN, blob + HDR_LEN + len);

    int rc = storage_save_file(name, blob, OVERHEAD + len);
    int e = errno;
    free(blob);
    errno = e;
    return rc;
}

int vault_get(const char *name, uint8_t *out, size_t *out_len) {
    if (!key_loaded) { errno = EINVAL; return -1; }
    if (sanitize_filename(name) != 0) { errno = EINVAL; return -1; }

    size_t cap = OVERHEAD + VAULT_MAX_PLAIN;
    uint8_t *blob = malloc(cap);
    if (!blob) return -1;

    size_t n;
    if (storage_retrieve_file(name, blob, cap, &n) != 0) { int e = errno; free(blob); errno = e; return -1; }
    if (n < OVERHEAD || memcmp(blob, MAGIC, MAGIC_LEN) != 0) { free(blob); errno = EBADMSG; return -1; }

    size_t ct_len = n - OVERHEAD;
    uint8_t aad[MAGIC_LEN + STORAGE_MAX_NAME];
    size_t aad_len;
    build_aad(name, aad, &aad_len);

    int rc = aead_decrypt(master_key, blob + MAGIC_LEN, aad, aad_len,
                          blob + HDR_LEN, ct_len, blob + HDR_LEN + ct_len, out);
    free(blob);
    if (rc != 0) { errno = EBADMSG; return -1; }
    *out_len = ct_len;
    return 0;
}

int vault_delete(const char *name) {
    return storage_delete_file(name);
}
