#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "storage.h"

#define VAULT_DIR "./vault_storage/"
#define MAX_PATH_LEN 512

/**
 * Sanitizes the filename to prevent directory traversal and injection.
 * Returns 0 on success (safe), or -1 if malicious patterns are detected.
 */
int sanitize_filename(const char *filename) {
    if (filename == NULL || strlen(filename) == 0) {
        return -1;
    }

    // Check for null-byte injection or forbidden path traversal elements
    if (strchr(filename, '/') != NULL || 
        strchr(filename, '\\') != NULL || 
        strstr(filename, "..") != NULL) {
        return -1;
    }

    return 0;
}

/**
 * Saves data securely to a file within the vault.
 */
int storage_save_file(const char *filename, const unsigned char *data, size_t data_len) {
    if (sanitize_filename(filename) != 0) {
        errno = EINVAL;
        return -1;
    }

    char filepath[MAX_PATH_LEN];
    int written = snprintf(filepath, sizeof(filepath), "%s%s", VAULT_DIR, filename);
    if (written < 0 || (size_t)written >= sizeof(filepath)) {
        return -1;
    }

    FILE *file = fopen(filepath, "wb");
    if (file == NULL) {
        return -1;
    }

    size_t blocks_written = fwrite(data, 1, data_len, file);
    fclose(file);

    if (blocks_written != data_len) {
        return -1;
    }

    return 0;
}

/**
 * Retrieves data from a file within the vault.
 */
int storage_retrieve_file(const char *filename, unsigned char *buffer, size_t max_len, size_t *out_len) {
    if (sanitize_filename(filename) != 0) {
        errno = EINVAL;
        return -1;
    }

    char filepath[MAX_PATH_LEN];
    int written = snprintf(filepath, sizeof(filepath), "%s%s", VAULT_DIR, filename);
    if (written < 0 || (size_t)written >= sizeof(filepath)) {
        return -1;
    }

    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        return -1;
    }

    size_t bytes_read = fread(buffer, 1, max_len, file);
    fclose(file);

    *out_len = bytes_read;
    return 0;
}

/**
 * Deletes a file from the vault.
 */
int storage_delete_file(const char *filename) {
    if (sanitize_filename(filename) != 0) {
        errno = EINVAL;
        return -1;
    }

    char filepath[MAX_PATH_LEN];
    int written = snprintf(filepath, sizeof(filepath), "%s%s", VAULT_DIR, filename);
    if (written < 0 || (size_t)written >= sizeof(filepath)) {
        return -1;
    }

    return remove(filepath);
}
