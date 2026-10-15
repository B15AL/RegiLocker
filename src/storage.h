#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>

#define STORAGE_MAX_NAME 64

/* Open the vault directory. Call once, before chroot(). Returns 0 / -1. */
int storage_init(const char *dir);

/* 0 if the name is safe, -1 otherwise. Whitelist: [A-Za-z0-9._-], 1..64 chars, no leading '.'. */
int sanitize_filename(const char *filename);

int storage_save_file(const char *filename, const unsigned char *data, size_t data_len);

/* errno = EFBIG if the file is larger than max_len, ENOENT if missing. */
int storage_retrieve_file(const char *filename, unsigned char *buffer, size_t max_len, size_t *out_len);

int storage_delete_file(const char *filename);

#endif
