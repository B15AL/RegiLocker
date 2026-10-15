#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>
#include <stdint.h>
#include "crypt.h"

#define VAULT_MAX_PLAIN (1024 * 1024)   /* 1 MiB per file */

/* Load the 32-byte master key. Rejects a missing/short file or one readable by group/other. */
int vault_load_key(const char *path);

/* Encrypt and store. Returns 0 / -1 (errno set). */
int vault_put(const char *name, const uint8_t *data, size_t len);

/* Retrieve and decrypt into out (capacity VAULT_MAX_PLAIN). errno = EBADMSG if tampered. */
int vault_get(const char *name, uint8_t *out, size_t *out_len);

int vault_delete(const char *name);

#endif
