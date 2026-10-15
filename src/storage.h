#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>

int sanitize_filename(const char *filename);
int storage_save_file(const char *filename, const unsigned char *data, size_t data_len);
int storage_retrieve_file(const char *filename, unsigned char *buffer, size_t max_len, size_t *out_len);
int storage_delete_file(const char *filename);

#endif
