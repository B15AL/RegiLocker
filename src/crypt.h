#ifndef CRYPT_H
#define CRYPT_H

#include <stddef.h>
#include <stdint.h>

#define CRYPT_KEY_LEN   32
#define CRYPT_NONCE_LEN 12
#define CRYPT_TAG_LEN   16

/* Raw ChaCha20 (RFC 8439). Same function encrypts and decrypts. */
void chacha20_crypt(const uint8_t key[CRYPT_KEY_LEN], const uint8_t nonce[CRYPT_NONCE_LEN],
                    uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);

/* One-shot Poly1305 MAC. */
void poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t tag[16]);

/* ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8). ct and pt may be the same buffer. */
void aead_encrypt(const uint8_t key[CRYPT_KEY_LEN], const uint8_t nonce[CRYPT_NONCE_LEN],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *pt, size_t pt_len,
                  uint8_t *ct, uint8_t tag[CRYPT_TAG_LEN]);

/* Returns 0 if the tag is valid (plaintext written), -1 otherwise (nothing written). */
int aead_decrypt(const uint8_t key[CRYPT_KEY_LEN], const uint8_t nonce[CRYPT_NONCE_LEN],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, size_t ct_len,
                 const uint8_t tag[CRYPT_TAG_LEN], uint8_t *pt);

#endif
