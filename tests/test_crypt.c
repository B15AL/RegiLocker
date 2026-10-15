/* Prints vectors so they can be compared against a reference implementation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/crypt.h"

static void hex(const uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", p[i]); }

int main(void) {
    uint8_t key[32], nonce[12], aad[20], pt[300], ct[300], out[300], tag[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i * 3 + 5);
    for (int i = 0; i < 20; i++) aad[i] = (uint8_t)(i + 100);
    for (int i = 0; i < 300; i++) pt[i] = (uint8_t)(i * 13);

    /* Lengths chosen to cover empty, partial-block, exact-block and multi-block cases */
    size_t lens[] = {0, 1, 15, 16, 17, 63, 64, 65, 127, 300};
    for (size_t k = 0; k < sizeof lens / sizeof *lens; k++) {
        size_t n = lens[k];
        aead_encrypt(key, nonce, aad, sizeof aad, pt, n, ct, tag);
        printf("%zu ", n); hex(ct, n); printf(" "); hex(tag, 16); printf("\n");
        if (aead_decrypt(key, nonce, aad, sizeof aad, ct, n, tag, out) != 0 || memcmp(out, pt, n)) {
            fprintf(stderr, "roundtrip FAILED len=%zu\n", n); return 1;
        }
        if (n > 0) {                                  /* tampering must be rejected */
            ct[n / 2] ^= 1;
            if (aead_decrypt(key, nonce, aad, sizeof aad, ct, n, tag, out) == 0) {
                fprintf(stderr, "tamper NOT detected len=%zu\n", n); return 1;
            }
        }
    }
    return 0;
}
