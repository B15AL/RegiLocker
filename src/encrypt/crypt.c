
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Left rotation macro
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

// Pack 4 bytes into a 32-bit little-endian integer
static uint32_t load32_le(const uint8_t *src) {
    return (uint32_t)src[0]        | ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

// Unpack a 32-bit little-endian integer into 4 bytes
static void store32_le(uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v);
    dst[1] = (uint8_t)(v >> 8);
    dst[2] = (uint8_t)(v >> 16);
    dst[3] = (uint8_t)(v >> 24);
}

// The core ChaCha20 Quarter-Round operation
static void chacha20_quarter_round(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL32(x[d], 16);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL32(x[b], 12);
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL32(x[d], 8);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL32(x[b], 7);
}

// Generates a single 64-byte keystream block from the current matrix state
static void chacha20_block(uint32_t state[16], uint8_t keystream[64]) {
    uint32_t x[16];
    memcpy(x, state, sizeof(x));

    // 10 iterations of 2 rounds each (1 column round, 1 diagonal round) = 20 rounds
    for (int i = 0; i < 10; i++) {
        // Column rounds
        chacha20_quarter_round(x, 0, 4, 8, 12);
        chacha20_quarter_round(x, 1, 5, 9, 13);
        chacha20_quarter_round(x, 2, 6, 10, 14);
        chacha20_quarter_round(x, 3, 7, 11, 15);
        // Diagonal rounds
        chacha20_quarter_round(x, 0, 5, 10, 15);
        chacha20_quarter_round(x, 1, 6, 11, 12);
        chacha20_quarter_round(x, 2, 7, 8, 13);
        chacha20_quarter_round(x, 3, 4, 9, 14);
    }

    // Add the original state to the scrambled state
    for (int i = 0; i < 16; i++) {
        x[i] += state[i];
        store32_le(&keystream[i * 4], x[i]);
    }
}

/**
 * Main ChaCha20 function. Because it is a stream cipher, 
 * encryption and decryption use the exact same logic.
 */
void chacha20_crypt(const uint8_t *key, const uint8_t *nonce, uint32_t counter, 
                    const uint8_t *input, uint8_t *output, size_t length) {
    uint32_t state[16];
    uint8_t keystream[64];

    // 1. Initialize the 4x4 matrix state
    // Constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // 256-bit Key (8 words)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = load32_le(&key[i * 4]);
    }

    // Block Counter (1 word)
    state[12] = counter;

    // 96-bit Nonce (3 words)
    state[13] = load32_le(&nonce[0]);
    state[14] = load32_le(&nonce[4]);
    state[15] = load32_le(&nonce[8]);

    // 2. Process data block by block
    while (length > 0) {
        chacha20_block(state, keystream);
        state[12]++; // Increment the block counter

        size_t chunk = (length > 64) ? 64 : length;
        for (size_t i = 0; i < chunk; i++) {
            output[i] = input[i] ^ keystream[i];
        }

        input += chunk;
        output += chunk;
        length -= chunk;
    }
}
