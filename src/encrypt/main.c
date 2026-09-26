
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>  // Fixes: uint8_t, uint32_t errors
#include <string.h>  // Fixes: strlen error

// Forward declaration so main.c knows the function exists in crypt.o
void chacha20_crypt(const uint8_t *key, const uint8_t *nonce, uint32_t counter, 
                    const uint8_t *input, uint8_t *output, size_t length);

int main() {
    // Fixed: Cast string literal to char* or use explicit casting for uint8_t arrays
    const uint8_t *key = (const uint8_t *)"0123456789abcdef0123456789abcdef"; 
    const uint8_t *nonce = (const uint8_t *)"abcdefghijkl";
    uint32_t counter = 1;

    const char *plaintext = "Hello, this is a secret message encrypted via ChaCha20!";
    size_t len = strlen(plaintext);

    uint8_t ciphertext[64] = {0};
    uint8_t decrypted[64] = {0};

    // Encrypt
    chacha20_crypt(key, nonce, counter, (const uint8_t*)plaintext, ciphertext, len);
    
    printf("Ciphertext (hex): ");
    for(size_t i = 0; i < len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decrypt
    chacha20_crypt(key, nonce, counter, ciphertext, decrypted, len);
    decrypted[len] = '\0'; 

    printf("Decrypted: %s\n", decrypted);
    return 0;
}
