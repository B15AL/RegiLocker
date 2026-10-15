#include <string.h>
#include "crypt.h"

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static uint32_t load32_le(const uint8_t *s) {
    return (uint32_t)s[0] | ((uint32_t)s[1] << 8) |
           ((uint32_t)s[2] << 16) | ((uint32_t)s[3] << 24);
}

static void store32_le(uint8_t *d, uint32_t v) {
    d[0] = (uint8_t)v;         d[1] = (uint8_t)(v >> 8);
    d[2] = (uint8_t)(v >> 16); d[3] = (uint8_t)(v >> 24);
}

static void store64_le(uint8_t *d, uint64_t v) {
    store32_le(d, (uint32_t)v);
    store32_le(d + 4, (uint32_t)(v >> 32));
}

/* ------------------------------ ChaCha20 ------------------------------ */

#define QR(a, b, c, d)                      \
    a += b; d ^= a; d = ROTL32(d, 16);      \
    c += d; b ^= c; b = ROTL32(b, 12);      \
    a += b; d ^= a; d = ROTL32(d, 8);       \
    c += d; b ^= c; b = ROTL32(b, 7)

static void chacha20_block(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, in, sizeof x);
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; i++)
        store32_le(out + 4 * i, x[i] + in[i]);
}

void chacha20_crypt(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                    const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t st[16];
    uint8_t ks[64];

    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) st[4 + i] = load32_le(key + 4 * i);
    st[12] = counter;
    st[13] = load32_le(nonce);
    st[14] = load32_le(nonce + 4);
    st[15] = load32_le(nonce + 8);

    while (len > 0) {
        chacha20_block(st, ks);
        st[12]++;                 /* RFC 8439: 32-bit counter; callers never exceed 2^32 blocks */
        size_t n = len < 64 ? len : 64;
        for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
        in += n; out += n; len -= n;
    }
    explicit_bzero(st, sizeof st);
    explicit_bzero(ks, sizeof ks);
}

/* ------------------------------ Poly1305 ------------------------------ */
/* 26-bit limb implementation (after poly1305-donna-32). */

typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t  buf[16];
    size_t   used;
} poly_ctx;

static void poly_init(poly_ctx *c, const uint8_t key[32]) {
    c->r[0] =  load32_le(key +  0)       & 0x3ffffff;
    c->r[1] = (load32_le(key +  3) >> 2) & 0x3ffff03;
    c->r[2] = (load32_le(key +  6) >> 4) & 0x3ffc0ff;
    c->r[3] = (load32_le(key +  9) >> 6) & 0x3f03fff;
    c->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;
    memset(c->h, 0, sizeof c->h);
    for (int i = 0; i < 4; i++) c->pad[i] = load32_le(key + 16 + 4 * i);
    c->used = 0;
}

static void poly_block(poly_ctx *c, const uint8_t m[16], uint32_t hibit) {
    uint32_t r0 = c->r[0], r1 = c->r[1], r2 = c->r[2], r3 = c->r[3], r4 = c->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = c->h[0], h1 = c->h[1], h2 = c->h[2], h3 = c->h[3], h4 = c->h[4];
    uint64_t d0, d1, d2, d3, d4;
    uint32_t cy;

    h0 +=  load32_le(m +  0)       & 0x3ffffff;
    h1 += (load32_le(m +  3) >> 2) & 0x3ffffff;
    h2 += (load32_le(m +  6) >> 4) & 0x3ffffff;
    h3 += (load32_le(m +  9) >> 6) & 0x3ffffff;
    h4 += (load32_le(m + 12) >> 8) | hibit;

    d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
    d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
    d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
    d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
    d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

    cy = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
    d1 += cy; cy = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
    d2 += cy; cy = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
    d3 += cy; cy = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
    d4 += cy; cy = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
    h0 += cy * 5; cy = h0 >> 26; h0 &= 0x3ffffff;
    h1 += cy;

    c->h[0] = h0; c->h[1] = h1; c->h[2] = h2; c->h[3] = h3; c->h[4] = h4;
}

static void poly_update(poly_ctx *c, const uint8_t *m, size_t len) {
    while (len > 0) {
        size_t n = 16 - c->used;
        if (n > len) n = len;
        memcpy(c->buf + c->used, m, n);
        c->used += n; m += n; len -= n;
        if (c->used == 16) {
            poly_block(c, c->buf, 1u << 24);
            c->used = 0;
        }
    }
}

/* Pads the running message with zeros up to a 16-byte boundary (AEAD construction). */
static void poly_pad16(poly_ctx *c) {
    static const uint8_t zeros[16] = {0};
    if (c->used) poly_update(c, zeros, 16 - c->used);
}

static void poly_final(poly_ctx *c, uint8_t tag[16]) {
    uint32_t h0, h1, h2, h3, h4, g0, g1, g2, g3, g4, cy, mask;
    uint64_t f;

    if (c->used) {
        c->buf[c->used++] = 1;
        while (c->used < 16) c->buf[c->used++] = 0;
        poly_block(c, c->buf, 0);
    }

    h0 = c->h[0]; h1 = c->h[1]; h2 = c->h[2]; h3 = c->h[3]; h4 = c->h[4];

    cy = h1 >> 26; h1 &= 0x3ffffff; h2 += cy;
    cy = h2 >> 26; h2 &= 0x3ffffff; h3 += cy;
    cy = h3 >> 26; h3 &= 0x3ffffff; h4 += cy;
    cy = h4 >> 26; h4 &= 0x3ffffff; h0 += cy * 5;
    cy = h0 >> 26; h0 &= 0x3ffffff; h1 += cy;

    g0 = h0 + 5; cy = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + cy; cy = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + cy; cy = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + cy; cy = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + cy - (1u << 26);

    mask = (g4 >> 31) - 1;               /* all ones if h >= p */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    h0 = (h0       | (h1 << 26));
    h1 = ((h1 >> 6)  | (h2 << 20));
    h2 = ((h2 >> 12) | (h3 << 14));
    h3 = ((h3 >> 18) | (h4 << 8));

    f = (uint64_t)h0 + c->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + c->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + c->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + c->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32_le(tag, h0); store32_le(tag + 4, h1);
    store32_le(tag + 8, h2); store32_le(tag + 12, h3);
    explicit_bzero(c, sizeof *c);
}

void poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t tag[16]) {
    poly_ctx c;
    poly_init(&c, key);
    poly_update(&c, msg, len);
    poly_final(&c, tag);
}

/* ------------------------- ChaCha20-Poly1305 AEAD ------------------------- */

static void aead_tag(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len, uint8_t tag[16]) {
    uint8_t otk[64] = {0}, lens[16];
    poly_ctx c;

    /* One-time Poly1305 key = first 32 bytes of keystream block 0 */
    chacha20_crypt(key, nonce, 0, otk, otk, 64);
    poly_init(&c, otk);
    explicit_bzero(otk, sizeof otk);

    poly_update(&c, aad, aad_len); poly_pad16(&c);
    poly_update(&c, ct, ct_len);   poly_pad16(&c);
    store64_le(lens, aad_len);
    store64_le(lens + 8, ct_len);
    poly_update(&c, lens, 16);
    poly_final(&c, tag);
}

void aead_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *pt, size_t pt_len,
                  uint8_t *ct, uint8_t tag[16]) {
    chacha20_crypt(key, nonce, 1, pt, ct, pt_len);   /* counter 1: block 0 is for the MAC key */
    aead_tag(key, nonce, aad, aad_len, ct, pt_len, tag);
}

int aead_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, size_t ct_len,
                 const uint8_t tag[16], uint8_t *pt) {
    uint8_t calc[16];
    uint8_t diff = 0;

    aead_tag(key, nonce, aad, aad_len, ct, ct_len, calc);
    for (int i = 0; i < 16; i++) diff |= calc[i] ^ tag[i];   /* constant-time compare */
    if (diff != 0) return -1;

    chacha20_crypt(key, nonce, 1, ct, pt, ct_len);
    return 0;
}
