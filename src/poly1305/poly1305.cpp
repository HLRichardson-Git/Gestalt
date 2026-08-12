/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * poly1305.cpp
 *
 * This file contains the implementation of Gestalts poly1305 security functions.
 */

#include "poly1305.h"

#include <cstring>
#include <stdexcept>

static inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0]
         | (uint32_t)p[1] << 8
         | (uint32_t)p[2] << 16
         | (uint32_t)p[3] << 24;
}

static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void clamp_r(uint8_t r[16]) {
    r[3]  &= 15;
    r[7]  &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4]  &= 252;
    r[8]  &= 252;
    r[12] &= 252;
}

/*
 * Poly1305 MAC per RFC 8439 §2.5 using 5 × 26-bit limbs for portability.
 *
 * The key must be 32 bytes (256 bits):
 *   r = key[0..15]  (clamped; used as the polynomial multiplier)
 *   s = key[16..31] (added to the final accumulator)
 *
 * Returns a 16-byte (128-bit) authentication tag.
 */
SecureBytes poly1305_mac(const SecureBytes& message, const SecureBytes& key) {
    if (key.size() != 32)
        throw std::invalid_argument("poly1305_mac: key must be 32 bytes");

    // split and clamp r, keep s
    uint8_t r_raw[16], s_raw[16];
    std::memcpy(r_raw, key.data(),      16);
    std::memcpy(s_raw, key.data() + 16, 16);
    clamp_r(r_raw);

    // Load r as 5 × 26-bit little-endian limbs
    uint32_t rb0 = load32_le(r_raw);
    uint32_t rb1 = load32_le(r_raw + 4);
    uint32_t rb2 = load32_le(r_raw + 8);
    uint32_t rb3 = load32_le(r_raw + 12);

    const uint64_t r0 = rb0 & 0x3ffffff;
    const uint64_t r1 = ((rb0 >> 26) | (rb1 <<  6)) & 0x3ffffff;
    const uint64_t r2 = ((rb1 >> 20) | (rb2 << 12)) & 0x3ffffff;
    const uint64_t r3 = ((rb2 >> 14) | (rb3 << 18)) & 0x3ffffff;
    const uint64_t r4 = (rb3 >> 8) & 0x3ffffff;

    // Precompute 5*r[1..4] for the 2^130 ≡ 5 (mod p) reduction trick
    const uint64_t r1_5 = r1 * 5;
    const uint64_t r2_5 = r2 * 5;
    const uint64_t r3_5 = r3 * 5;
    const uint64_t r4_5 = r4 * 5;

    uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    const uint8_t* msg = message.data();
    std::size_t remaining = message.size();

    while (remaining > 0) {
        // Load one block (<=16 bytes), zero-padded, with the RFC 8439 hibit appended
        uint8_t block[17] = {};
        std::size_t n = (remaining >= 16) ? 16 : remaining;
        std::memcpy(block, msg, n);
        block[n] = 0x01;  // append a 1-bit after the message bytes (RFC 8439 §2.5.1)
        msg       += n;
        remaining -= n;

        // Load block as 5 × 26-bit limbs and accumulate into h
        uint32_t t0 = load32_le(block);
        uint32_t t1 = load32_le(block + 4);
        uint32_t t2 = load32_le(block + 8);
        uint32_t t3 = load32_le(block + 12);
        uint32_t t4 = (uint32_t)block[16];

        h0 += (uint64_t)( t0                         & 0x3ffffff);
        h1 += (uint64_t)(((t0 >> 26) | (t1 <<  6))  & 0x3ffffff);
        h2 += (uint64_t)(((t1 >> 20) | (t2 << 12))  & 0x3ffffff);
        h3 += (uint64_t)(((t2 >> 14) | (t3 << 18))  & 0x3ffffff);
        h4 += (uint64_t)( (t3 >>  8) | (t4 << 24));

        // Multiply h by r mod p=2^130-5
        // Cross-terms above bit 129 wrap back with ×5 (since 2^130 ≡ 5 mod p)
        uint64_t d0 = h0*r0 + h1*r4_5 + h2*r3_5 + h3*r2_5 + h4*r1_5;
        uint64_t d1 = h0*r1 + h1*r0   + h2*r4_5 + h3*r3_5 + h4*r2_5;
        uint64_t d2 = h0*r2 + h1*r1   + h2*r0   + h3*r4_5 + h4*r3_5;
        uint64_t d3 = h0*r3 + h1*r2   + h2*r1   + h3*r0   + h4*r4_5;
        uint64_t d4 = h0*r4 + h1*r3   + h2*r2   + h3*r1   + h4*r0;

        // Carry-propagate to normalise back to 26-bit limbs
        uint64_t c;
        c = d0 >> 26; h0 = d0 & 0x3ffffff; d1 += c;
        c = d1 >> 26; h1 = d1 & 0x3ffffff; d2 += c;
        c = d2 >> 26; h2 = d2 & 0x3ffffff; d3 += c;
        c = d3 >> 26; h3 = d3 & 0x3ffffff; d4 += c;
        c = d4 >> 26; h4 = d4 & 0x3ffffff; h0 += c * 5;  // 2^130 ≡ 5
        c = h0 >> 26; h0 &= 0x3ffffff;     h1 += c;
    }

    // ensure h is fully reduced mod p
    uint64_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    // Conditional subtract p: compute g = h+5; if it overflows 130 bits, h >= p so use g
    uint64_t g0 = h0 + 5;
    c  = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c;
    c  = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c;
    c  = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c;
    c  = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c;

    // mask = all-zeros when h >= p (select g = h-p), all-ones when h < p (select h)
    uint64_t mask = (g4 >> 26) - 1;
    g0 = (g0 & ~mask) | (h0 & mask);
    g1 = (g1 & ~mask) | (h1 & mask);
    g2 = (g2 & ~mask) | (h2 & mask);
    g3 = (g3 & ~mask) | (h3 & mask);
    g4 = (g4 & ~mask) | (h4 & mask);

    // Pack 5 × 26-bit limbs back into 4 × 32-bit LE words (bits 128-129 of g4 are discarded)
    uint32_t f0 = (uint32_t)( g0         | (g1 << 26));
    uint32_t f1 = (uint32_t)((g1 >>  6)  | (g2 << 20));
    uint32_t f2 = (uint32_t)((g2 >> 12)  | (g3 << 14));
    uint32_t f3 = (uint32_t)((g3 >> 18)  | (g4 <<  8));

    // --- Add s mod 2^128 ---
    uint64_t a0 = (uint64_t)f0 + load32_le(s_raw);
    uint64_t a1 = (uint64_t)f1 + load32_le(s_raw +  4) + (a0 >> 32);
    uint64_t a2 = (uint64_t)f2 + load32_le(s_raw +  8) + (a1 >> 32);
    uint64_t a3 = (uint64_t)f3 + load32_le(s_raw + 12) + (a2 >> 32);

    // Serialise 16-byte tag (little-endian)
    SecureBytes tag(16);
    store32_le(tag.data(),      (uint32_t)a0);
    store32_le(tag.data() +  4, (uint32_t)a1);
    store32_le(tag.data() +  8, (uint32_t)a2);
    store32_le(tag.data() + 12, (uint32_t)a3);

    return tag;
}
