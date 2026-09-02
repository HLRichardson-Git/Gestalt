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
#include "../chacha/chachaCore.h"
#include "../../tools/bigInt/bigInt.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

// Poly1305 is little-endian; BigInt/GMP uses big-endian byte order.
// These helpers convert between the two representations.
static BigInt loadLE(const uint8_t* data, size_t len) {
    std::vector<uint8_t> be(data, data + len);
    std::reverse(be.begin(), be.end());
    return BigInt(be);
}

static void storeLE(uint8_t* out, size_t len, const BigInt& val) {
    auto be = val.toBytes();  // big-endian, no leading zeros
    std::vector<uint8_t> padded(len, 0);
    size_t offset = len - std::min(be.size(), len);
    std::copy(be.begin(), be.end(), padded.begin() + offset);
    std::reverse(padded.begin(), padded.end());  // little-endian
    std::memcpy(out, padded.data(), len);
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
 * Poly1305 MAC per RFC 8439 §2.5.
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

    uint8_t r_raw[16], s_raw[16];
    std::memcpy(r_raw, key.data(),      16);
    std::memcpy(s_raw, key.data() + 16, 16);
    clamp_r(r_raw);

    const BigInt r = loadLE(r_raw, 16);
    const BigInt s = loadLE(s_raw, 16);
    const BigInt p("0x3fffffffffffffffffffffffffffffffb");  // 2^130 - 5

    BigInt h(0);
    const uint8_t* msg = message.data();
    size_t remaining = message.size();

    while (remaining > 0) {
        size_t n = std::min(remaining, size_t(16));
        uint8_t block[17] = {};
        std::memcpy(block, msg, n);
        block[n] = 0x01;  // append a 1-bit after the message bytes (RFC 8439 §2.5.1)
        msg       += n;
        remaining -= n;

        h = (h + loadLE(block, n + 1)) * r % p;
    }

    // tag = (h + s) mod 2^128, serialised as 16-byte little-endian
    const BigInt two128("0x100000000000000000000000000000000");
    BigInt tag_int = (h + s) % two128;

    SecureBytes tag(16);
    storeLE(tag.data(), 16, tag_int);
    return tag;
}

/*
 * Poly1305 one-time key generation per RFC 8439 §2.6.
 *
 * Uses ChaCha20 with counter=0 to produce a 64-byte block; the first 32 bytes
 * become the one-time key used by poly1305_mac.
 */
SecureBytes poly1305_key_gen(const SecureBytes& key, const SecureBytes& nonce) {
    ChaCha chacha(key, nonce, 0);
    auto block = chacha.chacha20_block();

    SecureBytes out(32);
    for (size_t i = 0; i < 8; ++i) {
        uint32_t w = block[i];
        out[i*4 + 0] = static_cast<uint8_t>(w);
        out[i*4 + 1] = static_cast<uint8_t>(w >>  8);
        out[i*4 + 2] = static_cast<uint8_t>(w >> 16);
        out[i*4 + 3] = static_cast<uint8_t>(w >> 24);
    }
    return out;
}
