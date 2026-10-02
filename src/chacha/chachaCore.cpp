/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * chachaCore.cpp
 *
 */

#include <bit>
#include <cstring>

#include "chachaCore.h"

ChaCha::ChaCha(const SecureBytes& key, const SecureBytes& nonce, uint32_t counter) {
    SecureBytes counterBytes;
    counterBytes.appendLE(counter);
    setState(key, counterBytes, nonce);
}

ChaCha::~ChaCha() {}

void ChaCha::quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d^= a;  d = std::rotl(d, 16);
    c += d; b ^= c; b = std::rotl(b, 12);
    a += b; d ^= a; d = std::rotl(d, 8);
    c += d; b ^= c; b = std::rotl(b, 7);
}

void ChaCha::inner_block() {
    quarter_round(state[0], state[4], state[8],  state[12]);
    quarter_round(state[1], state[5], state[9],  state[13]);
    quarter_round(state[2], state[6], state[10], state[14]);
    quarter_round(state[3], state[7], state[11], state[15]);
    quarter_round(state[0], state[5], state[10], state[15]);
    quarter_round(state[1], state[6], state[11], state[12]);
    quarter_round(state[2], state[7], state[8],  state[13]);
    quarter_round(state[3], state[4], state[9],  state[14]);
}

std::array<uint32_t, 16> ChaCha::chacha20_block() {
    uint32_t initial[16];
    std::memcpy(initial, state, sizeof(state));

    for (int i = 0; i < 10; ++i)
        inner_block();

    std::array<uint32_t, 16> output;
    for (int i = 0; i < 16; ++i)
        output[i] = state[i] + initial[i];

    std::memcpy(state, initial, sizeof(state));
    state[12]++;
    return output;
}

void ChaCha::setState(SecureBytes key, SecureBytes counter, SecureBytes nonce) {
    for (int i = 0; i < 8; ++i)
        state[4 + i] = key.readLE<uint32_t>(i * 4);

    state[12] = counter.readLE<uint32_t>(0);

    for (int i = 0; i < 3; ++i)
        state[13 + i] = nonce.readLE<uint32_t>(i * 4);
}
