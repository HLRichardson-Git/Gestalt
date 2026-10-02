/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * chachaCore.h
 *
 */

#pragma once

#include <cstdint>
#include <array>

#include <gestalt/secure_bytes.h>

constexpr uint32_t CONST_1 = 0x61707865;
constexpr uint32_t CONST_2 = 0x3320646e;
constexpr uint32_t CONST_3 = 0x79622d32;
constexpr uint32_t CONST_4 = 0x6b206574;

class ChaCha {
private:
    uint32_t state[16] = {CONST_1, CONST_2, CONST_3, CONST_4};

    void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    void inner_block();

    void setState(const SecureBytes& key, const SecureBytes& counter, const SecureBytes& nonce);

	friend class ChaCha_Functions;
public:
	explicit ChaCha(const SecureBytes& key, const SecureBytes& nonce, uint32_t counter = 0);
	~ChaCha();

    std::array<uint32_t, 16> chacha20_block();
};
