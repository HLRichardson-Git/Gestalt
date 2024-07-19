/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * des.h
 *
 * This file contains the definitions of Gestalts DES security functions.
 */

#pragma once

#include <string>
#include <array>

#include "../../tools/utils.h"

const size_t DES_KEY_SIZE = 48;
const size_t DES_BLOCK_SIZE = 64;
const size_t DES_NUM_OF_ROUNDS = 16;

class DES {
private:
    std::array<uint64_t, 16> roundKeys;

    uint64_t permute(uint64_t input, const int* table, int inputSize, int outputSize);
    uint32_t permute(uint32_t input, const int* table, int inputSize, int outputSize);
    uint32_t leftRotate(uint32_t key, int shifts);
    void generateRoundKeys(const std::string& binaryKey);

    uint32_t sboxSubstitution(uint64_t input);
    uint32_t f(uint32_t rightChunk, size_t round);
    uint64_t encryptRound(uint64_t block, size_t round);

    friend class testDES;

public:
    explicit DES(const std::string& hexKey) {
        generateRoundKeys(hexToBinary(hexKey));
    }

    uint64_t encryptBlock(uint64_t block);
};