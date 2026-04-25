/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * desCore.h
 *
 * This file contains the definitions of Gestalts DES security functions.
 */

#pragma once

#include <array>
#include <vector>
#include <cstdint>

#include <gestalt/secure_bytes.h>

const size_t DES_KEY_SIZE = 48;
const size_t DES_BLOCK_SIZE = 64;
const size_t DES_NUM_OF_ROUNDS = 16;

class DES {
private:
    std::array<uint64_t, 16> roundKeys;

    uint64_t permute(uint64_t input, const int* table, int inputSize, int outputSize);
    uint32_t permute(uint32_t input, const int* table, int inputSize, int outputSize);
    uint32_t leftRotate(uint32_t key, int shifts);
    void generateRoundKeys(uint64_t key);

    uint32_t sboxSubstitution(uint64_t input);
    uint32_t f(uint32_t rightChunk, size_t round);

    friend class DES_Functions;

public:
    explicit DES(const SecureBytes& key) {
        uint64_t keyUint = 0;
        for (size_t i = 0; i < 8; ++i)
            keyUint = (keyUint << 8) | key[i];
        generateRoundKeys(keyUint);
    }

    uint64_t encryptBlock(uint64_t block);
    uint64_t decryptBlock(uint64_t block);
};

SecureBytes applyPKCS5Padding(const SecureBytes& data);
SecureBytes removePKCS5Padding(const SecureBytes& data);
uint64_t bytesToUint64(const SecureBytes& bytes);
std::vector<uint64_t> bytesToBlocks(const SecureBytes& bytes);
SecureBytes blocksToBytes(const std::vector<uint64_t>& blocks);

void validateKey(const SecureBytes& key);
void validateKeys(const SecureBytes& key1, const SecureBytes& key2, const SecureBytes& key3);