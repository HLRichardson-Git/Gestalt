/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
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

    friend class DES_Functions;

public:
    explicit DES(const std::string& hexKey) {
        generateRoundKeys(hexToBinary(hexKey));
    }

    uint64_t encryptBlock(uint64_t block);
    uint64_t decryptBlock(uint64_t block);
};

std::string applyPCKS5Padding(const std::string& data);
std::string removePKCS5Padding(const std::string& data);
uint64_t hexStringToUint64(const std::string& hexStr);
std::vector<uint64_t> stringToBlocks(const std::string& str);
std::vector<uint64_t> hexStringToBlocks(const std::string& hex);
std::string blocksToHexString(const std::vector<uint64_t>& blocks);
std::string blocksToString(const std::vector<uint64_t>& blocks);

void validateKey(const std::string& key);
void validateKeys(const std::string& key1, const std::string& key2, const std::string& key3);