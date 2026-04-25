/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * desCore.cpp
 *
 * This file contains the implementation of Gestalts DES security functions.
 */

#include <bitset>
#include <cstring>
#include <vector>

#include "desCore.h"
#include "desConstants.h"

uint64_t DES::permute(uint64_t input, const int* table, int inputSize, int outputSize) {
    uint64_t output = 0;
    for (int i = 0; i < outputSize; ++i) {
        output <<= 1;
        output |= (input >> (inputSize - table[i])) & 0x01;
    }
    return output;
}

uint32_t DES::permute(uint32_t input, const int* table, int inputSize, int outputSize) {
    uint32_t output = 0;
    for (int i = 0; i < outputSize; ++i) {
        output <<= 1;
        output |= (input >> (inputSize - table[i])) & 0x01;
    }
    return output;
}

uint32_t DES::leftRotate(uint32_t key, int shifts) {
    return ((key << shifts) & 0x0FFFFFFF) | (key >> (28 - shifts));
}

void DES::generateRoundKeys(uint64_t key) {
    uint64_t permutedKey = permute(key, PC1, 64, PC1_SIZE);

    uint32_t left = (permutedKey >> 28) & 0xFFFFFFF;
    uint32_t right = permutedKey & 0xFFFFFFF;

    for (int i = 0; i < 16; ++i) {
        left = leftRotate(left, keyShifts[i]);
        right = leftRotate(right, keyShifts[i]);

        uint64_t combinedKey = (static_cast<uint64_t>(left) << 28) | right;
        roundKeys[i] = permute(combinedKey, PC2, 56, PC2_SIZE);
    }
}

uint32_t DES::sboxSubstitution(uint64_t input) {
    uint32_t output = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t chunk = (input >> (42 - 6 * i)) & 0x3F;
        int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        int col = (chunk >> 1) & 0x0F; 
        output <<= 4;
        output |= SBOX[i][row][col];
    }
    return output;
}

uint32_t DES::f(uint32_t rightChunk, size_t round) {
    uint64_t expandedChunk = permute(static_cast<uint64_t>(rightChunk), E, 32, E_SIZE) & 0x0000FFFFFFFFFFFF;
    return permute(sboxSubstitution(expandedChunk ^ roundKeys[round]), P, 32, P_SIZE);
}  

uint64_t DES::encryptBlock(uint64_t block) {
    block = permute(block, IP, DES_BLOCK_SIZE, IP_SIZE); // Initial permutation

    uint32_t left = (block >> 32) & 0xFFFFFFFF;
    uint32_t right = block & 0xFFFFFFFF;

    for (size_t round = 0; round < DES_NUM_OF_ROUNDS - 1; round++) {
        uint32_t temp = left ^ f(right, round);

        left = right;
        right = temp;
    }

    // Final round without swapping halves
    left ^= f(right, DES_NUM_OF_ROUNDS - 1);
    block = (static_cast<uint64_t>(left) << 32) | right;

    return permute(block, FP, DES_BLOCK_SIZE, FP_SIZE); // Final permutation
}

uint64_t DES::decryptBlock(uint64_t block) {
    block = permute(block, IP, DES_BLOCK_SIZE, IP_SIZE); // Initial permutation

    uint32_t left = (block >> 32) & 0xFFFFFFFF;
    uint32_t right = block & 0xFFFFFFFF;

    for (size_t round = DES_NUM_OF_ROUNDS - 1; round > 0; --round) {
        uint32_t temp = left ^ f(right, round);

        left = right;
        right = temp;
    }

    // Final round without swapping halves
    left ^= f(right, 0);
    block = (static_cast<uint64_t>(left) << 32) | right;

    return permute(block, FP, DES_BLOCK_SIZE, FP_SIZE); // Final permutation
}

SecureBytes applyPCKS5Padding(const SecureBytes& data) {
    size_t paddingLength = 8 - (data.size() % 8);
    SecureBytes result(data.size() + paddingLength);
    std::memcpy(result.data(), data.data(), data.size());
    std::memset(result.data() + data.size(), static_cast<int>(paddingLength), paddingLength);
    return result;
}

SecureBytes removePKCS5Padding(const SecureBytes& data) {
    if (data.empty()) {
        throw std::runtime_error("Data is empty, cannot remove padding.");
    }
    size_t paddingLength = data[data.size() - 1];
    if (paddingLength > data.size() || paddingLength > 8) {
        throw std::runtime_error("Invalid padding length.");
    }
    SecureBytes result(data.size() - paddingLength);
    std::memcpy(result.data(), data.data(), result.size());
    return result;
}

uint64_t bytesToUint64(const SecureBytes& bytes) {
    if (bytes.size() != 8) {
        throw std::invalid_argument("Must be 8 bytes");
    }
    uint64_t result = 0;
    for (size_t i = 0; i < 8; ++i)
        result = (result << 8) | bytes[i];
    return result;
}

std::vector<uint64_t> bytesToBlocks(const SecureBytes& bytes) {
    std::vector<uint64_t> blocks;
    for (size_t i = 0; i < bytes.size(); i += 8) {
        uint64_t block = 0;
        for (size_t j = 0; j < 8 && i + j < bytes.size(); ++j)
            block = (block << 8) | bytes[i + j];
        blocks.push_back(block);
    }
    return blocks;
}

SecureBytes blocksToBytes(const std::vector<uint64_t>& blocks) {
    SecureBytes result(blocks.size() * 8);
    for (size_t b = 0; b < blocks.size(); ++b)
        for (int i = 7; i >= 0; --i)
            result[b * 8 + (7 - i)] = static_cast<uint8_t>((blocks[b] >> (i * 8)) & 0xFF);
    return result;
}

void validateKey(const SecureBytes& key) {
    if (key.size() != 8) {
        throw std::invalid_argument("DES key must be 8 bytes.");
    }
}

void validateKeys(const SecureBytes& key1, const SecureBytes& key2, const SecureBytes& key3) {
    if (key1.size() != 8 || key2.size() != 8 || key3.size() != 8) {
        throw std::invalid_argument("Each DES key must be 8 bytes.");
    }

    bool isThreeKey = (key1 != key2 && key1 != key3 && key2 != key3);
    bool isTwoKey = (key1 == key3 && key1 != key2);

    if (!isThreeKey && !isTwoKey) {
        throw std::invalid_argument(
            "Invalid keys: for 3-key 3DES, all keys must be distinct; "
            "for 2-key 3DES, key1 must equal key3 and key1 must be distinct from key2."
        );
    }
}