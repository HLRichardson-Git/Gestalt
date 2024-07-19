/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * des.cpp
 *
 * This file contains the implementation of Gestalts DES security functions.
 */

#include <iostream>
#include <string>
#include <bitset>

#include <gestalt/des.h>
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

void DES::generateRoundKeys(const std::string& binaryKey) {
    uint64_t key = std::bitset<64>(binaryKey).to_ullong();
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

uint64_t DES::encryptRound(uint64_t block, size_t round) {
    uint32_t left = (block >> 32) & 0xFFFFFFFF;
    uint32_t right = block & 0xFFFFFFFF;

    left ^= f(right, round);

    return (static_cast<uint64_t>(right) << 32) | left; // swap and combine halves
}

uint64_t DES::encryptBlock(uint64_t block) {
    block = permute(block, IP, DES_BLOCK_SIZE, IP_SIZE); // Initial permutation

    for (size_t round = 0; round < DES_NUM_OF_ROUNDS - 1; round++) {
        block = encryptRound(block, round);
    }

    // Final round without swapping halves
    uint32_t left = (block >> 32) & 0xFFFFFFFF;
    uint32_t right = block & 0xFFFFFFFF;
    left ^= f(right, DES_NUM_OF_ROUNDS - 1);

    block = (static_cast<uint64_t>(left) << 32) | right;

    return permute(block, FP, DES_BLOCK_SIZE, FP_SIZE); // Final permutation
}