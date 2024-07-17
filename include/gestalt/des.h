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
#include <bitset> // for bitset implementation
#include <array> // for uint64_t implementation
#include <chrono> // this can be removed when benchmarking is done

#include "../../tools/utils.h"

const size_t DES_KEY_SIZE = 48;
const size_t DES_BLOCK_SIZE = 64;
const size_t DES_NUM_OF_ROUNDS = 16;

class DES_BITSET {
private:

    std::bitset<DES_KEY_SIZE> key[16];
    std::bitset<DES_BLOCK_SIZE> block;

    std::bitset<56> permute(const std::bitset<64>& input, const int* table, int size);
    std::bitset<48> permute(const std::bitset<56>& input, const int* table, int size);
    std::bitset<28> leftRotate(const std::bitset<28>& key, int shifts);
    void generateRoundKeys(std::string binaryKey);

    friend class testDES;
public:

    explicit DES_BITSET(const std::string& hexKey) {
        generateRoundKeys(hexToBinary(hexKey));
    };
};

class DES_STRING {
public:

	std::string keyRounds[16];

	std::string shiftLeft(std::string keyHalf, int amount);
	void generateKeySchedule(std::string key);
};

class DES_UINT64 {
private:
    std::array<uint64_t, 16> roundKeys;
    uint64_t block;

    //uint64_t permute(uint64_t input, const int* table, int size);
    uint64_t permute64to56(uint64_t input, const int* table, int size);
    uint64_t permute56to48(uint64_t input, const int* table, int size);
    uint32_t leftRotate(uint32_t key, int shifts);
    void generateRoundKeys(const std::string& binaryKey);

    friend class testDES_UINT64;

public:
    explicit DES_UINT64(const std::string& hexKey) {
        generateRoundKeys(hexToBinary(hexKey));
    }
};