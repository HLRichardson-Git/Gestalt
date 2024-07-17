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

/*template<size_t N>
void printBitset(const std::bitset<N>& bs) {
    for (int i = N - 1; i >= 0; --i) {
        std::cout << bs[i];
        if (i % 4 == 0) // Add a space every 4 bits for readability
            std::cout << " ";
    }
    std::cout << std::endl;
}

std::bitset<28> DES::shiftLeft(const std::bitset<28> in) {
    //std::bitset<28> temp;
    //for (size_t i = 1; i < 28; i++) {
    //    temp[i - 1] = in[i];
    //}
    //temp[27] = in[0];
    //return temp;

    std::bitset<28> rotated = in;
    bool msb = rotated[27];
    rotated <<= 1;
    rotated[0] = msb;
    
    return rotated;
}

void DES::expandKey(std::string binaryKey) {
    if(binaryKey.length() != 64) throw std::invalid_argument("Invalid DES key size. Expected 64-bits.");
    std::bitset<28> left, right;
    std::cout << "binary key = " << binaryKey << std::endl;
    for (size_t i = 0; i < 28; i++) {
        left[i] = (binaryKey[PC1[i] - 1] == '1');
        right[i] = (binaryKey[PC1[(i + 28)] - 1] == '1');
    }
    std::cout << "left = ";
    printBitset(left);
    std::cout << "right = ";
    printBitset(right);

    for (size_t i = 0; i < DES_NUM_OF_ROUNDS; i++) {
        left = shiftLeft(left);
        right = shiftLeft(right);
        // rounds 1, 2, 9, 16 are shifted left once, twice if else
        if (!(i == 0 || i == 1 || i == 8 || i == 15)) {
            left = shiftLeft(left);
            right = shiftLeft(right);
        }

        std::bitset<56> temp;
        for (size_t j = 0; j < 28; j++) {
            temp[j] = left[j];
            temp[j + 28] = right[j];
        }
        for (size_t j = 0; j < DES_KEY_SIZE; j++) {
            key[i][j] = temp[PC2[j] - 1];
        }
    }
}*/
// Apply permutation using a specified table
std::bitset<56> DES_BITSET::permute(const std::bitset<64>& input, const int* table, int size) {
    std::bitset<56> output;
    for (int i = 0; i < size; i++) {
        output[size - 1 - i] = input[64 - table[i]];
    }
    return output;
}

std::bitset<48> DES_BITSET::permute(const std::bitset<56>& input, const int* table, int size) {
    std::bitset<48> output;
    for (int i = 0; i < size; i++) {
        output[size - 1 - i] = input[56 - table[i]];
    }
    return output;
}

// Left rotate a 28-bit key
std::bitset<28> DES_BITSET::leftRotate(const std::bitset<28>& key, int shifts) {
    std::bitset<28> rotated = key;
    for (int i = 0; i < shifts; i++) {
        bool msb = rotated[27];
        rotated <<= 1;
        rotated[0] = msb;
    }
    return rotated;
}

void DES_BITSET::generateRoundKeys(std::string binaryKey) {
    std::bitset<64> tempKey(binaryKey);
    // Apply PC1 permutation
    std::bitset<56> permutedKey = permute(tempKey, PC1, 56);

    // Split into left and right halves
    std::bitset<28> left = permutedKey.to_ullong() >> 28;
    std::bitset<28> right = permutedKey.to_ullong() & 0xFFFFFFF;

    // Generate the 16 round keys
    for (int round = 0; round < 16; round++) {
        // Perform left rotations
        left = leftRotate(left, keyShifts[round]);
        right = leftRotate(right, keyShifts[round]);

        // Combine the two halves
        std::bitset<56> combinedKey = (left.to_ullong() << 28) | right.to_ullong();

        // Apply PC2 permutation to get the round key
        key[round] = permute(combinedKey, PC2, 48);
    }
}








/*        STRING                 */

std::string DES_STRING::shiftLeft(std::string keyHalf, int amount)
{
    std::string shifted = "";
    for (int i = 0; i < amount; i++)
    {
        for (int j = 1; j < 28; j++)
        {
            shifted += keyHalf[j];
        }
        shifted += keyHalf[0];
        keyHalf = shifted;
        shifted = "";
    }
    return keyHalf;
}

// Function to generate the 16 sub keys
void DES_STRING::generateKeySchedule(std::string key)
{

    // 1. Compressing our 64-bit key down to 56 bits
    std::string permutation1 = "";
    for (int i = 0; i < 56; i++) {
        permutation1 += key[PC1[i] - 1];
    }

    // 2. Split our key into two halves
    std::string left = permutation1.substr(0, 28);
    std::string right = permutation1.substr(28, 28);

    for (int i = 0; i < 16; i++)
    {
        // 3.1. Rounds 1, 2, 9, 16 are shifted left once
        if (i == 0 || i == 1 || i == 8 || i == 15)
        {
            left = shiftLeft(left, 1);
            right = shiftLeft(right, 1);
        }
        // 3.2. All other rounds are shifted left twice
        else
        {
            left = shiftLeft(left, 2);
            right = shiftLeft(right, 2);
        }

        // 4. Combine the two halves
        std::string combined = left + right;
        std::string permutation2 = "";

        // 5. Permute the two halves into 48-bit sub key i
        for (int j = 0; j < 48; j++) {
            permutation2 += combined[PC2[j] - 1];
        }

        keyRounds[i] = permutation2;
    }
}

/*           UINT64_T                */

/*uint64_t DES_UINT64::permute(uint64_t input, const int* table, int size) {
    uint64_t output = 0;
    for (int i = 0; i < size; ++i) {
        output <<= 1;
        output |= (input >> (64 - table[i])) & 0x01;
    }
    return output;
}*/

uint64_t DES_UINT64::permute64to56(uint64_t input, const int* table, int size) {
    uint64_t output = 0;
    for (int i = 0; i < size; ++i) {
        output <<= 1;
        output |= (input >> (64 - table[i])) & 0x01;
    }
    return output;
}

uint64_t DES_UINT64::permute56to48(uint64_t input, const int* table, int size) {
    uint64_t output = 0;
    for (int i = 0; i < size; ++i) {
        output <<= 1;
        output |= (input >> (56 - table[i])) & 0x01;
    }
    return output;
}

uint32_t DES_UINT64::leftRotate(uint32_t key, int shifts) {
    return ((key << shifts) & 0x0FFFFFFF) | (key >> (28 - shifts));
}

void DES_UINT64::generateRoundKeys(const std::string& binaryKey) {
    uint64_t key = std::bitset<64>(binaryKey).to_ullong();
    uint64_t permutedKey = permute64to56(key, PC1, 56);

    uint32_t C = (permutedKey >> 28) & 0xFFFFFFF;
    uint32_t D = permutedKey & 0xFFFFFFF;

    for (int i = 0; i < 16; ++i) {
        C = leftRotate(C, keyShifts[i]);
        D = leftRotate(D, keyShifts[i]);

        uint64_t combinedKey = (static_cast<uint64_t>(C) << 28) | D;
        roundKeys[i] = permute56to48(combinedKey, PC2, 48);
    }
}
