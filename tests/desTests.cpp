/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * desTests.cpp
 */

#include <iostream>
#include <string>
#include "gtest/gtest.h"

#include <gestalt/des.h>

class testDES {
private:
    DES_BITSET des;
public:
    testDES(std::string hexKey) : des(hexKey) {};

    std::string getKey(size_t index) { return des.key[index].to_string(); };
};

class testDES_UINT64 {
private:
    DES_UINT64 des;
public:
    testDES_UINT64(std::string hexKey) : des(hexKey) {};

    std::string getKey(size_t index) { return std::bitset<DES_KEY_SIZE>(des.roundKeys[index]).to_string(); };
};

const std::string expectedExpandedKey[16] = {
    "001110001010110011101111010001100101011001001010",
    //"000110010100110011010000011100101101111010001100",
    "100010011011111011010100010010001001110100010010",
    "010101000111111011101110010011010100010000111100",
    "111100101111010101100000010010010101100011001000",
    "110010001100111101100111100000001101000000111101",
    "111000011111001100011111100000110001111010100100",
    "001001011001011111100011100110000000101110110001",
    "111100110101100011110011000100110100101000010101",
    "000011001101101001111011101000000000101011000110",
    "101001110111100101011110100101001010001010010111",
    "001011100110111111000001001101110000011011000001",
    "010110110111110100111001000110101010000101000011",
    "110011011010010111011001001001101110010100000100",
    "010101111100111010001111011010000010010111000010",
    "011110111011100110000010111011001100000000001011",
    "110100110011101000101101001000111000110101101000"
};

TEST(testDES_BITSET, keyExpansion)
{
    auto start = std::chrono::high_resolution_clock::now();
    testDES tester("752878397493CB70");
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    std::cout << "Time taken for bitset implementation: " << duration << " nanoseconds" << std::endl;

    for (size_t i = 0; i < 16; i++) {
        EXPECT_EQ(tester.getKey(i), expectedExpandedKey[i]);
    }
}

TEST(testDES_STRING, keyExpansion)
{
    DES_STRING tester;
    std::string binaryString = hexToBinary("752878397493CB70");
    auto start = std::chrono::high_resolution_clock::now();
    tester.generateKeySchedule(binaryString);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    std::cout << "Time taken for bitset implementation: " << duration << " nanoseconds" << std::endl;

    for (size_t i = 0; i < 16; i++) {
        EXPECT_EQ(tester.keyRounds[i], expectedExpandedKey[i]);
    }
}

TEST(testDES_UINT64, keyExpansion)
{
    auto start = std::chrono::high_resolution_clock::now();
    testDES_UINT64 tester("752878397493CB70");
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    std::cout << "Time taken for bitset implementation: " << duration << " nanoseconds" << std::endl;

    for (size_t i = 0; i < 16; i++) {
        EXPECT_EQ(tester.getKey(i), expectedExpandedKey[i]);
    }
}