/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * desTests.cpp
 *
 * This file contains the unit tests for the DES Functions (Data Encryption Standard) algorithm implementation.
 */

#include "gtest/gtest.h"
#include <bitset>

#include <gestalt/des.h>
#include "des/desCore.h"
#include "des/desConstants.h"
#include "utils.h"
#include "vectors/vectors_des.h"

class DES_Functions {
private:
    DES des;
public:
    explicit DES_Functions(const SecureBytes& key) : des(key) {};

    std::string getKey(size_t index) { return std::bitset<DES_KEY_SIZE>(des.roundKeys[index]).to_string(); };
    std::string initialPermutation(uint64_t in) { 
        return printIntToBinary(des.permute(in, IP, DES_BLOCK_SIZE, IP_SIZE)); 
    };
    std::string expansion(uint32_t in) { 
        return printIntToBinary(des.permute(static_cast<uint64_t>(in), E, 32, E_SIZE) & 0x0000FFFFFFFFFFFF); 
    };
    std::string sbox(uint64_t in) { return printIntToBinary(des.sboxSubstitution(in)); };
    std::string permutation(uint32_t in) { return printIntToBinary(des.permute(in, P, 32, P_SIZE)); };
    std::string f(uint32_t in) { return printIntToBinary(des.f(in, 0)); };
    std::string finalPermutation(uint64_t in) { 
        return printIntToBinary(des.permute(in, FP, DES_BLOCK_SIZE, FP_SIZE));
    };
};

// Thanks to https://www.nayuki.io/page/des-cipher-internals-in-excel for DES test vector with internal steps
const std::string expectedExpandedKey[16] = {
    "001110001010110011101111010001100101011001001010",
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

TEST(DES_Functions, keyExpansion) {
    DES_Functions tester(SecureBytes::fromHex("752878397493CB70"));

    for (size_t i = 0; i < 16; i++) {
        EXPECT_EQ(tester.getKey(i), expectedExpandedKey[i]);
    }
}

TEST(DES_Functions, encryptBlock) {
    DES tester(SecureBytes::fromHex("752878397493CB70"));
    std::array<uint8_t, 8> block = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    tester.encryptBlock(block);
    std::array<uint8_t, 8> expected = {0xB5, 0x21, 0x9E, 0xE8, 0x1A, 0xA7, 0x49, 0x9D};

    EXPECT_EQ(block, expected);
}

TEST(DES_Functions, decryptBlock) {
    DES tester(SecureBytes::fromHex("752878397493CB70"));
    std::array<uint8_t, 8> block = {0xB5, 0x21, 0x9E, 0xE8, 0x1A, 0xA7, 0x49, 0x9D};
    tester.decryptBlock(block);
    std::array<uint8_t, 8> expected = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

    EXPECT_EQ(block, expected);
}

TEST(DES_Functions, initialPermutation) {
    DES_Functions tester(SecureBytes::fromHex("752878397493CB70"));
    uint64_t input = 0x1122334455667788;
    std::string output =  tester.initialPermutation(input);
    std::string expected = "0111100001010101011110000101010110000000011001101000000001100110";

    EXPECT_EQ(output, expected);
}

TEST(DES_Functions, expansion) {
    DES_Functions tester(SecureBytes::fromHex("752878397493CB70"));
    uint32_t input = 0x80668066;
    std::string output =  tester.expansion(input);
    std::string expected = "010000000000001100001101010000000000001100001101";

    EXPECT_EQ(output.substr(16, output.size()), expected);
}

TEST(DES_Functions, substitution) {
    DES_Functions tester(SecureBytes::fromHex("752878397493CB70"));
    uint64_t input = 0x78AFE2065547;
    std::string output =  tester.sbox(input);
    std::string expected = "01111011110001101110001001011000";

    EXPECT_EQ(output, expected);
}

TEST(DES_Functions, permutation) {
    DES_Functions tester(SecureBytes::fromHex("752878397493CB70"));
    uint32_t input = 0x7BC6E258;
    std::string output =  tester.permutation(input);
    std::string expected = "01001011011111011101001110000010";

    EXPECT_EQ(output, expected);
}

TEST(DES_Functions, f) {
    DES_Functions tester(SecureBytes::fromHex("752878397493CB70"));
    uint32_t input = 0x80668066;
    std::string output =  tester.f(input);
    std::string expected = "01001011011111011101001110000010";

    EXPECT_EQ(output, expected);
}

TEST(DES_Functions, finalPermutation) {
    DES_Functions tester(SecureBytes::fromHex("752878397493CB70"));
    uint64_t input = 0x4895A5E3AD2BDC34;
    std::string output =  tester.finalPermutation(input);
    std::string expected = "1011010100100001100111101110100000011010101001110100100110011101";

    EXPECT_EQ(output, expected);
}

TEST(DES_Errors, singleKeyInvalidSize) {
    SecureBytes smallKey(3, 0x00);   // 3 bytes — too small for DES
    EXPECT_THROW(encryptDESECB(plaintext, smallKey), std::invalid_argument);

    SecureBytes largeKey(16, 0x00);  // 16 bytes — too large for DES
    EXPECT_THROW(encryptDESECB(plaintext, largeKey), std::invalid_argument);
}

TEST(TDES_Errors, invalidKeyArrangement) {
    SecureBytes largeKey(16, 0x00);  // 16 bytes — too large for DES
    EXPECT_THROW(encrypt3DESECB(plaintext, largeKey, key2, key3), std::invalid_argument);
    EXPECT_THROW(encrypt3DESECB(plaintext, key, key, key3), std::invalid_argument);
    EXPECT_THROW(encrypt3DESECB(plaintext, key, key2, key2), std::invalid_argument);
    EXPECT_THROW(encrypt3DESECB(plaintext, key, key, key), std::invalid_argument);
}