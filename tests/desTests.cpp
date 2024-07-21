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
#include <bitset> // for testDES
#include "gtest/gtest.h"

#include <gestalt/des.h>
#include "des/desCore.h"
#include "des/desConstants.h"


/*TEST(testDES, encryptECB)
{
    std::string key = "752878397493CB70";
    std::string plaintext = "Hello, Gestalt!";
    std::string ciphertext = desEncryptECB(plaintext, key);
    std::string expected = "fca4a0b8cb579ea8cc830fcf3a5ee2dc";

    EXPECT_EQ(ciphertext, expected);
}*/
const std::string key = "752878397493CB70";
const std::string nonce = "0102030405060708";
const std::string plaintext = "Hello, Gestalt!";

TEST(DES_ECB, encrypt) {
    std::string ciphertext = desEncryptECB(plaintext, key);
    std::string expected = "fca4a0b8cb579ea8cc830fcf3a5ee2dc";

    EXPECT_EQ(ciphertext, expected);
}

TEST(DES_ECB, decrypt) {
    std::string ciphertext = "fca4a0b8cb579ea8cc830fcf3a5ee2dc";
    std::string decryptedPlaintext = desDecryptECB(ciphertext, key);

    EXPECT_EQ(decryptedPlaintext, plaintext);
}

TEST(DES_ECB, multiBlock) {
	std::string multiBlockPT = "In the spring of her twenty-second year, Sumire fell in love for the first time in her life. An intense love, a veritable tornado sweeping across the plains flattening everything in its path, tossing things up in the air, ripping them to shreds, crushing them to bits.";
	std::string ciphertext = desEncryptECB(multiBlockPT, key);
	std::string expected = "e4e386dd911d20a6d3e3adf15c870dd7ee4ab9c3ead6258b3b0f37a400b2d2fa96aedd4e5bbae6a93c85adaa877d90a835d98b69fc4d3efcd3775123fc812108c28048094fd20758d854bedfb6e8eba0ea286cbf4d67e35aca2577b7a87910c8aaae65bad41491a86e62ebf8795eb7658503c1a8c5f33f10e1a95ed1fd296733e3a0a2b22516384ab3b171019efb7e7724b5b09e44799bee3c79e6ff735c115b593e38e0164da49d772326b3fc101346c2148e59c4260d5c490457329f1d85a9c4587614646a17f63dbc83c0042593c03e9abc44daee687de78fb6b49526816cdaef970d685a97fd7526eae0c7e000dd9d88763daee8569325f7bcaa2f78734408cbcd375d0049da255b286cf13f8e5a";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = desDecryptECB(ciphertext, key);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

TEST(DES_CBC, encrypt) {
    std::string ciphertext = desEncryptCBC(plaintext, nonce, key);
    std::string expected = "95a32bce039b97b209e35f005da93c0c";

    EXPECT_EQ(ciphertext, expected);
}

TEST(DES_CBC, decrypt) {
    std::string ciphertext = "95a32bce039b97b209e35f005da93c0c";
    std::string decryptedPlaintext = desDecryptCBC(ciphertext, nonce, key);

    EXPECT_EQ(decryptedPlaintext, plaintext);
}

TEST(DES_CBC, multiBlock) {
	std::string multiBlockPT = "In the spring of her twenty-second year, Sumire fell in love for the first time in her life. An intense love, a veritable tornado sweeping across the plains flattening everything in its path, tossing things up in the air, ripping them to shreds, crushing them to bits.";
	std::string ciphertext = desEncryptCBC(multiBlockPT, nonce, key);
	std::string expected = "1e7f5cb164f834ccf552938010224f1fe3331b853a236e2ee2712cd49d88319acb7fe7e7ae8279ba44b05cb8146d9a4cf28e84606191ecdcd415320f35ef5919a9d8c79c8885a93087c76748c029be3dbfe5a50f163f1cd04a50f18da13e4e4e8fb9500667b965d12d8f786ca9ef524e62bee6466339568f0598c1a287884c017687b082bda57d3656a6844b298ecb0976f6169ac13fefa853cb73b49b1ce4cdaf9a36388b0e639b3b482a85ffbefbb5de7ea70ce171ce35abad9c825431eba5d5f518345c6f74f3708edfa589b2d5e9207f6b5ecd3d90fe710e088989990aabee547975d7cd56576ab79f038db9154c6d10054118fddace20b66d7debb753f00144676758a8eb25306207aeca21159e";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = desDecryptCBC(ciphertext, nonce, key);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

class DES_Functions {
private:
    DES des;
public:
    explicit DES_Functions(std::string hexKey) : des(hexKey) {};

    std::string getKey(size_t index) { return std::bitset<DES_KEY_SIZE>(des.roundKeys[index]).to_string(); };
    std::string initialPermutation(uint64_t in) { return printIntToBinary(des.permute(in, IP, DES_BLOCK_SIZE, IP_SIZE)); };
    std::string expansion(uint32_t in) { return printIntToBinary(des.permute(static_cast<uint64_t>(in), E, 32, E_SIZE) & 0x0000FFFFFFFFFFFF); };
    std::string sbox(uint64_t in) { return printIntToBinary(des.sboxSubstitution(in)); };
    std::string permutation(uint32_t in) { return printIntToBinary(des.permute(in, P, 32, P_SIZE)); };
    std::string f(uint32_t in) { return printIntToBinary(des.f(in, 0)); };
    std::string finalPermutation(uint64_t in) { return printIntToBinary(des.permute(in, FP, DES_BLOCK_SIZE, FP_SIZE)); };
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

TEST(DES_Functions, keyExpansion)
{
    DES_Functions tester("752878397493CB70");

    for (size_t i = 0; i < 16; i++) {
        EXPECT_EQ(tester.getKey(i), expectedExpandedKey[i]);
    }
}

TEST(DES_Functions, encryptBlock)
{
    DES tester("752878397493CB70");
    uint64_t plaintext = 0x1122334455667788;
    uint64_t ciphertext = tester.encryptBlock(plaintext);
    uint64_t expected = 0xB5219EE81AA7499D;

    EXPECT_EQ(ciphertext, expected);
}

TEST(DES_Functions, decryptBlock)
{
    DES tester("752878397493CB70");
    uint64_t ciphertext = 0xB5219EE81AA7499D;
    uint64_t plaintext = tester.decryptBlock(ciphertext);
    uint64_t expected = 0x1122334455667788;

    EXPECT_EQ(plaintext, expected);
}

TEST(DES_Functions, initialPermutation)
{
    DES_Functions tester("752878397493CB70");
    uint64_t input = 0x1122334455667788;
    std::string output =  tester.initialPermutation(input);
    std::string expected = "0111100001010101011110000101010110000000011001101000000001100110";

    EXPECT_EQ(output, expected);
}

TEST(DES_Functions, expansion)
{
    DES_Functions tester("752878397493CB70");
    uint32_t input = 0x80668066;
    std::string output =  tester.expansion(input);
    std::string expected = "010000000000001100001101010000000000001100001101";

    EXPECT_EQ(output.substr(16, output.size()), expected);
}

TEST(DES_Functions, substitution)
{
    DES_Functions tester("752878397493CB70");
    uint64_t input = 0x78AFE2065547;
    std::string output =  tester.sbox(input);
    std::string expected = "01111011110001101110001001011000";

    EXPECT_EQ(output, expected);
    //EXPECT_EQ(output, expected);
}

TEST(DES_Functions, permutation)
{
    DES_Functions tester("752878397493CB70");
    uint32_t input = 0x7BC6E258;
    std::string output =  tester.permutation(input);
    std::string expected = "01001011011111011101001110000010";

    EXPECT_EQ(output, expected);
    //EXPECT_EQ(output, expected);
}

TEST(DES_Functions, f)
{
    DES_Functions tester("752878397493CB70");
    uint32_t input = 0x80668066;
    std::string output =  tester.f(input);
    std::string expected = "01001011011111011101001110000010";

    EXPECT_EQ(output, expected);
    //EXPECT_EQ(output, expected);
}

TEST(DES_Functions, finalPermutation)
{
    DES_Functions tester("752878397493CB70");
    uint64_t input = 0x4895A5E3AD2BDC34;
    std::string output =  tester.finalPermutation(input);
    std::string expected = "1011010100100001100111101110100000011010101001110100100110011101";
    
    EXPECT_EQ(output, expected);
}