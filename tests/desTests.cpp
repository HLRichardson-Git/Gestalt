/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * desTests.cpp
 *
 * This file contains the unit tests for the DES (Data Encryption Standard) algorithm implementation.
 */

#include "gtest/gtest.h"
#include <bitset>

#include <gestalt/des.h>
#include "des/desCore.h"
#include "des/desConstants.h"

const std::string key = "752878397493CB70";
const std::string key2 = "10316E028C8F3B4A";
const std::string key3 = "7CA110454A1A6E57";
const std::string nonce = "0102030405060708";
const std::string plaintext = "Hello, Gestalt!";
const std::string multiBlockPT = 
    "In the spring of her twenty-second year, Sumire fell in love for the first time in her life. An intense love, "
    "a veritable tornado sweeping across the plains flattening everything in its path, tossing things up in the air, "
    "ripping them to shreds, crushing them to bits.";

TEST(DES_ECB, encrypt) {
    std::string ciphertext = encryptDESECB(plaintext, key);
    std::string expected = "fca4a0b8cb579ea8cc830fcf3a5ee2dc";
    EXPECT_EQ(ciphertext, expected);
}

TEST(DES_ECB, decrypt) {
    std::string ciphertext = "fca4a0b8cb579ea8cc830fcf3a5ee2dc";
    std::string decryptedPlaintext = decryptDESECB(ciphertext, key);
    EXPECT_EQ(decryptedPlaintext, plaintext);
}

TEST(DES_ECB, multiBlock) {
	std::string ciphertext = encryptDESECB(multiBlockPT, key);
	std::string expected = 
        "e4e386dd911d20a6d3e3adf15c870dd7ee4ab9c3ead6258b3b0f37a400b2d2fa96aedd4e5bbae6a93c85adaa877d90a835d98b69fc4d3"
        "efcd3775123fc812108c28048094fd20758d854bedfb6e8eba0ea286cbf4d67e35aca2577b7a87910c8aaae65bad41491a86e62ebf879"
        "5eb7658503c1a8c5f33f10e1a95ed1fd296733e3a0a2b22516384ab3b171019efb7e7724b5b09e44799bee3c79e6ff735c115b593e38e"
        "0164da49d772326b3fc101346c2148e59c4260d5c490457329f1d85a9c4587614646a17f63dbc83c0042593c03e9abc44daee687de78f"
        "b6b49526816cdaef970d685a97fd7526eae0c7e000dd9d88763daee8569325f7bcaa2f78734408cbcd375d0049da255b286cf13f8e5a";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = decryptDESECB(ciphertext, key);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

TEST(TDES_ECB, encrypt) {
    std::string ciphertext = encrypt3DESECB(plaintext, key, key2, key3);
    std::string expected = "8b3a49695d593b3633f5d3a48c4de370";
    EXPECT_EQ(ciphertext, expected);
}

TEST(TDES_ECB, decrypt) {
    std::string ciphertext = "8b3a49695d593b3633f5d3a48c4de370";
    std::string decryptedPlaintect = decrypt3DESECB(ciphertext, key, key2, key3);
    EXPECT_EQ(decryptedPlaintect, plaintext);
}

TEST(TDES_ECB, multiBlock) {
	std::string ciphertext = encrypt3DESECB(multiBlockPT, key, key2, key3);
	std::string expected = 
        "4c730a6b6936f51cbed96f7930f4fc897074d5a6e4112e51f13a47639667890533800ac69dd821ef35ce239a6a04483741b3fc3fe252b"
        "9d18705b9c8c4457d3a617e09d07473a33be5f7ab899427be78bdfc1dc0fc9780e4e5e7cb3b33bbd8edccbf7ef518c9f22581d662c385"
        "6bb63585d6d6ebc5525d391bbfb91be2041edaf9d8bb96a628842b9a5f4c90b0261e7730ac33988bbebe967fe3ff2b02db667821498c1"
        "46fc5d4ee39a73b1e3a4d340c43638bb0626664fc3a82bd621370dafc20b32ce84e2ca33b4120f06926cfb35a5738d02181cd5ce019aa"
        "be345d2fd7b756ccd38103a2564247f20ab8e54e8d8c0ccc3a1891fe2c90791123a1de0f1326e0e3d0a9ddc229092212f4f736e24010";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = decrypt3DESECB(ciphertext, key, key2, key3);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

TEST(DES_CBC, encrypt) {
    std::string ciphertext = encryptDESCBC(plaintext, nonce, key);
    std::string expected = "95a32bce039b97b209e35f005da93c0c";
    EXPECT_EQ(ciphertext, expected);
}

TEST(DES_CBC, decrypt) {
    std::string ciphertext = "95a32bce039b97b209e35f005da93c0c";
    std::string decryptedPlaintext = decryptDESCBC(ciphertext, nonce, key);
    EXPECT_EQ(decryptedPlaintext, plaintext);
}

TEST(DES_CBC, multiBlock) {
	std::string ciphertext = encryptDESCBC(multiBlockPT, nonce, key);
	std::string expected = 
        "1e7f5cb164f834ccf552938010224f1fe3331b853a236e2ee2712cd49d88319acb7fe7e7ae8279ba44b05cb8146d9a4cf28e84606191e"
        "cdcd415320f35ef5919a9d8c79c8885a93087c76748c029be3dbfe5a50f163f1cd04a50f18da13e4e4e8fb9500667b965d12d8f786ca9"
        "ef524e62bee6466339568f0598c1a287884c017687b082bda57d3656a6844b298ecb0976f6169ac13fefa853cb73b49b1ce4cdaf9a363"
        "88b0e639b3b482a85ffbefbb5de7ea70ce171ce35abad9c825431eba5d5f518345c6f74f3708edfa589b2d5e9207f6b5ecd3d90fe710e"
        "088989990aabee547975d7cd56576ab79f038db9154c6d10054118fddace20b66d7debb753f00144676758a8eb25306207aeca21159e";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = decryptDESCBC(ciphertext, nonce, key);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

TEST(TDES_CBC, encrypt) {
    std::string ciphertext = encrypt3DESCBC(plaintext, nonce, key, key2, key3);
    std::string expected = "ee6edc51099b7783bf57f381d620957c";
    EXPECT_EQ(ciphertext, expected);
}

TEST(TDES_CBC, decrypt) {
    std::string ciphertext = "ee6edc51099b7783bf57f381d620957c";
    std::string decryptedPlaintext = decrypt3DESCBC(ciphertext, nonce, key, key2, key3);
    EXPECT_EQ(decryptedPlaintext, plaintext);
}

TEST(TDES_CBC, multiBlock) {
	std::string ciphertext = encrypt3DESCBC(multiBlockPT, nonce, key, key2, key3);
	std::string expected = 
        "bda177e57c5e45bf91b02e7824b9cd8b3b4fa15977ad9c8e01f9679c6c6695a3ae14338de9ef5dc82a55cb65d5b135878e93e3b1b22ee"
        "823c52ed330aaeade44b3d5d09958f75f95f881c5dc189beb2b72422436aca2b2de21edb9c580d365947b5709850b4bc0248b58c770c6"
        "e08aa0d61b6f90895206f321da34f68a1d8f6f813fd1533e7584e2e6ae8115b4f6f8c5a7fa1689e4def62e84498215d0ad6b6f1a51bb0"
        "bf9f838ffde2f13ae4c0960b22184526b856a66c3b1d0ad146a42acb3e0b412bbc5c91fc5c551bd464e8e88b44d4ccdf5d707c096001c"
        "3f024b57dcf1930fcbdcfec724e48a702a87d27a579b96e595b5f5b6c4a56b0727f0b1f530ebff2186d839f1412bcecf3b7a3c4b1e3c";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = decrypt3DESCBC(ciphertext, nonce, key, key2, key3);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

TEST(DES_Erros, singleKeyInvalidSize) {
    std::string smallKey = "abc";
    EXPECT_THROW(encryptDESECB(plaintext, smallKey), std::invalid_argument);

    std::string largeKey = "10a58869d74be5a374cf867cfb473859";
    EXPECT_THROW(encryptDESECB(plaintext, smallKey), std::invalid_argument);
}

TEST(TDES_Erros, invalidKeyArrangement) {
    std::string largeKey = "10a58869d74be5a374cf867cfb473859";
    EXPECT_THROW(encrypt3DESECB(plaintext, largeKey, key2, key3), std::invalid_argument);
    EXPECT_THROW(encrypt3DESECB(plaintext, key, key, key3), std::invalid_argument);
    EXPECT_THROW(encrypt3DESECB(plaintext, key, key2, key2), std::invalid_argument);
    EXPECT_THROW(encrypt3DESECB(plaintext, key, key, key), std::invalid_argument);
}

class DES_Functions {
private:
    DES des;
public:
    explicit DES_Functions(const std::string& hexKey) : des(hexKey) {};

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

TEST(DES_Functions, keyExpansion) {
    DES_Functions tester("752878397493CB70");

    for (size_t i = 0; i < 16; i++) {
        EXPECT_EQ(tester.getKey(i), expectedExpandedKey[i]);
    }
}

TEST(DES_Functions, encryptBlock) {
    DES tester("752878397493CB70");
    uint64_t plaintext = 0x1122334455667788;
    uint64_t ciphertext = tester.encryptBlock(plaintext);
    uint64_t expected = 0xB5219EE81AA7499D;

    EXPECT_EQ(ciphertext, expected);
}

TEST(DES_Functions, decryptBlock) {
    DES tester("752878397493CB70");
    uint64_t ciphertext = 0xB5219EE81AA7499D;
    uint64_t plaintext = tester.decryptBlock(ciphertext);
    uint64_t expected = 0x1122334455667788;

    EXPECT_EQ(plaintext, expected);
}

TEST(DES_Functions, initialPermutation) {
    DES_Functions tester("752878397493CB70");
    uint64_t input = 0x1122334455667788;
    std::string output =  tester.initialPermutation(input);
    std::string expected = "0111100001010101011110000101010110000000011001101000000001100110";

    EXPECT_EQ(output, expected);
}

TEST(DES_Functions, expansion) {
    DES_Functions tester("752878397493CB70");
    uint32_t input = 0x80668066;
    std::string output =  tester.expansion(input);
    std::string expected = "010000000000001100001101010000000000001100001101";

    EXPECT_EQ(output.substr(16, output.size()), expected);
}

TEST(DES_Functions, substitution) {
    DES_Functions tester("752878397493CB70");
    uint64_t input = 0x78AFE2065547;
    std::string output =  tester.sbox(input);
    std::string expected = "01111011110001101110001001011000";

    EXPECT_EQ(output, expected);
}

TEST(DES_Functions, permutation) {
    DES_Functions tester("752878397493CB70");
    uint32_t input = 0x7BC6E258;
    std::string output =  tester.permutation(input);
    std::string expected = "01001011011111011101001110000010";

    EXPECT_EQ(output, expected);
}

TEST(DES_Functions, f) {
    DES_Functions tester("752878397493CB70");
    uint32_t input = 0x80668066;
    std::string output =  tester.f(input);
    std::string expected = "01001011011111011101001110000010";

    EXPECT_EQ(output, expected);
}

TEST(DES_Functions, finalPermutation) {
    DES_Functions tester("752878397493CB70");
    uint64_t input = 0x4895A5E3AD2BDC34;
    std::string output =  tester.finalPermutation(input);
    std::string expected = "1011010100100001100111101110100000011010101001110100100110011101";
    
    EXPECT_EQ(output, expected);
}