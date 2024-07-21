/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * aesTests.cpp
 *
 * This file contains the unit tests for the AES (Advanced Encryption Standard) algorithm implementation.
 * The tests cover various scenarios including roundtrip encryption and decryption with different key sizes,
 * key expansion, AES block operations (SubBytes, ShiftRows, MixColumns), and AES inverse block operations.
 */

#include "gtest/gtest.h"
#include <iostream>
#include <cstring>

#include <gestalt/aes.h>

#include "../src/aes/aesCore.h"
#include "modes/modes.h"
#include "../tools/utils.h"

AES_Functions testFunctions;
const std::string plaintext = "Hello, Gestalt!";
std::string nonce = "01020304050607080910111213141516";

// Unit tests for AES ECB mode with 128-bit key
TEST(AES_ECB, 128) {
	const std::string key = "10a58869d74be5a374cf867cfb473859";

	std::string ciphertext = aesEncryptECB(plaintext, key);
	std::string expected = "f161272a11982e3421fea21823ae82ab";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = aesDecryptECB(ciphertext, key);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

// Unit tests for AES ECB mode with 192-bit key
TEST(AES_ECB, 192) {
	const std::string key = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";

	std::string ciphertext = aesEncryptECB(plaintext, key);
	std::string expected = "8803e5855cdf85314d118bad1b0291bc";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = aesDecryptECB(ciphertext, key);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

// Unit tests for AES ECB mode with 256-bit key
TEST(AES_ECB, 256) {
	const std::string key = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";

	std::string ciphertext = aesEncryptECB(plaintext, key);
	std::string expected = "6a99877e03ae0219f69d73c8c8c3d735";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = aesDecryptECB(ciphertext, key);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

TEST(AES_ECB, multiBlock) {
	const std::string key = "10a58869d74be5a374cf867cfb473850";
	std::string multiBlockPT = "In the spring of her twenty-second year, Sumire fell in love for the first time in her life. An intense love, a veritable tornado sweeping across the plains flattening everything in its path, tossing things up in the air, ripping them to shreds, crushing them to bits.";
	std::string ciphertext = aesEncryptECB(multiBlockPT, key);
	std::string expected = "ffdbbdbc66629c0ea62a3505de438c90d769fdd9d9d7b8a31a783d52b1629be49c4e1d3e109f1788ef78b8943763b5791b8564e6aa65048ed7142681c2f4914d617fbe9854321068d5cfc867c4b8543bcc68c8146bf89ddab089280bcd0f899f8eee9a6d9991eae1ddb2beb92e1d3aa3303775eaf8ed1f4548e495d0f3858ef91ae8b5a0b7df816d833977a4810200452e204acc467146d5933f792ede29f304fad8ab92ed481716b8bbe50c2bc215e9dcc841050b321635050b37c49dae737856313582707126850c7ad3702f3a5d0c0102595d3fffba50f18cd39fdedb21a15e9f5448c8b12e36af54a1796aa5b73e483d2a12ffba0eb527417848037424221f3d31ad33189485cf0823ff04a8b838";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = aesDecryptECB(ciphertext, key);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

// Unit tests for AES CBC mode with 128-bit key
TEST(AES_CBC, 128) {
	const std::string key = "10a58869d74be5a374cf867cfb473850";
	std::string ciphertext = aesEncryptCBC(plaintext, nonce, key);
	std::string expected = "25aaf47a5c3cf51721af5962c74bcf62";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = aesDecryptCBC(ciphertext, nonce, key);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

// Unit tests for AES CBC mode with 192-bit key
TEST(AES_CBC, 192) {
	const std::string key = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";

	std::string ciphertext = aesEncryptCBC(plaintext, nonce, key);
	std::string expected = "beb6831697004e90f0c09a941b6ddefa";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = aesDecryptCBC(ciphertext, nonce, key);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

// Unit tests for AES CBC mode with 256-bit key
TEST(AES_CBC, 256) {
	const std::string key = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";

	std::string ciphertext = aesEncryptCBC(plaintext, nonce, key);
	std::string expected = "235804bb2e2e8a51e559ba9d4c73963d";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = aesDecryptCBC(ciphertext, nonce, key);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

TEST(AES_CBC, multiBlock) {
	const std::string key = "10a58869d74be5a374cf867cfb473850";
	std::string multiBlockPT = "In the spring of her twenty-second year, Sumire fell in love for the first time in her life. An intense love, a veritable tornado sweeping across the plains flattening everything in its path, tossing things up in the air, ripping them to shreds, crushing them to bits.";
	std::string ciphertext = aesEncryptCBC(multiBlockPT, nonce, key);
	std::string expected = "565b23e9de132e60e5f376f4c64726cc7504d5a4290b31cf43c90200c726ad2449e06c4f6ffc11d855e2f0851313f7d60f1a2c2774f30b0d189b80de1da0beb947defdb06237e264912c7b7b5a6bc0b745a233d666329cd40e7486aca446ee11dc325fc4bbbbab943193dddce82b540201c2e57374772b7dafef1598347a08c15fafb497fe574d2d749add9011a0ee8c69316d00202d9eb4a6ec30fee335785d4df23b7901befaee18bfa8a77536e922a69c6a8b5769cb4f220a5ad6ae61f2e9c84f99152fd24b14e058dc8575e4cacd456dd33a3b8f1b702ac92a15f1139ec66a2f4988b49fa87dba4aeb93ecd5ad9c8163f2209574b75430b1ca8f518150a34d8c624913ce320359e04929de54da04";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = aesDecryptCBC(ciphertext, nonce, key);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

// Unit tests for AES key expansion
TEST(AES, KeyExpansion) {
	const unsigned char* roundKey = testFunctions.testKeyExpansion();

	const std::string expectedStr = "10a58869d74be5a374cf867cfb473859b1a2436666e9a6c5122620b9e96118e05c0fa2783ae604bd28c02404c1a13ce46ae4cb005002cfbd78c2ebb9b963d75d99ea8756c9e848ebb12aa3520849740fb278f1667b90b98dcaba1adfc2f36ed09fe78143e47738ce2ecd2211ec3e4cc16dcef98d89b9c143a774e3524b4aaf933bb7253eb20ee47d157a072f5e30a8bc24754066967ba41b8301a334dd310b88d55e84a7432520bcc02483881d158800";
	size_t arraySize = expectedStr.length() / 2;
    unsigned char* expectedByteArray = new unsigned char[arraySize];
    hexStringToBytes(expectedStr, expectedByteArray);

	// Compare computed round key with expected round key
	bool arraysEqual = true;
	for (size_t i = 0; i < arraySize; ++i) {
		if (roundKey[i] != expectedByteArray[i]) {
			arraysEqual = false;
			break;
		}
	}

	// Check if computed round key matches the expected round key
	EXPECT_TRUE(arraysEqual);
	// Clean up memory
	delete[] expectedByteArray;
}

// Unit test for SubBytes operation
TEST(AES_Functions, SubByte) {
	// Prepare input data
	unsigned char state[16] = {0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a};

	testFunctions.testSubByte(state);

	// Expected output after SubByte transformation
	const unsigned char expected[16] = {0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	// Check if the output matches the expected output
	EXPECT_TRUE(arraysEqaul);
}

// Unit test for ShiftRows operation
TEST(AES_Functions, shiftRows) {
	// Prepare input data
	unsigned char state[16] = {0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe};

	// Call the shiftRows function and test
	testFunctions.testShiftRows(state);

	const unsigned char expected[16] = {0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	// Check if the output matches the expected output
	EXPECT_TRUE(arraysEqaul);
}

// Unit test for MixColumns operation
TEST(AES_Functions, mixColumns) {
	// Prepare input data
	unsigned char state[16] = {0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad};

	// Call the mixColumns function and test
	testFunctions.testMixColumns(state);

	const unsigned char expected[16] = {0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	// Check if the output matches the expected output
	EXPECT_TRUE(arraysEqaul);
}

// Unit test for AddRoundKey operation
TEST(AES_Functions, addRoundKey) {
	// Prepare input data
	unsigned char state[16] = {0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4};
	const unsigned char key[16] = {0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a};

	// Call the addRoundKey function and test
	testFunctions.testAddRoundKey(state, key);

	const unsigned char expected[16] = {0x21, 0x97, 0xc7, 0xde, 0x67, 0xa9, 0xb1, 0x0e, 0xa5, 0x20, 0x56, 0xe5, 0xaa, 0x20, 0x6d, 0xfe};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	// Check if the output matches the expected output
	EXPECT_TRUE(arraysEqaul);
}

// Unit test for inverse SubBytes operation
TEST(AES_Functions, invSubByte) {
	// Prepare input data
	unsigned char state[16] = {0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69};

	// Call the invSubByte function and test
	testFunctions.testInvSubByte(state);

	const unsigned char expected[16] = {0x20, 0x53, 0xc7, 0xde, 0x46, 0x5d, 0xc2, 0xe2, 0x82, 0x65, 0x20, 0x14, 0x22, 0x08, 0xac, 0xe4};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	// Check if the output matches the expected output
	EXPECT_TRUE(arraysEqaul);
}

// Unit test for inverse ShiftRows operation
TEST(AES_Functions, invShiftRows) {
	// Prepare input data
	unsigned char state[16] = {0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa};

	// Call the invSubByte function and test
	testFunctions.testInvShiftRows(state);

	const unsigned char expected[16] = {0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	// Check if the output matches the expected output
	EXPECT_TRUE(arraysEqaul);
}

// Unit test for inverse MixColumns operation
TEST(AES_Functions, invMixColumns) {
	// Prepare input data
	unsigned char state[16] = {0x7f, 0x84, 0x35, 0xeb, 0xef, 0x75, 0x09, 0x08, 0x28, 0xba, 0x07, 0xe8, 0xce, 0xc7, 0x21, 0x89};

	// Call the invSubByte function and test
	testFunctions.testInvMixColumns(state);

	const unsigned char expected[16] = {0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	// Check if the output matches the expected output
	EXPECT_TRUE(arraysEqaul);
}