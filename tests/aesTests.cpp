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

#include <gestalt/aes.h>
#include "../src/aes/aesCore.h"
#include "../tools/utils.h"

AES_Functions testFunctions;

const std::string key128 = "10a58869d74be5a374cf867cfb473859";
const std::string key192 = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";
const std::string key256 = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";
const std::string plaintext = "Hello, Gestalt!";
const std::string nonce = "01020304050607080910111213141516";
const std::string multiBlockPT = 
    "Everything that lives is designed to end. We are perpetually trapped in a never-ending spiral of life and death. "
	"Is this a curse? Or some kind of punishment? I often think about the god who blessed us with this "
	"cryptic puzzle...and wonder if we'll ever get the chance to kill him.";

TEST(AES_ECB, encrypt128) {
	std::string ciphertext = encryptAESECB(plaintext, key128);
	std::string expected = "f161272a11982e3421fea21823ae82ab";
	EXPECT_EQ(ciphertext, expected); 
}

TEST(AES_ECB, decrypt128) {
	std::string ciphertext = "f161272a11982e3421fea21823ae82ab";
	std::string descryptedPlaintext = decryptAESECB(ciphertext, key128);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

TEST(AES_ECB, encrypt192) {
	std::string ciphertext = encryptAESECB(plaintext, key192);
	std::string expected = "8803e5855cdf85314d118bad1b0291bc";
	EXPECT_EQ(ciphertext, expected); 
}

TEST(AES_ECB, decrypt192) {
	std::string ciphertext = "8803e5855cdf85314d118bad1b0291bc";
	std::string descryptedPlaintext = decryptAESECB(ciphertext, key192);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

TEST(AES_ECB, encrypt256) {
	std::string ciphertext = encryptAESECB(plaintext, key256);
	std::string expected = "6a99877e03ae0219f69d73c8c8c3d735";
	EXPECT_EQ(ciphertext, expected); 
}

TEST(AES_ECB, decrypt256) {
	std::string ciphertext = "6a99877e03ae0219f69d73c8c8c3d735";
	std::string descryptedPlaintext = decryptAESECB(ciphertext, key256);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

TEST(AES_ECB, multiBlock) {
	std::string ciphertext = encryptAESECB(multiBlockPT, key128);
	std::string expected = 
		"948084c7c03487d76e58b1d9747103578c93790463a680009fc74fcbf59e63a39a044953a4a6e11f99257ab4068ccea583a60daa41fe9"
		"b9dfa20f5352ce4669c914c41110dbac9e0d0bcf92981fb494e87ce717f2ded9ba4b3fea9be4598e324ba93f50414d0cd9f9131357fcc"
		"edf8bf0bb64c4bd16a1cda3e9d823d377284bbe53164922969d1d2a7c982b768a131c7223919e377e66fc09a4f7f74899405b49d5f752"
		"448595de2f5818fe56b442e5354e517d36ccc44b90f7e5abc8f11b1a593a97f4b8193ee6be5ce850da8d6fca3178c06c39c2285915074"
		"79750eaf625fd85055c04479824757f7e57e246fb3fc26c3da324c0a30c030dd3848bd705df289a39ebe1cb6e529508c874d2dc2d616f"
		"8cfb0ab683d1296ce1d5e22bc0dd048";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = decryptAESECB(ciphertext, key128);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

TEST(AES_CBC, encrypt128) {
	std::string ciphertext = encryptAESCBC(plaintext, nonce, key128);
	std::string expected = "54885260a1c3cd22be863ac4bf0e1dcc";
	EXPECT_EQ(ciphertext, expected); 
}

TEST(AES_CBC, decrypt128) {
	std::string ciphertext = "54885260a1c3cd22be863ac4bf0e1dcc";
	std::string descryptedPlaintext = decryptAESCBC(ciphertext, nonce, key128);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

TEST(AES_CBC, encrypt192) {
	std::string ciphertext = encryptAESCBC(plaintext, nonce, key192);
	std::string expected = "beb6831697004e90f0c09a941b6ddefa";
	EXPECT_EQ(ciphertext, expected); 
}

TEST(AES_CBC, decrypt192) {
	std::string ciphertext = "beb6831697004e90f0c09a941b6ddefa";
	std::string descryptedPlaintext = decryptAESCBC(ciphertext, nonce, key192);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

TEST(AES_CBC, encrypt256) {
	std::string ciphertext = encryptAESCBC(plaintext, nonce, key256);
	std::string expected = "235804bb2e2e8a51e559ba9d4c73963d";
	EXPECT_EQ(ciphertext, expected); 
}

TEST(AES_CBC, decrypt256) {
	std::string ciphertext = "235804bb2e2e8a51e559ba9d4c73963d";
	std::string descryptedPlaintext = decryptAESCBC(ciphertext, nonce, key256);
	EXPECT_EQ(descryptedPlaintext, plaintext); 
}

TEST(AES_CBC, multiBlock) {
	std::string ciphertext = encryptAESCBC(multiBlockPT, nonce, key128);
	std::string expected = 
		"383c656f56fd815e6879b18ec85f6774cac53dd7706675584e3a3c6e5abe1b30d83cad1b0b0d2cab69494a3fbb2fed2e6033b9873b807"
		"bda600840a1b3ec26cec2098b72b7e6978110814bac0c55b1232342a6ed615f7cc6e445084efbe86713825f7a251145095f2ef428a3a6"
		"b2eae143240920c355a4cd92c8ab03279232aab21995228d1d718ddb474ab693063fdbbf14e75a78e7134854b5ee49032180eef6c365c"
		"27602d4d3d7909b9d6b6ddbb31e824fc720405799069bbf4dd04c51b30ecdd31586f7018b819ce5d464b55d2a26b16365149ee8431d38"
		"8dce47981a058340eea2c34b5f185939f087dd3d9b401bf617efd334e49546715829bbd984406c8a5913e4e7315c263fcf38d8e357f79"
		"90af830043c18a578840b91454a356a";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = decryptAESCBC(ciphertext, nonce, key128);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

TEST(AES, KeyExpansion) {
	const unsigned char* roundKey = testFunctions.testKeyExpansion();

	const std::string expectedStr = 
		"10a58869d74be5a374cf867cfb473859b1a2436666e9a6c5122620b9e96118e05c0fa2783ae604bd28c02404c1a13ce46ae4cb005002c"
		"fbd78c2ebb9b963d75d99ea8756c9e848ebb12aa3520849740fb278f1667b90b98dcaba1adfc2f36ed09fe78143e47738ce2ecd2211ec"
		"3e4cc16dcef98d89b9c143a774e3524b4aaf933bb7253eb20ee47d157a072f5e30a8bc24754066967ba41b8301a334dd310b88d55e84a"
		"7432520bcc02483881d158800";
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

	EXPECT_TRUE(arraysEqual);
	delete[] expectedByteArray;
}

TEST(AES_Functions, SubByte) {
	unsigned char state[16] = {0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a};

	testFunctions.testSubByte(state);

	const unsigned char expected[16] = {0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	EXPECT_TRUE(arraysEqaul);
}

TEST(AES_Functions, shiftRows) {
	unsigned char state[16] = {0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe};

	testFunctions.testShiftRows(state);

	const unsigned char expected[16] = {0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	EXPECT_TRUE(arraysEqaul);
}

TEST(AES_Functions, mixColumns) {
	unsigned char state[16] = {0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad};

	testFunctions.testMixColumns(state);

	const unsigned char expected[16] = {0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	EXPECT_TRUE(arraysEqaul);
}

TEST(AES_Functions, addRoundKey) {
	unsigned char state[16] = {0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4};
	const unsigned char key[16] = {0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a};

	testFunctions.testAddRoundKey(state, key);

	const unsigned char expected[16] = {0x21, 0x97, 0xc7, 0xde, 0x67, 0xa9, 0xb1, 0x0e, 0xa5, 0x20, 0x56, 0xe5, 0xaa, 0x20, 0x6d, 0xfe};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	EXPECT_TRUE(arraysEqaul);
}

TEST(AES_Functions, invSubByte) {
	unsigned char state[16] = {0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69};

	testFunctions.testInvSubByte(state);

	const unsigned char expected[16] = {0x20, 0x53, 0xc7, 0xde, 0x46, 0x5d, 0xc2, 0xe2, 0x82, 0x65, 0x20, 0x14, 0x22, 0x08, 0xac, 0xe4};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	EXPECT_TRUE(arraysEqaul);
}

TEST(AES_Functions, invShiftRows) {
	unsigned char state[16] = {0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa};

	testFunctions.testInvShiftRows(state);

	const unsigned char expected[16] = {0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	EXPECT_TRUE(arraysEqaul);
}

TEST(AES_Functions, invMixColumns) {
	unsigned char state[16] = {0x7f, 0x84, 0x35, 0xeb, 0xef, 0x75, 0x09, 0x08, 0x28, 0xba, 0x07, 0xe8, 0xce, 0xc7, 0x21, 0x89};

	testFunctions.testInvMixColumns(state);

	const unsigned char expected[16] = {0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	EXPECT_TRUE(arraysEqaul);
}