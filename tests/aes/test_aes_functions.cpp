/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_aes_functions.cpp
 *
 */

#include <cstring>

#include "gtest/gtest.h"

#include "aes/aesCore.h"
#include "utils.h"

//AES_Functions testFunctions;
class AES_Functions : public ::testing::Test {
private:
	AES aesObject;
	unsigned char roundKey[AES_BLOCK_SIZE * 15]; // Array to hold round key
public:

	AES_Functions() : aesObject("10a58869d74be5a374cf867cfb473859") {
        aesObject.keyExpansion("10a58869d74be5a374cf867cfb473859", roundKey);
    }
	
	const unsigned char* testKeyExpansion() { return this->roundKey; }
	void testSubByte(unsigned char state[AES_BLOCK_SIZE]) { this->aesObject.subByte(state); }
	void testShiftRows(unsigned char state[AES_BLOCK_SIZE]) { this->aesObject.shiftRows(state); }
	void testMixColumns(unsigned char state[AES_BLOCK_SIZE]) { this->aesObject.mixColumns(state); }
	void testAddRoundKey(unsigned char state[AES_BLOCK_SIZE], const unsigned char* roundKey) { 
		this->aesObject.addRoundKey(state, roundKey); 
	}
	void testInvSubByte(unsigned char state[AES_BLOCK_SIZE]) { this->aesObject.invSubByte(state); }
	void testInvShiftRows(unsigned char state[AES_BLOCK_SIZE]) { this->aesObject.invShiftRows(state); }
	void testInvMixColumns(unsigned char state[AES_BLOCK_SIZE]) { this->aesObject.invMixColumns(state); }
};

TEST_F(AES_Functions, KeyExpansion) {
	const unsigned char* roundKey = testKeyExpansion();

	const std::string expectedStr = 
		"10a58869d74be5a374cf867cfb473859b1a2436666e9a6c5122620b9e96118e05c0fa2783ae604bd28c02404c1a13ce46ae4cb005002c"
		"fbd78c2ebb9b963d75d99ea8756c9e848ebb12aa3520849740fb278f1667b90b98dcaba1adfc2f36ed09fe78143e47738ce2ecd2211ec"
		"3e4cc16dcef98d89b9c143a774e3524b4aaf933bb7253eb20ee47d157a072f5e30a8bc24754066967ba41b8301a334dd310b88d55e84a"
		"7432520bcc02483881d158800";
	size_t arraySize = expectedStr.length() / 2;
    unsigned char* expectedByteArray = new unsigned char[arraySize];
    hexStringToBytes(expectedStr, expectedByteArray);

	EXPECT_EQ(0, std::memcmp(roundKey, expectedByteArray, AES_BLOCK_SIZE));
}

TEST_F(AES_Functions, SubByte) {
	unsigned char state[AES_BLOCK_SIZE] = {
		0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a
	};

	testSubByte(state);

	const unsigned char expected[AES_BLOCK_SIZE] = {
		0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe
	};

	EXPECT_EQ(0, std::memcmp(state, expected, AES_BLOCK_SIZE));
}

TEST_F(AES_Functions, shiftRows) {
	unsigned char state[AES_BLOCK_SIZE] = {
		0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe
	};

	testShiftRows(state);

	const unsigned char expected[AES_BLOCK_SIZE] = {
		0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad
	};

	EXPECT_EQ(0, std::memcmp(state, expected, AES_BLOCK_SIZE));
}

TEST_F(AES_Functions, mixColumns) {
	unsigned char state[AES_BLOCK_SIZE] = {
		0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad
	};

	testMixColumns(state);

	const unsigned char expected[AES_BLOCK_SIZE] = {
		0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4
	};

	EXPECT_EQ(0, std::memcmp(state, expected, AES_BLOCK_SIZE));
}

TEST_F(AES_Functions, addRoundKey) {
	unsigned char state[AES_BLOCK_SIZE] = {
		0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4
	};
	const unsigned char key[AES_BLOCK_SIZE] = {
		0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a
	};

	testAddRoundKey(state, key);

	const unsigned char expected[AES_BLOCK_SIZE] = {
		0x21, 0x97, 0xc7, 0xde, 0x67, 0xa9, 0xb1, 0x0e, 0xa5, 0x20, 0x56, 0xe5, 0xaa, 0x20, 0x6d, 0xfe
	};

	EXPECT_EQ(0, std::memcmp(state, expected, AES_BLOCK_SIZE));
}

TEST_F(AES_Functions, invSubByte) {
	unsigned char state[AES_BLOCK_SIZE] = {
		0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69
	};

	testInvSubByte(state);

	const unsigned char expected[AES_BLOCK_SIZE] = {
		0x20, 0x53, 0xc7, 0xde, 0x46, 0x5d, 0xc2, 0xe2, 0x82, 0x65, 0x20, 0x14, 0x22, 0x08, 0xac, 0xe4
	};

	EXPECT_EQ(0, std::memcmp(state, expected, AES_BLOCK_SIZE));
}

TEST_F(AES_Functions, invShiftRows) {
	unsigned char state[AES_BLOCK_SIZE] = {
		0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa
	};

	testInvShiftRows(state);

	const unsigned char expected[AES_BLOCK_SIZE] = {
		0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69
	};

	EXPECT_EQ(0, std::memcmp(state, expected, AES_BLOCK_SIZE));
}

TEST_F(AES_Functions, invMixColumns) {
	unsigned char state[AES_BLOCK_SIZE] = {
		0x7f, 0x84, 0x35, 0xeb, 0xef, 0x75, 0x09, 0x08, 0x28, 0xba, 0x07, 0xe8, 0xce, 0xc7, 0x21, 0x89
	};

	testInvMixColumns(state);

	const unsigned char expected[AES_BLOCK_SIZE] = {
		0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa
	};

	EXPECT_EQ(0, std::memcmp(state, expected, AES_BLOCK_SIZE));
}