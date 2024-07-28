/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_aes_functions.cpp
 *
 */

#include "gtest/gtest.h"

#include "aes/aesCore.h"
#include "utils.h"

AES_Functions testFunctions;

TEST(AES_Functions, KeyExpansion) {
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
	unsigned char state[16] = {
		0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a
	};

	testFunctions.testSubByte(state);

	const unsigned char expected[16] = {
		0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe
	};

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
	unsigned char state[16] = {
		0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe
	};

	testFunctions.testShiftRows(state);

	const unsigned char expected[16] = {
		0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad
	};

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
	unsigned char state[16] = {
		0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad
	};

	testFunctions.testMixColumns(state);

	const unsigned char expected[16] = {
		0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4
	};

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
	unsigned char state[16] = {
		0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4
	};
	const unsigned char key[16] = {
		0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a
	};

	testFunctions.testAddRoundKey(state, key);

	const unsigned char expected[16] = {
		0x21, 0x97, 0xc7, 0xde, 0x67, 0xa9, 0xb1, 0x0e, 0xa5, 0x20, 0x56, 0xe5, 0xaa, 0x20, 0x6d, 0xfe
	};

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
	unsigned char state[16] = {
		0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69
	};

	testFunctions.testInvSubByte(state);

	const unsigned char expected[16] = {
		0x20, 0x53, 0xc7, 0xde, 0x46, 0x5d, 0xc2, 0xe2, 0x82, 0x65, 0x20, 0x14, 0x22, 0x08, 0xac, 0xe4
	};

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
	unsigned char state[16] = {
		0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa
	};

	testFunctions.testInvShiftRows(state);

	const unsigned char expected[16] = {
		0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69
	};

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
	unsigned char state[16] = {
		0x7f, 0x84, 0x35, 0xeb, 0xef, 0x75, 0x09, 0x08, 0x28, 0xba, 0x07, 0xe8, 0xce, 0xc7, 0x21, 0x89
	};

	testFunctions.testInvMixColumns(state);

	const unsigned char expected[16] = {
		0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa
	};

	bool arraysEqaul = true;
	for (size_t i = 0; i < 16; ++i) {
		if (state[i] != expected[i]) {
			arraysEqaul = false;
			break;
		}
	}

	EXPECT_TRUE(arraysEqaul);
}