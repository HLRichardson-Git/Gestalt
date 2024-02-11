/*
 * aesTests.cpp
 *
 * This file contains the unit tests for the AES (Advanced Encryption Standard) algorithm implementation.
 * The tests cover various scenarios including roundtrip encryption and decryption with different key sizes,
 * key expansion, AES block operations (SubBytes, ShiftRows, MixColumns), and AES inverse block operations.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-02-11
 */

#include "gtest/gtest.h"
#include <iostream>
#include <cstring>
#include <chrono>

#include "../src/aes/aes.h"
#include "../tools/utils.h"
#include "../src/lib.h"

// Unit tests for AES ECB mode with 128-bit key
TEST(TestAesECB, RoundtripWith128BitKey) {
	std::string inputData = generateRandomData(1); // Generate random input data (1MB)
	Message message(inputData); // Create message object with input data

	std::string key = "10a58869d74be5a374cf867cfb473859";

	// Encrypt and decrypt the message using AES ECB mode with 128-bit key
	message.aes_encrypt_ecb(key);
	message.aes_decrypt_ecb(key);

	// Check if decrypted message matches original input data
	EXPECT_EQ(message.msg, inputData); 
}

// Unit tests for AES ECB mode with 192-bit key
TEST(TestAesECB, RoundtripWith192BitKey) {
	std::string inputData = generateRandomData(1); // Generate random input data (1MB)
	Message message(inputData); // Create message object with input data

	std::string key = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";

	// Encrypt and decrypt the message using AES ECB mode with 192-bit key
	message.aes_encrypt_ecb(key);
	message.aes_decrypt_ecb(key);

	// Check if decrypted message matches original input data
	EXPECT_EQ(message.msg, inputData);
}

// Unit tests for AES ECB mode with 256-bit key
TEST(TestAesECB, RoundtripWith256BitKey) {
	std::string inputData = generateRandomData(1); // Generate random input data (1MB)
	Message message(inputData); // Create message object with input data

	std::string key = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";

	// Encrypt and decrypt the message using AES ECB mode with 256-bit key
	message.aes_encrypt_ecb(key);
	message.aes_decrypt_ecb(key);

	// Check if decrypted message matches original input data
	EXPECT_EQ(message.msg, inputData);
}

// Unit tests for AES CBC mode with 128-bit key
TEST(TestAesCBC, RoundtripWith128BitKey) {
	std::string inputData = generateRandomData(1); // Generate random input data (1MB)
	std::string nonce = generateRandomHexData(16); // Generate random 16-byte (128-bit) nonce
	Message message(inputData, AES_CBC, nonce); // Create message object with input data

	std::string key = "10a58869d74be5a374cf867cfb473850";

	// Encrypt and decrypt the message using AES CBC mode with 128-bit key
	message.aes_encrypt_cbc(key);
	message.aes_decrypt_cbc(key);

	// Check if decrypted message matches original input data
	EXPECT_EQ(message.msg, inputData);
}

// Unit tests for AES CBC mode with 192-bit key
TEST(TestAesCBC, RoundtripWith192BitKey) {
	std::string inputData = generateRandomData(1); // Generate random input data (1MB)
	std::string nonce = generateRandomHexData(16); // Generate random 16-byte (128-bit) nonce
	Message message(inputData, AES_CBC, nonce); // Create message object with input data

	std::string key = "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd";

	// Encrypt and decrypt the message using AES CBC mode with 192-bit key
	message.aes_encrypt_cbc(key);
	message.aes_decrypt_cbc(key);

	// Check if decrypted message matches original input data
	EXPECT_EQ(message.msg, inputData);
}

// Unit tests for AES CBC mode with 256-bit key
TEST(TestAesCBC, RoundtripWith256BitKey) {
	std::string inputData = generateRandomData(1); // Generate random input data (1MB)
	std::string nonce = generateRandomHexData(16); // Generate random 16-byte (128-bit) nonce
	Message message(inputData, AES_CBC, nonce); // Create message object with input data

	std::string key = "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558";

	// Encrypt and decrypt the message using AES CBC mode with 256-bit key
	message.aes_encrypt_cbc(key);
	message.aes_decrypt_cbc(key);

	// Check if decrypted message matches original input data
	EXPECT_EQ(message.msg, inputData);
}

// Unit tests for AES ECB mode Known Answer Test with 128-bit key
TEST(TestAesKAT, KATWith128BitKey) {
	// Use known plaintext
	std::string inputData = "Everything that lives is designed to end. We are perpetually trapped in a never-ending spiral of life and death. Is this a curse? Or some kind of punishment? I often think about the god who blessed us with this cryptic puzzle...and wonder if we'll ever get the chance to kill him.";
	Message message(inputData); // Create message object with input data

	std::string key = "10a58869d74be5a374cf867cfb473859";

	// Encrypt and decrypt the message using AES ECB mode with 128-bit key
	message.aes_encrypt_ecb(key);
	std::string expectedStr = "948084c7c03487d76e58b1d9747103578c93790463a680009fc74fcbf59e63a39a044953a4a6e11f99257ab4068ccea583a60daa41fe9b9dfa20f5352ce4669c914c41110dbac9e0d0bcf92981fb494e87ce717f2ded9ba4b3fea9be4598e324ba93f50414d0cd9f9131357fccedf8bf0bb64c4bd16a1cda3e9d823d377284bbe53164922969d1d2a7c982b768a131c7223919e377e66fc09a4f7f74899405b49d5f752448595de2f5818fe56b442e5354e517d36ccc44b90f7e5abc8f11b1a593a97f4b8193ee6be5ce850da8d6fca3178c06c39c228591507479750eaf625fd85055c04479824757f7e57e246fb3fc26c3da324c0a30c030dd3848bd705df289a39ebe1cb6e529508c874d2dc2d616f8cfb0ab683d1296ce1d5e22bc0dd048";
	std::string hexCiphertext = convertToHex(message.msg);
	// Check if encrypted message matches expected ciphertext
	EXPECT_EQ(hexCiphertext, expectedStr);

	message.aes_decrypt_ecb(key);
	
	// Check if decrypted message matches original input data
	EXPECT_EQ(inputData, message.msg);
}

// Unit tests for AES key expansion
TEST(TestAesKeyExpansion, KeyExpansion) {
	std::string key = "10a58869d74be5a374cf867cfb473859";

	AES Key(key);
	unsigned char* roundKey = Key.getRoundKey();

	std::string expectedStr = "10a58869d74be5a374cf867cfb473859b1a2436666e9a6c5122620b9e96118e05c0fa2783ae604bd28c02404c1a13ce46ae4cb005002cfbd78c2ebb9b963d75d99ea8756c9e848ebb12aa3520849740fb278f1667b90b98dcaba1adfc2f36ed09fe78143e47738ce2ecd2211ec3e4cc16dcef98d89b9c143a774e3524b4aaf933bb7253eb20ee47d157a072f5e30a8bc24754066967ba41b8301a334dd310b88d55e84a7432520bcc02483881d158800";
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
TEST(TestAesFunctions, SubByte) {
	AES aesObject("00000000000000000000000000000000");

	unsigned char state[16] = {0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a};

	aesObject.subByte(state);

	// Expected output after SubByte transformation
	unsigned char expected[16] = {0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe};

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
TEST(TestAesFunctions, shiftRows) {
	AES aesObject("00000000000000000000000000000000");
	// Prepare input data
	unsigned char state[16] = {0x6a, 0xba, 0x69, 0x6b, 0x6c, 0x85, 0xa6, 0xbf, 0xaf, 0x7a, 0x87, 0xad, 0x57, 0x1b, 0xe2, 0xbe};

	// Call the shiftRows function and test
	aesObject.shiftRows(state);

	unsigned char expected[16] = {0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad};

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
TEST(TestAesFunctions, mixColumns) {
	AES aesObject("00000000000000000000000000000000");
	// Prepare input data
	unsigned char state[16] = {0x6a, 0x85, 0x87, 0xbe, 0x6c, 0x7a, 0xe2, 0x6b, 0xaf, 0x1b, 0x69, 0xbf, 0x57, 0xba, 0xa6, 0xad};

	// Call the mixColumns function and test
	aesObject.mixColumns(state);

	unsigned char expected[16] = {0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4};

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
TEST(TestAesFunctions, addRoundKey) {
	AES aesObject("00000000000000000000000000000000");
	// Prepare input data
	unsigned char state[16] = {0x79, 0x57, 0x23, 0xdb, 0xdf, 0xce, 0x74, 0xfa, 0xbe, 0x9d, 0xbc, 0xfd, 0x70, 0x64, 0x56, 0xa4};
	unsigned char key[16] = {0x58, 0xc0, 0xe4, 0x05, 0xb8, 0x67, 0xc5, 0xf4, 0x1b, 0xbd, 0xea, 0x18, 0xda, 0x44, 0x3b, 0x5a};

	// Call the addRoundKey function and test
	aesObject.addRoundKey(state, key);

	unsigned char expected[16] = {0x21, 0x97, 0xc7, 0xde, 0x67, 0xa9, 0xb1, 0x0e, 0xa5, 0x20, 0x56, 0xe5, 0xaa, 0x20, 0x6d, 0xfe};

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
TEST(TestAesFunctions, invSubByte) {
	AES aesObject("00000000000000000000000000000000");
	// Prepare input data
	unsigned char state[16] = {0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69};

	// Call the invSubByte function and test
	aesObject.invSubByte(state);

	unsigned char expected[16] = {0x20, 0x53, 0xc7, 0xde, 0x46, 0x5d, 0xc2, 0xe2, 0x82, 0x65, 0x20, 0x14, 0x22, 0x08, 0xac, 0xe4};

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
TEST(TestAesFunctions, invShiftRows) {
	AES aesObject("00000000000000000000000000000000");
	// Prepare input data
	unsigned char state[16] = {0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa};

	// Call the invSubByte function and test
	aesObject.invShiftRows(state);

	unsigned char expected[16] = {0xb7, 0xed, 0xc6, 0x1d, 0x5a, 0x4c, 0x25, 0x98, 0x13, 0x4d, 0xb7, 0xfa, 0x93, 0x30, 0x91, 0x69};

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
TEST(TestAesFunctions, invMixColumns) {
	AES aesObject("00000000000000000000000000000000");
	// Prepare input data
	unsigned char state[16] = {0x7f, 0x84, 0x35, 0xeb, 0xef, 0x75, 0x09, 0x08, 0x28, 0xba, 0x07, 0xe8, 0xce, 0xc7, 0x21, 0x89};

	// Call the invSubByte function and test
	aesObject.invMixColumns(state);

	unsigned char expected[16] = {0xb7, 0x4c, 0xb7, 0x69, 0x5a, 0x4d, 0x91, 0x1d, 0x13, 0x30, 0xc6, 0x98, 0x93, 0xed, 0x25, 0xfa};

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