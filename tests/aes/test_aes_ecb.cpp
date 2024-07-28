/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_aes_ecb.cpp
 *
 */

#include "gtest/gtest.h"

#include <gestalt/aes.h>
#include "vectors/vectors_aes.h"

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