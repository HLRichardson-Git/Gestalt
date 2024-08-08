/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_aes_cbc.cpp
 *
 */

#include "gtest/gtest.h"

#include <gestalt/aes.h>
#include "vectors/vectors_aes.h"

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