/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_des_cbc.cpp
 *
 * This file contains the unit tests for the DES CBC (Data Encryption Standard) algorithm implementation.
 */

#include "gtest/gtest.h"

#include <gestalt/des.h>
#include "vectors/vectors_des.h"

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