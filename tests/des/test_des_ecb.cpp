/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_des_ecb.cpp
 *
 * This file contains the unit tests for the DES ECB (Data Encryption Standard) algorithm implementation.
 */

#include "gtest/gtest.h"

#include <gestalt/des.h>
#include "vectors/vectors_des.h"

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