/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_tdes_cbc.cpp
 *
 * This file contains the unit tests for the TDES CBC (Data Encryption Standard) algorithm implementation.
 */

#include "gtest/gtest.h"

#include <gestalt/des.h>
#include "vectors/vectors_des.h"

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