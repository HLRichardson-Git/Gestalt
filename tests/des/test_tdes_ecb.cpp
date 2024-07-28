/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_tdes_ecb.cpp
 *
 * This file contains the unit tests for the TDES ECB (Data Encryption Standard) algorithm implementation.
 */

#include "gtest/gtest.h"

#include <gestalt/des.h>
#include "vectors/vectors_des.h"

TEST(TDES_ECB, encrypt) {
    std::string ciphertext = encrypt3DESECB(plaintext, key, key2, key3);
    std::string expected = "8b3a49695d593b3633f5d3a48c4de370";
    EXPECT_EQ(ciphertext, expected);
}

TEST(TDES_ECB, decrypt) {
    std::string ciphertext = "8b3a49695d593b3633f5d3a48c4de370";
    std::string decryptedPlaintect = decrypt3DESECB(ciphertext, key, key2, key3);
    EXPECT_EQ(decryptedPlaintect, plaintext);
}

TEST(TDES_ECB, multiBlock) {
	std::string ciphertext = encrypt3DESECB(multiBlockPT, key, key2, key3);
	std::string expected = 
        "4c730a6b6936f51cbed96f7930f4fc897074d5a6e4112e51f13a47639667890533800ac69dd821ef35ce239a6a04483741b3fc3fe252b"
        "9d18705b9c8c4457d3a617e09d07473a33be5f7ab899427be78bdfc1dc0fc9780e4e5e7cb3b33bbd8edccbf7ef518c9f22581d662c385"
        "6bb63585d6d6ebc5525d391bbfb91be2041edaf9d8bb96a628842b9a5f4c90b0261e7730ac33988bbebe967fe3ff2b02db667821498c1"
        "46fc5d4ee39a73b1e3a4d340c43638bb0626664fc3a82bd621370dafc20b32ce84e2ca33b4120f06926cfb35a5738d02181cd5ce019aa"
        "be345d2fd7b756ccd38103a2564247f20ab8e54e8d8c0ccc3a1891fe2c90791123a1de0f1326e0e3d0a9ddc229092212f4f736e24010";
	EXPECT_EQ(ciphertext, expected); 

	std::string descryptedPlaintext = decrypt3DESECB(ciphertext, key, key2, key3);
	EXPECT_EQ(descryptedPlaintext, multiBlockPT); 
}

