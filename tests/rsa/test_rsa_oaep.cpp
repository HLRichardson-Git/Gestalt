/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_oaep.cpp
 *
 * This file contains unit tests for the RSA Optimal Asymmetric Encryption Padding (OAEP) scheme, including both the 
 * application and removal of OAEP padding. Tests ensure correct handling of padding, error conditions, and OAEP 
 * encryption/decryption functionality.
 *
 */

#include "gtest/gtest.h"
#include <iostream>

#include <gestalt/rsa.h>
#include "rsa/padding_schemes/oaep/oaep.h"
#include "vectors/vectors_rsa_oaep.h"
#include "utils.h"

TEST(RSA_OAEP, applyOAEP) {
    std::string input = "Hello, Gestalt!";
    std::string output = applyOAEP_Padding(input, 
                                           {HashAlgorithm::SHA1, MGF1, "", "aafd12f659cae63489b479e5076ddec2f06cb58f"}, 
                                           80);
    std::string expectedOutput = 
        "00db9178b344652251240b0ee59f8b33a8d882089fdcd87d5c68f1eea8f55267c31b2e8bb4251f84d7e0b2c04626f5aff93edcfb25c9c2"
        "b3ff8ae10e839a2ddb4d949b2398180494e6d2b2424ac6a6bb";
    EXPECT_TRUE(convertToHex(output) == expectedOutput);
}

TEST(RSA_OAEP, removeOAEP) {
    std::string input = 
        "00db9178b344652251240b0ee59f8b33a8d882089fdcd87d5c68f1eea8f55267c31b2e8bb4251f84d7e0b2c04626f5aff93edcfb25c9c2"
        "b3ff8ae10e839a2ddb4d949b2398180494e6d2b2424ac6a6bb";
    std::string output = removeOAEP_Padding(hexToBytes(input), {HashAlgorithm::SHA1, MGF1, ""}, 80);
    EXPECT_EQ(output, "Hello, Gestalt!");
}

TEST(RSA_OAEP, messageToEncodeTooLong) {
    EXPECT_THROW({
        try {
            std::string input = 
                "0094bb1acb6d6afeb3ea24ebf89dbe86e57bc25180dcd87d5c68f1eea8f55267c31b2e8bb4251f84d7e0b2c04626f5aff93edc"
                "fb25c9c2b3ff8ae10e839a2ddb4cdcfe4ff47728b4a1b7c1362baad29ab48d2869d5024121435811591be392f982fb3e87d09";
            std::string output = applyOAEP_Padding(hexToBytes(input), {HashAlgorithm::SHA1, MGF1, ""}, 80);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("Message too long for RSA modulus", e.what());
            throw;
        }
    }, std::invalid_argument);
}

TEST(RSA_OAEP, messageToDecodeDoesntStartWith0) {
    EXPECT_THROW({
        try {
            std::string input = "94bb1acb6d6afeb3ea24ebf89dbe86e57bc25180dcd87d5c68f1eea8f55267c31b2e8bb4251f";
            std::string output = removeOAEP_Padding(hexToBytes(input), {HashAlgorithm::SHA1, MGF1, ""}, 80);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("Given OAEP message does not begin with 0x00", e.what());
            throw;
        }
    }, std::invalid_argument);
}

TEST(RSA_OAEP, messageDecodeHasWrongLabel) {
    EXPECT_THROW({
        try {
            std::string input = 
                "00db9178b344652251240b0ee59f8b33a8d882089fdcd87d5c68f1eea8f55267c31b2e8bb4251f84d7e0b2c04626f5aff93edc"
                "fb25c9c2b3ff8ae10e839a2ddb4d949b2398180494e6d2b2424ac6a6bb";
            std::string output = removeOAEP_Padding(hexToBytes(input), {HashAlgorithm::SHA1, MGF1, "badLabel"}, 80);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("OAEP Decode Error: The encoded lhash and computed lhash are not the same.", e.what());
            throw;
        }
    }, std::invalid_argument);
}

TEST(RSA_OAEP, messageDecodeHasNoPaddingByte) {
    EXPECT_THROW({
        try {
            std::string input = 
                "005c5998793395880ad52a4c8a2610d3671d386cb0dcd87d5c68f1eea8f55267c31b2e8bb4251f84d7e0b2c04626f5aff93edc"
                "fb25c9c2b3ff8ae10e839a2ddbb3949b2398180494e6d2b2424ac6a6bb";
            std::string output = removeOAEP_Padding(hexToBytes(input), {HashAlgorithm::SHA1, MGF1, ""}, 80);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("OAEP Decode Error: Padding 0x01 byte not found.", e.what());
            throw;
        }
    }, std::invalid_argument);
}

TEST(RSA_OAEP, nonZeroByteFoundInPS) {
    EXPECT_THROW({
        try {
            std::string input = 
                "009498dd98806fe44df5dfb98da724db1bf43f360fdcd87d5c68f1eea8f55267c31b2e8bb4251f84d71f4d3fb9d90a5006c123"
                "04da363d4c00751ef17c65d2244d949b2398180494e6d2b2424ac6a6bb";
            std::string output = removeOAEP_Padding(hexToBytes(input), {HashAlgorithm::SHA1, MGF1, ""}, 80);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("OAEP Decode Error: Non-zero byte found in padding (PS).", e.what());
            throw;
        }
    }, std::invalid_argument);
}

TEST_P(RSA_OAEP_Test, encrypt) {
    const RSA_OAEP_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    RSA rsa(test.keySecurityStrength, test.privateKey, test.publicKey);
    std::string computedCiphertext = rsa.encrypt(hexToBytes(test.pt), test.publicKey, test.parameters);

    EXPECT_TRUE(computedCiphertext == test.ct);
}

TEST_P(RSA_OAEP_Test, decrypt) {
    const RSA_OAEP_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    RSA rsa(test.keySecurityStrength, test.privateKey, test.publicKey);
    std::string computedPlaintext = rsa.decrypt(test.ct, test.parameters);

    EXPECT_TRUE(computedPlaintext == test.pt);
}