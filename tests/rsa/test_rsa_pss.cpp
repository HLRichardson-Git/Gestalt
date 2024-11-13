/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_pss.cpp
 *
 * This file contains unit tests for the RSA Probabilistic Signature Scheme (PSS), covering padding encoding and 
 * verification, as well as the signing and verification of messages using RSA keys. Tests ensure correct handling of 
 * PSS padding and error conditions.
 * 
 */

#include "gtest/gtest.h"

#include <gestalt/rsa.h>
#include "utils.h"
#include "rsa/padding_schemes/rsa_padding.h"
#include "rsa/padding_schemes/pss/pss.h"
#include "vectors/vectors_rsa_pss.h"

TEST(RSA_PSS, encode) {
    std::string result = encodePSS_Padding(hexToBytes(inputMsg), parameters, 128);
    EXPECT_EQ(convertToHex(result), expectedEncodedMessage);
}

TEST(RSA_PSS, verify) {
    bool result = verifyPSS_Padding(hexToBytes(expectedEncodedMessage), hexToBytes(inputMsg), parameters, 128);
    EXPECT_TRUE(result);
}

TEST_P(RSA_PSS_Test, sign) {
    const RSA_PSS_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    RSA rsa(test.keySecurityStrength, test.privateKey, test.publicKey);
    std::string computedSignature = rsa.signMessage(hexToBytes(test.pt), test.parameters);

    EXPECT_TRUE(computedSignature == test.ct);
}

TEST_P(RSA_PSS_Test, verify) {
    const RSA_PSS_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    RSA rsa(test.keySecurityStrength, test.privateKey, test.publicKey);
    std::string computedSignature = rsa.signMessage(hexToBytes(test.pt), test.parameters);
    bool result = rsa.verifySignature(hexToBytes(test.pt), computedSignature, test.publicKey, test.parameters);

    EXPECT_TRUE(result);
}

TEST(RSA_PSS, EncodeEmLenTooShort) {
    EXPECT_THROW({
        try {
            encodePSS_Padding("Test message", parameters, 32);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("Error PSS Encode: emLen is too short.", e.what());
            throw;
        }
    }, std::invalid_argument);
}

TEST(RSA_PSS, EndsWithIncorrectByte) {
    EXPECT_THROW({
        try {
            verifyPSS_Padding("abcd...", "Test message", parameters, 128);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("Error: Given PSS encoded message does not end with 0xbc", e.what());
            throw;
        }
    }, std::invalid_argument);
}

TEST(RSA_PSS, EmLenTooShort) {
    EXPECT_THROW({
        try {
            verifyPSS_Padding(hexToBytes("1234bc"), "Another test message", parameters, 128);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("Error PSS Verification: emLen is too short.", e.what());
            throw;
        }
    }, std::invalid_argument);
}

TEST(RSA_PSS, NonZeroLeftmostDbOctets) {
    std::string EM = hexToBytes(
        "12ab6707d2fb5368109d5f2860888afe19ef019f89bcebdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc6707d2fb5368109d5f2860"
        "888afe19ef019f89bcebdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc6707d2fb5368109d5f2860888afe19ef019f89bcebdf1a89"
        "6f9d8bc816d97cd7a2c43bad546fbe8cfebc");

    EXPECT_THROW({
        try {
            verifyPSS_Padding(EM, "Padding check message", parameters, 128);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("Inconsistent: Leftmost octets of DB are not zero.", e.what());
            throw;
        }
    }, std::invalid_argument);
}

TEST(RSA_PSS, Missing0x01AtSpecifiedPosition) {
    std::string EM = hexToBytes(
        "66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd8"
        "5b6d3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc8748c7cb641d2d26e036d3b682cf2d40cfe556e63df1a896f"
        "9d8bc816d97cd7a2c43bad546fbe8cfebc");

    EXPECT_THROW({
        try {
            verifyPSS_Padding(EM, "0x01 position check", parameters, 128);
        } catch (const std::invalid_argument& e) {
            EXPECT_STREQ("Inconsistent: The specified position in DB does not contain 0x01.", e.what());
            throw;
        }
    }, std::invalid_argument);
}