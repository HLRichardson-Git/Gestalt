/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_padding.cpp
 *
 */

#include "gtest/gtest.h"
#include <iostream> // for debugging

//#include <gestalt/rsa.h>
#include "utils.h"
#include "rsa/padding_schemes/rsa_padding.h"
#include "rsa/padding_schemes/pss/pss.h"
#include "vectors/vectors_rsa_pss.h"

TEST(RSA_PSS, encode) {
    std::string input = "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc";
    PSSParams parameters = { RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, MGF1, 20, "e3b5d5d002c1bce50c2b65ef88a188d83bce7e61"};
    std::string result = encodePSS_Padding(hexToBytes(input), parameters, 128);
    std::string expectedResult = "66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37ea4a75e24bdbfd5c1da0de7cecdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc";
    EXPECT_EQ(convertToHex(result), expectedResult);
}

TEST(RSA_PSS, verify) {
    std::string encodedMessage = "66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37ea4a75e24bdbfd5c1da0de7cecdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc";
    std::string input = "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc";
    PSSParams parameters = { RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, MGF1, 20, "e3b5d5d002c1bce50c2b65ef88a188d83bce7e61"};
    bool result = verifyPSS_Padding(hexToBytes(encodedMessage), hexToBytes(input), parameters, 128);
    EXPECT_TRUE(result);
}

TEST_P(RSA_PSS_Test, sign) {
    const RSA_PSS_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    RSA rsa(test.keySecurityStrength, test.privateKey, test.publicKey);
    std::string computedSignature = rsa.signMessage(hexToBytes(test.pt), test.parameters);
    std::cout << "Signature = " << computedSignature << std::endl;

    EXPECT_TRUE(computedSignature == test.ct);
}

TEST_P(RSA_PSS_Test, verify) {
    const RSA_PSS_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    RSA rsa(test.keySecurityStrength, test.privateKey, test.publicKey);
    std::string computedSignature = rsa.signMessage(hexToBytes(test.pt), test.parameters);
    bool result = rsa.verifySignature(hexToBytes(test.pt), computedSignature, test.publicKey, test.parameters);
    //std::cout << "Signature = " << computedSignature << std::endl;

    EXPECT_TRUE(result);
}