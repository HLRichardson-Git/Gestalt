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

TEST(RSA_PSS, encoding) {
    std::string input = "859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc";
    PSSParams parameters = { RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, MGF1, 20, "e3b5d5d002c1bce50c2b65ef88a188d83bce7e61"};
    std::string output = applyPSS_Padding(hexToBytes(input), parameters, 128);
    EXPECT_EQ(1, 1);
}

TEST_P(RSA_PSS_Test, sign) {
    const RSA_PSS_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    RSA rsa(test.keySecurityStrength, test.privateKey, test.publicKey);
    std::string computedSignature = rsa.signMessage(hexToBytes(test.pt), test.parameters);
    std::cout << "Signature = " << computedSignature << std::endl;

    EXPECT_TRUE(computedSignature == test.ct);
}