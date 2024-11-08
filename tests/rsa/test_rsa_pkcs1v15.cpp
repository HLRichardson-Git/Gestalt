/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_pkcs1v15.cpp
 *
 */

#include "gtest/gtest.h"

#include <gestalt/rsa.h>
#include "utils.h"
#include "rsa/padding_schemes/rsa_padding.h"
#include "rsa/padding_schemes/pkcs1v15/pkcs1v15.h"
#include "vectors/vectors_rsa_pkcs1v15.h"

const std::string inputMsg = 
    "cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0";
const std::string expectedSignature = 
    "6bc3a06656842930a247e30d5864b4d819236ba7c68965862ad7dbc4e24af28e86bb531f03358be5fb74777c6086f850caef893f0d6fcc2d0c91ec013693b4ea00b80cd49aac4ecb5f8911afe539ada4a8f3823d1d13e472d1490547c659c7617f3d24087ddb6f2b72096167fc097cab18e9a458fcb634cdce8ee35894c484d7";

TEST(RSA_PKCS1v15, encodeForSigning) {
    GTEST_SKIP(); // Currently Failing as GMP strips leading zeros of the encoded message with PKCS#1v1.5
    RSA rsa(RSA_SECURITY_STRENGTH::RSA_1024, privateKeyVector, publicKeyVector);
    std::string computedSignature = rsa.signMessage(hexToBytes(inputMsg), HashAlgorithm::SHA1);
    EXPECT_EQ(computedSignature, expectedSignature);
}