/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_pkcs1v15.cpp
 *
 * This file contains unit tests for the PKCS#1 v1.5 padding scheme used in RSA encryption and signature operations.
 * The tests cover both encoding and decoding of padded messages for encryption and verification of signature integrity,
 * ensuring correct padding behavior and error handling.
 *
 */

#include "gtest/gtest.h"

#include <gestalt/rsa.h>
#include "utils.h"
#include "rsa/padding_schemes/rsa_padding.h"
#include "rsa/padding_schemes/pkcs1v15/pkcs1v15.h"
#include "vectors/vectors_rsa_pkcs1v15.h"

// Known-answer test vectors from PKCS #1 v2.1 test vectors (RSASSA-PKCS1-v1_5, SHA-1)
const std::string inputMsg =
    "cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0";
const std::string expectedSignature =
    "6bc3a06656842930a247e30d5864b4d819236ba7c68965862ad7dbc4e24af28e86bb531f03358be5fb74777c6086f850caef893f0d6fcc2d0c91ec013693b4ea00b80cd49aac4ecb5f8911afe539ada4a8f3823d1d13e472d1490547c659c7617f3d24087ddb6f2b72096167fc097cab18e9a458fcb634cdce8ee35894c484d7";

TEST(RSA_PKCS1v15, KAT_Sign) {
    RSA rsa(RSASecurityStrength::RSA_1024, privateKeyVector, publicKeyVector);
    std::string computedSignature = rsa.signMessage(hexToBytes(inputMsg), PKCS1v15Params(HashAlgorithm::SHA1));
    EXPECT_EQ(computedSignature, expectedSignature);
}

TEST(RSA_PKCS1v15, KAT_Verify) {
    RSA rsa(RSASecurityStrength::RSA_1024, privateKeyVector, publicKeyVector);
    bool valid = rsa.verifySignature(hexToBytes(inputMsg), expectedSignature, publicKeyVector, PKCS1v15Params(HashAlgorithm::SHA1));
    EXPECT_TRUE(valid);
}

TEST(RSA_PKCS1v15, RoundTrip_Sign_Verify) {
    RSA rsa(RSASecurityStrength::RSA_1024, privateKeyVector, publicKeyVector);
    const std::string message = "Hello, PKCS#1 v1.5!";
    std::string sig = rsa.signMessage(message, PKCS1v15Params(HashAlgorithm::SHA256));
    EXPECT_TRUE(rsa.verifySignature(message, sig, publicKeyVector, PKCS1v15Params(HashAlgorithm::SHA256)));
}

TEST(RSA_PKCS1v15, RoundTrip_Encrypt_Decrypt) {
    RSA rsa(RSASecurityStrength::RSA_1024, privateKeyVector, publicKeyVector);
    const std::string plaintext = "Hello, PKCS#1 v1.5 encryption!";
    std::string ciphertext = rsa.encrypt(plaintext, publicKeyVector, PKCS1v15Params());
    std::string recovered = rsa.decrypt(ciphertext, PKCS1v15Params());
    EXPECT_EQ(recovered, plaintext);
}

TEST(RSA_PKCS1v15, VerifySignature_Tampered_Fails) {
    RSA rsa(RSASecurityStrength::RSA_1024, privateKeyVector, publicKeyVector);
    const std::string message = "Hello, PKCS#1 v1.5!";
    std::string sig = rsa.signMessage(message, PKCS1v15Params(HashAlgorithm::SHA256));
    // Flip a byte in the signature
    std::string tampered = sig;
    tampered[0] ^= 0xff;
    EXPECT_FALSE(rsa.verifySignature(message, tampered, publicKeyVector, PKCS1v15Params(HashAlgorithm::SHA256)));
}
