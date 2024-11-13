/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_raw.cpp
 *
 * This file contains unit tests for raw RSA encryption, decryption, and signature operations. The tests verify the 
 * correct functioning of RSA encryption and decryption without padding, as well as signature generation and 
 * verification, including failure scenarios for tampered signatures.
 * 
 */

#include "gtest/gtest.h"
#include <iostream>

#include <gestalt/rsa.h>
#include "vectors/vectors_rsa.h"

TEST(RSA_Raw, encrypt) {
    std::string computedCiphertext = rsa.encrypt(pt, publicKeyVector);
    EXPECT_TRUE(computedCiphertext == ct);
}

TEST(RSA_Raw, decrypt) {
    std::string computedPlaintext = rsa.decrypt(ct);
    EXPECT_TRUE(computedPlaintext == pt);
}

TEST(RSA_Raw, signatureGeneration) {
    std::string computedSignature = rsa.signMessage(messageToSign);
    EXPECT_TRUE(computedSignature == expectedSignature);
}

TEST(RSA_Raw, signatureVerification) {
    bool signatureResult = rsa.verifySignature(messageToSign, expectedSignature, publicKeyVector);
    EXPECT_TRUE(signatureResult);
}

TEST(RSA_Raw, inducedFailureSignatureVerification) {
    bool signatureResult = rsa.verifySignature(messageToSign, expectedSignature + "1", publicKeyVector);
    EXPECT_FALSE(signatureResult);
}