/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
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
    SecureBytes computedCiphertext = rsa.encrypt(SecureBytes::fromHex(pt), publicKeyVector);
    EXPECT_TRUE(computedCiphertext == SecureBytes::fromHex(ct));
}

TEST(RSA_Raw, decrypt) {
    SecureBytes computedPlaintext = rsa.decrypt(SecureBytes::fromHex(ct));
    EXPECT_TRUE(computedPlaintext == SecureBytes::fromHex(pt));
}

TEST(RSA_Raw, signatureGeneration) {
    SecureBytes computedSignature = rsa.signMessage(SecureBytes::fromHex(messageToSign));
    EXPECT_TRUE(computedSignature == SecureBytes::fromHex(expectedSignature));
}

TEST(RSA_Raw, signatureVerification) {
    bool signatureResult = rsa.verifySignature(SecureBytes::fromHex(messageToSign), SecureBytes::fromHex(expectedSignature), publicKeyVector);
    EXPECT_TRUE(signatureResult);
}

TEST(RSA_Raw, inducedFailureSignatureVerification) {
    SecureBytes tamperedSig = SecureBytes::fromHex(expectedSignature);
    tamperedSig[0] ^= 0xFF;
    bool signatureResult = rsa.verifySignature(SecureBytes::fromHex(messageToSign), tamperedSig, publicKeyVector);
    EXPECT_FALSE(signatureResult);
}
