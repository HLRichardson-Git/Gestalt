/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa.cpp
 *
 */

#include "gtest/gtest.h"

#include <gestalt/rsa.h>
#include "vectors/vectors_rsa.h"

TEST(RSA, encrypt) {
    RSA rsa(privateKeyVector, publicKeyVector);
    BigInt computedCiphertext = rsa.encrypt(pt, ENCRYPTION_PADDING_SCHEME::NO_PADDING);
    EXPECT_TRUE("0x" + computedCiphertext.toHexString() == ct) << "Generated key pair was invalid";
}

TEST(RSA, decrypt) {
    RSA rsa(privateKeyVector, publicKeyVector);
    BigInt computedPlaintext = rsa.decrypt(ct, ENCRYPTION_PADDING_SCHEME::NO_PADDING);
    EXPECT_TRUE("0x" + computedPlaintext.toHexString() == pt) << "Generated key pair was invalid";
}