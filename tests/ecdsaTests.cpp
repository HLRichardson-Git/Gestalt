/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsaTests.cpp
 */

#include <gestalt/ecdsa.h>

#include "gtest/gtest.h"
#include <string>

TEST(TestECDSAsignature, testSignautre)
{
    ECDSA sign;
    ECDSA_KeyPair keyPair = sign.generateKeyPair();

    std::string message = "Hello, ECDSA!";
    Signature signature = sign.signMessage(message, keyPair);

    bool verify = sign.verifySignature(message, signature, keyPair.publicKey);

    EXPECT_EQ(verify, 1);
}