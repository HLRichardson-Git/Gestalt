/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_ecdh.cpp
 *
 * This file containts the unit tests for the ECDH (Elliptic Curve Diffie Hellman Algorithm) Gestalt implementation. 
 * 
 */

#include "gtest/gtest.h"

#include <gestalt/ecdh.h>
#include "vectors/vectors_ecdh.h"

TEST_P(ECDHComputeSharedSecret, computeSharedSecret) {
    const ECDHTestVector &test = GetParam();
    SCOPED_TRACE(test.name);

    ECDH alice(test.curve, test.dIUT);
    ECDHPublicKey peerPublicKey(test.QCAVSx, test.QCAVSy);

    std::string computedSharedSecret = alice.computeSharedSecret(peerPublicKey);

    EXPECT_TRUE(computedSharedSecret == test.ZIUT);
}

TEST(ECDHComputeSharedSecret, computeSharedSecretAsPair) {
    ECDH alice(StandardCurve::P256, "0x7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
    ECDH bob  (StandardCurve::P256, "0x38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5");

    std::string aliceSharedSecret = alice.computeSharedSecret(bob.getPublicKey());
    std::string bobSharedSecret = bob.computeSharedSecret(alice.getPublicKey());

    EXPECT_TRUE(aliceSharedSecret == bobSharedSecret);
}