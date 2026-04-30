/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_ecdsa.cpp
 *
 * This file containts the unit tests for the ECDSA (Elliptic Curve Digital Signature Algorithm) Gestalt 
 * implementation. These tests cover various scenarios including keyGen, sigGen, sigVer, pair-wise consistency test,
 * and an induced failure test. For sigGen and sigVer we test all added standard curves with a sha-256 hash.
 * 
 */

#include "gtest/gtest.h"

#include <gestalt/ecdsa.h>
#include "vectors/vectors_ecdsa.h"

TEST_P(ECDSASignatureGenTest, sigGen) {
    const ECDSATestVector &test = GetParam();
    SCOPED_TRACE(test.name);

    ECDSA ecdsa(test.curve, BigInt(test.privateKey));

    BigInt k_value = test.k;

    ECDSASignature signature = ecdsa.signMessage(SecureBytes::fromHex(test.msg), k_value);

    ECDSASignature expected(BigInt(test.expected_r), BigInt(test.expected_s));

    EXPECT_EQ(signature.r, expected.r);
    EXPECT_EQ(signature.s, expected.s);
}

TEST_P(ECDSASignatureVerTest, sigVer) {
    const ECDSATestVector &test = GetParam();
    SCOPED_TRACE(test.name);
    
    ECDSA ecdsa(test.curve, BigInt(test.privateKey));

    ECDSASignature signature(BigInt(test.expected_r), BigInt(test.expected_s));

    ECDSAPublicKey peerPublicKey(ecdsa.getPublicKey().getPublicKey(), test.curve);

    bool verify = ecdsa.verifySignature(SecureBytes::fromHex(test.msg), peerPublicKey, signature);

    EXPECT_TRUE(verify);
}

TEST(ECDSA, PWCT)  {
    ECDSA ecdsa(StandardCurve::P256, BigInt("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464"));

    BigInt k = "0x94A1BBB14B906A61A280F245F9E93C7F3B4A6247824F5D33B9670787642A68DE";

    SecureBytes digest = SecureBytes::fromHex("44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56");

    ECDSASignature signature = ecdsa.signMessage(digest, k);

    ECDSASignature expected(BigInt("0xF3AC8061B514795B8843E3D6629527ED2AFD6B1F6A555A7ACABB5E6F79C8C2AC"),
                       BigInt("0x8BF77819CA05A6B2786C76262BF7371CEF97B218E96F175A3CCDDA2ACC058903"));

    EXPECT_EQ(signature.r, expected.r);
    EXPECT_EQ(signature.s, expected.s);

    bool verify = ecdsa.verifySignature(digest, ecdsa.getPublicKey(), signature);

    EXPECT_TRUE(verify);
}

TEST(ECDSA, inducedFailureVerification) {
    ECDSA ecdsa;

    ECDSASignature signature = ecdsa.signMessage(SecureBytes::fromHex("1AC5"));

    bool verify = ecdsa.verifySignature(SecureBytes::fromHex("1AC6"), ecdsa.getPublicKey(), signature);

    EXPECT_TRUE(!verify);
}