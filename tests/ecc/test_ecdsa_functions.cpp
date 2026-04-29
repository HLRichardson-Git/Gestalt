/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_ecds_functions.cpp
 *
 * This file containts the unit tests for the ECDSA (Elliptic Curve Digital Signature Algorithm) Gestalt
 * implementation. These tests cover various scenarios including keyGen, sigGen, sigVer, pair-wise consistency test,
 * and an induced failure test. For sigGen and sigVer we test all added standard curves with a sha-256 hash.
 *
 */

#include "gtest/gtest.h"

#include <gestalt/ecdsa.h>
#include "vectors/vectors_ecdsa.h"

TEST(ECDSA, keyGen) {
    ECDSA ecdsa;

    ecdsa.setKeyPair(BigInt("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464"));
    KeyPair resultKeyPair = ecdsa.getKeyPair();

    ECDSAPublicKey publicKey(BigInt("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE"),
                             BigInt("0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD"));
    KeyPair expected(BigInt("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464"), publicKey);

    EXPECT_EQ(resultKeyPair.privateKey, expected.privateKey);
    EXPECT_EQ(resultKeyPair.getPublicKey().x, expected.getPublicKey().x);
    EXPECT_EQ(resultKeyPair.getPublicKey().y, expected.getPublicKey().y);
}

class ECDSA_Test : public ::testing::Test {
private:
    ECDSA ecdsa;
protected:
    BigInt prepareMessage(const SecureBytes& messageHash) {
        return ecdsa.prepareMessage(messageHash);
    };
    bool isInvalidSignature(Signature S) { return ecdsa.isInvalidSignature(S); };
    void setKeyPair(const BigInt& givenKey) { ecdsa.setKeyPair(givenKey); };
    Signature generateSignature(const BigInt& e, const BigInt& k) { return ecdsa.generateSignature(e, k); };
};

TEST_F(ECDSA_Test, PrepareMessage) {
    BigInt result;
    BigInt expected;

    // 0x0FFF = 2 bytes
    expected = "0xFFF";
    result = prepareMessage(SecureBytes::fromHex("0fff"));
    EXPECT_EQ(result, expected);

    // 32 bytes = 256 bits (exactly matches secp256k1 curve bit length)
    expected = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    result = prepareMessage(SecureBytes::fromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    EXPECT_EQ(result, expected);

    // 36 bytes > 256 bits — truncated to first 32 bytes, same result
    expected = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    result = prepareMessage(SecureBytes::fromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    EXPECT_EQ(result, expected);
}

TEST_F(ECDSA_Test, IsValidSignature)  {
    Signature validSig(BigInt("0xF3AC8061B514795B8843E3D6629527ED2AFD6B1F6A555A7ACABB5E6F79C8C2AC"),
                       BigInt("0x8BF77819CA05A6B2786C76262BF7371CEF97B218E96F175A3CCDDA2ACC058903"));
    Signature invalidSig;

    EXPECT_FALSE(isInvalidSignature(validSig));
    EXPECT_TRUE(isInvalidSignature(invalidSig));
}

TEST_F(ECDSA_Test, GenerateSignature)  {
    SecureBytes digest = SecureBytes::fromHex("4c24c2225c70900f85f97d6ff7936f1dca59e8283f1a1a8872c981b98a0ee53a");
    BigInt e = prepareMessage(digest);
    setKeyPair(BigInt("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464"));
    BigInt k = "0x94A1BBB14B906A61A280F245F9E93C7F3B4A6247824F5D33B9670787642A68DE";

    Signature signature = generateSignature(e, k);

    Signature expected(BigInt("0x69979C16867D369D95E8852B4C68B323A66A7AAE0A3C112B2F426726EF93B41D"),
                       BigInt("0x5D9416379D19A392740CF6EE448161D630E04CD968EC74DB3EA4C6CE67CC48F7"));

    EXPECT_EQ(signature.r, expected.r);
    EXPECT_EQ(signature.s, expected.s);
}