/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
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

    std::string privateKey = "0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464";

    ecdsa.setKeyPair(privateKey);
    KeyPair resultKeyPair = ecdsa.getKeyPair();

    Point publicKey("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE", 
                    "0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD");
    KeyPair expected("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464", publicKey);

    EXPECT_TRUE(mpz_cmp(resultKeyPair.privateKey, expected.privateKey) == 0);
    EXPECT_TRUE(mpz_cmp(resultKeyPair.publicKey.x, expected.publicKey.x) == 0);
    EXPECT_TRUE(mpz_cmp(resultKeyPair.publicKey.y, expected.publicKey.y) == 0);
}

class ECDSA_Test : public ::testing::Test {
private:
    ECDSA ecdsa;
protected:
    void prepareMessage(const std::string& messageHash, mpz_t& result) { 
        ecdsa.prepareMessage(messageHash, result);
    };
    bool isInvalidSignature(Signature S) { return ecdsa.isInvalidSignature(S); };
    void setKeyPair(const std::string& givenKey) { ecdsa.setKeyPair(givenKey); };
    Signature generateSignature(const mpz_t& e, mpz_t& k) { return ecdsa.generateSignature(e, k); };
};

TEST_F(ECDSA_Test, PrepareMessage) {
    BigInt result;
    BigInt expected;

    std::string smallerThanBitSize = "0xFFF";
    expected = "0xFFF";
    prepareMessage(smallerThanBitSize, result.n);
    EXPECT_TRUE(mpz_cmp(result.n, expected.n) == 0);

    std::string sameBitSize = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    expected = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    prepareMessage(sameBitSize, result.n);
    EXPECT_TRUE(mpz_cmp(result.n, expected.n) == 0);

    std::string largerThanBitSize = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    expected = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    prepareMessage(largerThanBitSize, result.n);
    EXPECT_TRUE(mpz_cmp(result.n, expected.n) == 0);
}

TEST_F(ECDSA_Test, IsValidSignature)  {
    Signature validSig("0xF3AC8061B514795B8843E3D6629527ED2AFD6B1F6A555A7ACABB5E6F79C8C2AC", 
                       "0x8BF77819CA05A6B2786C76262BF7371CEF97B218E96F175A3CCDDA2ACC058903");
    Signature invalidSig;
    
    EXPECT_FALSE(isInvalidSignature(validSig));
    EXPECT_TRUE(isInvalidSignature(invalidSig));
}

TEST_F(ECDSA_Test, GenerateSignature)  {
    std::string digest = "4c24c2225c70900f85f97d6ff7936f1dca59e8283f1a1a8872c981b98a0ee53a";
    BigInt e;
    prepareMessage(digest, e.n);
    setKeyPair("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464");
    BigInt k = "0x94A1BBB14B906A61A280F245F9E93C7F3B4A6247824F5D33B9670787642A68DE";

    Signature signature = generateSignature(e.n, k.n);

    Signature expected("0x69979C16867D369D95E8852B4C68B323A66A7AAE0A3C112B2F426726EF93B41D",
                       "0x5D9416379D19A392740CF6EE448161D630E04CD968EC74DB3EA4C6CE67CC48F7");

    EXPECT_TRUE(mpz_cmp(signature.r, expected.r) == 0);
    EXPECT_TRUE(mpz_cmp(signature.s, expected.s) == 0);
}