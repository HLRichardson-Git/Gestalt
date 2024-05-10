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

TEST(TestECDSAkeyGen, keyGen)
{
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

TEST(TestECDSAsignature, sigGen)
{
    ECDSA ecdsa("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464");

    BigInt k = "0x94A1BBB14B906A61A280F245F9E93C7F3B4A6247824F5D33B9670787642A68DE";

    std::string digest = "4c24c2225c70900f85f97d6ff7936f1dca59e8283f1a1a8872c981b98a0ee53a";

    Signature signature = ecdsa.signMessage(digest, k);

    Signature expected("0x69979C16867D369D95E8852B4C68B323A66A7AAE0A3C112B2F426726EF93B41D", 
                       "0x5D9416379D19A392740CF6EE448161D630E04CD968EC74DB3EA4C6CE67CC48F7");

    EXPECT_TRUE(mpz_cmp(signature.r, expected.r) == 0);
    EXPECT_TRUE(mpz_cmp(signature.s, expected.s) == 0);
}

TEST(TestECDSAsignature, sigVer)
{
    ECDSA ecdsa("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464");

    std::string digest = "4c24c2225c70900f85f97d6ff7936f1dca59e8283f1a1a8872c981b98a0ee53a";

    Signature signature("0x69979C16867D369D95E8852B4C68B323A66A7AAE0A3C112B2F426726EF93B41D", 
                        "0x5D9416379D19A392740CF6EE448161D630E04CD968EC74DB3EA4C6CE67CC48F7");

    bool verify = ecdsa.verifySignature(digest, signature);

    EXPECT_TRUE(verify);
}

TEST(TestECDSAsignature, PWCT) 
{
    ECDSA ecdsa(StandardCurve::P256, "0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464");

    BigInt k = "0x94A1BBB14B906A61A280F245F9E93C7F3B4A6247824F5D33B9670787642A68DE";

    std::string digest = "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56";

    Signature signature = ecdsa.signMessage(digest, k);

    Signature expected("0xF3AC8061B514795B8843E3D6629527ED2AFD6B1F6A555A7ACABB5E6F79C8C2AC", 
                       "0x8BF77819CA05A6B2786C76262BF7371CEF97B218E96F175A3CCDDA2ACC058903");

    EXPECT_TRUE(mpz_cmp(signature.r, expected.r) == 0);
    EXPECT_TRUE(mpz_cmp(signature.s, expected.s) == 0);

    bool verify = ecdsa.verifySignature(digest, signature);

    EXPECT_TRUE(verify);
}

TEST(TestECDSAsignature, inducedFailureVerification)
{
    ECDSA ecdsa;

    std::string digest = "1AC5";

    Signature signature = ecdsa.signMessage(digest);

    digest= "1AC6";
    bool verify = ecdsa.verifySignature(digest, signature);

    EXPECT_TRUE(!verify);
}