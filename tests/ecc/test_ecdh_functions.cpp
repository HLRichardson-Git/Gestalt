/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_ecdh_functions.cpp
 *
 * This file containts the unit tests for the ECDH (Elliptic Curve Diffie Hellman Algorithm) Gestalt implementation. 
 * 
 */

#include "gtest/gtest.h"

#include <gestalt/ecdh.h>

class ECDH_Test : public ::testing::Test {
private:
    ECDH ecdh;
protected:
    void getPublicKey(const Point& givenPublicKey) { ecdh.peerPublicKey = givenPublicKey; };
    Point retrievePublicKey() { return ecdh.peerPublicKey; };
    std::string keyToString(const Point& point) const { return ecdh.keyToString(point); };
};

TEST_F(ECDH_Test, keyToString) {
    Point P("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE", 
            "0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD");
    
    std::string result = keyToString(P);

    std::string expected = "cec028ee08d09e02672a68310814354f9eabfff0de6dacc1cd3a774496076ae";

    EXPECT_EQ(result, expected);
}

TEST_F(ECDH_Test, givePublicKey) {
    ECDH alice("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464");

    Point givenPubKey = alice.givePublicKey();

    Point expected("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE", 
                   "0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD");

    EXPECT_TRUE(mpz_cmp(givenPubKey.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(givenPubKey.y, expected.y) == 0);
}

TEST_F(ECDH_Test, getPublicKey) {
    ECDH bob("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464");

    getPublicKey(bob.givePublicKey());
    Point givenPubKey = retrievePublicKey();

    Point expected("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE", 
                   "0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD");

    EXPECT_TRUE(mpz_cmp(givenPubKey.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(givenPubKey.y, expected.y) == 0);
}