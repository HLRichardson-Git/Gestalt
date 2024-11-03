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
    std::string keyToString(const Point& point) const { return ecdh.keyToString(point); };
};

TEST_F(ECDH_Test, keyToString) {
    Point P("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE", 
            "0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD");
    
    std::string result = keyToString(P);

    std::string expected = "cec028ee08d09e02672a68310814354f9eabfff0de6dacc1cd3a774496076ae";

    EXPECT_EQ(result, expected);
}