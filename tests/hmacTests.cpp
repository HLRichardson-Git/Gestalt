/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * sha2Tests.cpp
 *
 * This file contains the unit tests for the SHA2 (Secure Hashing Algorithm 2) algorithm implementation.
 */

#include "gtest/gtest.h"
#include <string>

#include <gestalt/hmac_sha2.h>
#include <gestalt/sha2.h>

TEST(testHMAC, SHA256) {
    std::string key = "key";
    std::string data = "Hi There";
    const std::string expected = "e75865ac3fe73a8074997001fcdf339dbb878200ace6efa70f0ee1b2df3a3cf6";

    std::string computed = hmac_sha256(key, data);

    EXPECT_EQ(computed, expected);
}
