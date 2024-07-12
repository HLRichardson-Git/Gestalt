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

#include <gestalt/hmac_sha1.h>
#include <gestalt/hmac_sha2.h>

TEST(testHMAC, SHA1) {
    std::string key = "key";
    std::string data = "Hi There";
    const std::string expected = "37dc8976df0a29180c80070b234998f5be3712d7";

    std::string computed = hmac_sha1(key, data);

    EXPECT_EQ(computed, expected);
}

TEST(testHMAC, SHA224) {
    std::string key = "key";
    std::string data = "Hi There";
    const std::string expected = "521219145667863b5428b8ba24c6d5328c09aeff7a3c18209091e73e";

    std::string computed = hmac_sha224(key, data);

    EXPECT_EQ(computed, expected);
}

TEST(testHMAC, SHA256) {
    std::string key = "key";
    std::string data = "Hi There";
    const std::string expected = "e75865ac3fe73a8074997001fcdf339dbb878200ace6efa70f0ee1b2df3a3cf6";

    std::string computed = hmac_sha256(key, data);

    EXPECT_EQ(computed, expected);
}

TEST(testHMAC, SHA384) {
    std::string key = "key";
    std::string data = "Hi There";
    const std::string expected = "fd6a2f3aac06b57f73da24301d5e09bcbfe9bffda3de7d856fbcc36456e7b1758c85c5baa2cdfff99c37f3ad318ba49a";

    std::string computed = hmac_sha384(key, data);

    EXPECT_EQ(computed, expected);
}

TEST(testHMAC, SHA512) {
    std::string key = "key";
    std::string data = "Hi There";
    const std::string expected = "227a38aae5f62292fe155de50a2c85f8e8f94acb797a4e86da8e7cc3c5f4d579429b67a572f53538d4676341d298c150124f3c61f71b98070be30f77fdd5011a";

    std::string computed = hmac_sha512(key, data);

    EXPECT_EQ(computed, expected);
}

TEST(testHMAC, SHA512_224) {
    std::string key = "key";
    std::string data = "Hi There";
    const std::string expected = "1a2a568db639e643b7b74ddc850d1f6c9df8fd917739d22cc31d7d41";

    std::string computed = hmac_sha512_224(key, data);

    EXPECT_EQ(computed, expected);
}

TEST(testHMAC, SHA512_256) {
    std::string key = "key";
    std::string data = "Hi There";
    const std::string expected = "220838cbadd4c1c2d2be991511bbef8a731a36227994c21b828747b0555f34f6";

    std::string computed = hmac_sha512_256(key, data);

    EXPECT_EQ(computed, expected);
}
