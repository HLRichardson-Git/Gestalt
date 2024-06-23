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

#include <gestalt/sha2.h>

#include <string>

TEST(SHA224, shortHash) {
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";

    std::string shortDigest = hashSHA224(shortKAT);

    EXPECT_EQ(shortDigest, expectedShortKAT);
}

TEST(SHA256, shortHash) {
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    std::string shortDigest = hashSHA256(shortKAT);

    EXPECT_EQ(shortDigest, expectedShortKAT);
}

TEST(SHA384, shortHash) {
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";

    std::string shortDigest = hashSHA384(shortKAT);

    EXPECT_EQ(shortDigest, expectedShortKAT);
}

TEST(SHA512, shortHash) {
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    std::string shortDigest = hashSHA512(shortKAT);

    EXPECT_EQ(shortDigest, expectedShortKAT);
}

TEST(SHA512_224, shortHash) {
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa";

    std::string shortDigest = hashSHA512_224(shortKAT);

    EXPECT_EQ(shortDigest, expectedShortKAT);
}

TEST(SHA512_256, shortHash) {
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23";

    std::string shortDigest = hashSHA512_256(shortKAT);

    EXPECT_EQ(shortDigest, expectedShortKAT);
}