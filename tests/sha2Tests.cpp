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

TEST(testSHA2Hash, hashKatSHA2) {
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    std::string shortDigest = hashSHA2(shortKAT);

    EXPECT_EQ(shortDigest, expectedShortKAT);
}