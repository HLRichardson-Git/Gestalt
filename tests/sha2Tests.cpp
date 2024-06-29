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

#include <gestalt/sha2.h>
#include "vectors/sha2TestVectors.h"

TEST_P(SHA224HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);
    EXPECT_EQ(hashSHA224(test.in), test.expected);
}

TEST_P(SHA256HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);
    EXPECT_EQ(hashSHA256(test.in), test.expected);
}

TEST_P(SHA3844HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);
    EXPECT_EQ(hashSHA384(test.in), test.expected);
}

TEST_P(SHA512HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);
    EXPECT_EQ(hashSHA512(test.in), test.expected);
}

TEST_P(SHA512_224HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);
    EXPECT_EQ(hashSHA512_224(test.in), test.expected);
}

TEST_P(SHA512_256HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);
    EXPECT_EQ(hashSHA512_256(test.in), test.expected);
}