/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
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
#include "vectors/vectors_sha2.h"

const bool skipLargeHash = true; // This test can take a bit, so set to false if you'd like to test.

SecureBytes prepareInput(const std::string& in, size_t repetitions) {
    SecureBytes out;
    SecureBytes seed = SecureBytes::fromAscii(in);
    for (size_t i = 0; i < repetitions; i++) {
        out.append(seed);
    }
    return out;
}

// SHA2 Tets Vectors from:
// [1] - https://www.di-mgt.com.au/sha_testvectors.html
TEST_P(SHA2_224HashTest, KAT) {
    const SHA2TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);

    if (skipLargeHash && vector.repetitions != 1)
        GTEST_SKIP();

    EXPECT_EQ(hashSHA224(prepareInput(vector.in, vector.repetitions)).toHex(), vector.expected);
}

TEST_P(SHA2_256HashTest, KAT) {
    const SHA2TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);

    if (skipLargeHash && vector.repetitions != 1)
        GTEST_SKIP();

    EXPECT_EQ(hashSHA256(prepareInput(vector.in, vector.repetitions)).toHex(), vector.expected);
}

TEST_P(SHA2_3844HashTest, KAT) {
    const SHA2TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);

    if (skipLargeHash && vector.repetitions != 1)
        GTEST_SKIP();

    EXPECT_EQ(hashSHA384(prepareInput(vector.in, vector.repetitions)).toHex(), vector.expected);
}

TEST_P(SHA2_512HashTest, KAT) {
    const SHA2TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);

    if (skipLargeHash && vector.repetitions != 1)
        GTEST_SKIP();

    EXPECT_EQ(hashSHA512(prepareInput(vector.in, vector.repetitions)).toHex(), vector.expected);
}

TEST_P(SHA2_512_224HashTest, KAT) {
    const SHA2TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);

    if (skipLargeHash && vector.repetitions != 1)
        GTEST_SKIP();

    EXPECT_EQ(hashSHA512_224(prepareInput(vector.in, vector.repetitions)).toHex(), vector.expected);
}

TEST_P(SHA2_512_256HashTest, KAT) {
    const SHA2TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);

    if (skipLargeHash && vector.repetitions != 1)
        GTEST_SKIP();

    EXPECT_EQ(hashSHA512_256(prepareInput(vector.in, vector.repetitions)).toHex(), vector.expected);
}