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

const bool skipLargeHash = true; // This test can take a bit, so set to false if you'd like to test.

// SHA2 Tets Vectors from:
// [1] - https://www.di-mgt.com.au/sha_testvectors.html
TEST_P(SHA224HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    if (skipLargeHash && test.repetitions != 1)
        GTEST_SKIP();

    std::string in = "";
    for (size_t i = 0; i < test.repetitions; i++) 
        in += test.in;

    EXPECT_EQ(hashSHA224(in), test.expected);
}

TEST_P(SHA256HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    if (skipLargeHash && test.repetitions != 1)
        GTEST_SKIP();

    std::string in = "";
    for (size_t i = 0; i < test.repetitions; i++) 
        in += test.in;

    EXPECT_EQ(hashSHA256(in), test.expected);
}

TEST_P(SHA3844HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    if (skipLargeHash && test.repetitions != 1)
        GTEST_SKIP();

    std::string in = "";
    for (size_t i = 0; i < test.repetitions; i++) 
        in += test.in;

    EXPECT_EQ(hashSHA384(in), test.expected);
}

TEST_P(SHA512HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    if (skipLargeHash && test.repetitions != 1)
        GTEST_SKIP();

    std::string in = "";
    for (size_t i = 0; i < test.repetitions; i++) 
        in += test.in;

    EXPECT_EQ(hashSHA512(in), test.expected);
}

TEST_P(SHA512_224HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    if (skipLargeHash && test.repetitions != 1)
        GTEST_SKIP();

    std::string in = "";
    for (size_t i = 0; i < test.repetitions; i++) 
        in += test.in;

    EXPECT_EQ(hashSHA512_224(in), test.expected);
}

TEST_P(SHA512_256HashTest, KAT) {
    const SHA2TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    if (skipLargeHash && test.repetitions != 1)
        GTEST_SKIP();

    std::string in = "";
    for (size_t i = 0; i < test.repetitions; i++) 
        in += test.in;

    EXPECT_EQ(hashSHA512_256(in), test.expected);
}