/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_sha1.cpp
 *
 * This file contains the unit tests for the SHA1 (Secure Hashing Algorithm 1) algorithm implementation.
 */

#include "gtest/gtest.h"
#include <string>

#include <gestalt/sha1.h>
#include "sha1/sha1Core.h"
#include "utils.h"

const bool skipLargeHash = true; // This test can take a bit, so set to false if you'd like to test.

// Known Answer Test(KAT) for SHA1 from:
// [1] - https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf
// [2] - https://www.di-mgt.com.au/sha_testvectors.html
TEST(SHA1, hashKatSHA1) {
    // See [1] pg.12 for test vector.
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "a9993e364706816aba3e25717850c26c9cd0d89d";

    std::string shortDigest = hashSHA1(shortKAT);

    EXPECT_EQ(shortDigest, expectedShortKAT);

    // See [1] pg.15 for test vector.
    std::string longKAT = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const std::string expectedLongKAT = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";

    std::string longDigest = hashSHA1(longKAT);

    EXPECT_EQ(longDigest, expectedLongKAT);

    // See [2] test vector 4.
    std::string longLongKAT = 
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const std::string expectedLongLongKAT = "a49b2446a02c645bf419f995b67091253a04a259";

    std::string longLongDigest = hashSHA1(longLongKAT);

    EXPECT_EQ(longLongDigest, expectedLongLongKAT);

    // See [2] test vector 2.
    std::string emptyStringKAT = "";
    const std::string expectedEmptyStringKAT = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    std::string emptyStringDigest = hashSHA1(emptyStringKAT);

    EXPECT_EQ(emptyStringDigest, expectedEmptyStringKAT);
}

// Large Known Answer Test(KAT) for SHA1 from:
// [1] - https://www.di-mgt.com.au/sha_testvectors.html
TEST(SHA1, hashLargeKatSHA1) {
    if(skipLargeHash) GTEST_SKIP();
    // See [2] test vector 5.
    std::string largeSeed = "a"; // repeated 1,000,000 times.
    std::string largeKAT = "";
    const size_t largeRepetitions = 1000000;
    for (size_t i = 0; i < largeRepetitions; i++) {
        largeKAT += largeSeed;
    }
    const std::string expectedLargeKAT = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";
    std::string largeDigest = hashSHA1(largeKAT);

    EXPECT_EQ(largeDigest, expectedLargeKAT);

    // See [2] test vector 6. 
    // repeated 16,777,216 times
    std::string extremelyLongSeed = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
    std::string extremelyLongKAT = "";
    const size_t extremelyLongRepetitions = 16777216;
    for (size_t i = 0; i < extremelyLongRepetitions; i++) {
        extremelyLongKAT += extremelyLongSeed;
    }
    const std::string expectedExtremelyLongKAT = "7789f0c9ef7bfc40d93311143dfbe69e2017f592";
    std::string expectedExtremelyLongDigest = hashSHA1(extremelyLongKAT);

    EXPECT_EQ(expectedExtremelyLongDigest, expectedExtremelyLongKAT);
}