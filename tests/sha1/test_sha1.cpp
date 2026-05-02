/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_sha1.cpp
 *
 * This file contains the unit tests for the SHA1 (Secure Hashing Algorithm 1) algorithm implementation.
 */

#include "gtest/gtest.h"

#include <gestalt/sha1.h>
#include "sha1/sha1Core.h"

const bool skipLargeHash = true; // This test can take a bit, so set to false if you'd like to test.

// Known Answer Test(KAT) for SHA1 from:
// [1] - https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf
// [2] - https://www.di-mgt.com.au/sha_testvectors.html
TEST(SHA1, hashKatSHA1) {
    // See [1] pg.12 for test vector.
    SecureBytes shortDigest = hashSHA1(SecureBytes::fromAscii("abc"));
    EXPECT_EQ(shortDigest, SecureBytes::fromHex("a9993e364706816aba3e25717850c26c9cd0d89d"));

    // See [1] pg.15 for test vector.
    SecureBytes longDigest = hashSHA1(SecureBytes::fromAscii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    EXPECT_EQ(longDigest, SecureBytes::fromHex("84983e441c3bd26ebaae4aa1f95129e5e54670f1"));

    // See [2] test vector 4.
    SecureBytes longLongDigest = hashSHA1(SecureBytes::fromAscii(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    EXPECT_EQ(longLongDigest, SecureBytes::fromHex("a49b2446a02c645bf419f995b67091253a04a259"));

    // See [2] test vector 2.
    SecureBytes emptyStringDigest = hashSHA1(SecureBytes());
    EXPECT_EQ(emptyStringDigest, SecureBytes::fromHex("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
}

// Large Known Answer Test(KAT) for SHA1 from:
// [1] - https://www.di-mgt.com.au/sha_testvectors.html
TEST(SHA1, hashLargeKatSHA1) {
    if(skipLargeHash) GTEST_SKIP();
    // See [2] test vector 5.
    SecureBytes largeKAT;
    SecureBytes largeSeed = SecureBytes::fromAscii("a");
    const size_t largeRepetitions = 1000000;
    for (size_t i = 0; i < largeRepetitions; i++) {
        largeKAT.append(largeSeed);
    }
    EXPECT_EQ(hashSHA1(largeKAT), SecureBytes::fromHex("34aa973cd4c4daa4f61eeb2bdbad27316534016f"));

    // See [2] test vector 6.
    // repeated 16,777,216 times
    SecureBytes extremelyLongKAT;
    SecureBytes extremelyLongSeed = SecureBytes::fromAscii("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
    const size_t extremelyLongRepetitions = 16777216;
    for (size_t i = 0; i < extremelyLongRepetitions; i++) {
        extremelyLongKAT.append(extremelyLongSeed);
    }
    EXPECT_EQ(hashSHA1(extremelyLongKAT), SecureBytes::fromHex("7789f0c9ef7bfc40d93311143dfbe69e2017f592"));
}