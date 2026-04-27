/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_hmac.cpp
 *
 * This file contains the unit tests for the HMAC (Keyed Secure Hashing Algorithm) algorithm implementation.
 */

#include "gtest/gtest.h"

#include <gestalt/hmac_sha1.h>
#include <gestalt/hmac_sha2.h>
#include "vectors/vectors_hmac.h"

TEST_P(HMAC_SHA1, KAT) {
    const HMAC_TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);
    EXPECT_EQ(hmacSHA1(SecureBytes::fromAscii(vector.key), SecureBytes::fromAscii(vector.data)).toHex(), vector.expected);
}

TEST_P(HMAC_SHA2_224, KAT) {
    const HMAC_TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);
    EXPECT_EQ(hmacSHA224(SecureBytes::fromAscii(vector.key), SecureBytes::fromAscii(vector.data)).toHex(), vector.expected);
}

TEST_P(HMAC_SHA2_256, KAT) {
    const HMAC_TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);
    EXPECT_EQ(hmacSHA256(SecureBytes::fromAscii(vector.key), SecureBytes::fromAscii(vector.data)).toHex(), vector.expected);
}

TEST_P(HMAC_SHA2_384, KAT) {
    const HMAC_TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);
    EXPECT_EQ(hmacSHA384(SecureBytes::fromAscii(vector.key), SecureBytes::fromAscii(vector.data)).toHex(), vector.expected);
}

TEST_P(HMAC_SHA2_512, KAT) {
    const HMAC_TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);
    EXPECT_EQ(hmacSHA512(SecureBytes::fromAscii(vector.key), SecureBytes::fromAscii(vector.data)).toHex(), vector.expected);
}

TEST_P(HMAC_SHA2_512_224, KAT) {
    const HMAC_TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);
    EXPECT_EQ(hmacSHA512_224(SecureBytes::fromAscii(vector.key), SecureBytes::fromAscii(vector.data)).toHex(), vector.expected);
}

TEST_P(HMAC_SHA2_512_256, KAT) {
    const HMAC_TestVectors &vector = GetParam();
    SCOPED_TRACE(vector.name);
    EXPECT_EQ(hmacSHA512_256(SecureBytes::fromAscii(vector.key), SecureBytes::fromAscii(vector.data)).toHex(), vector.expected);
}