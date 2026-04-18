/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_secure_bytes.cpp
 *
 * Unit tests for the SecureBytes type. Covers named constructors, round-trip
 * conversions, buffer manipulation, operators, and zeroing behaviour.
 */

#include "gtest/gtest.h"
#include <gestalt/secure_bytes.h>

// fromHex

TEST(SecureBytes, FromHex_RoundTrip) {
    SecureBytes sb = SecureBytes::fromHex("deadbeef");
    EXPECT_EQ(sb.size(), 4u);
    EXPECT_EQ(sb.toHex(), "deadbeef");
}

TEST(SecureBytes, FromHex_UpperCase) {
    SecureBytes sb = SecureBytes::fromHex("DEADBEEF");
    EXPECT_EQ(sb.toHex(), "deadbeef");
}

TEST(SecureBytes, FromHex_WithOxPrefix) {
    SecureBytes sb = SecureBytes::fromHex("0xdeadbeef");
    EXPECT_EQ(sb.toHex(), "deadbeef");
}

TEST(SecureBytes, FromHex_WithOXPrefix) {
    SecureBytes sb = SecureBytes::fromHex("0Xdeadbeef");
    EXPECT_EQ(sb.toHex(), "deadbeef");
}

TEST(SecureBytes, FromHex_EmptyString) {
    SecureBytes sb = SecureBytes::fromHex("");
    EXPECT_TRUE(sb.empty());
}

TEST(SecureBytes, FromHex_OddLengthThrows) {
    EXPECT_THROW(SecureBytes::fromHex("abc"), std::invalid_argument);
}

TEST(SecureBytes, FromHex_NonHexCharThrows) {
    EXPECT_THROW(SecureBytes::fromHex("zz"), std::invalid_argument);
}

TEST(SecureBytes, FromHex_LeadingZeroPreserved) {
    SecureBytes sb = SecureBytes::fromHex("00ff");
    EXPECT_EQ(sb.size(), 2u);
    EXPECT_EQ(sb[0], 0x00);
    EXPECT_EQ(sb[1], 0xff);
    EXPECT_EQ(sb.toHex(), "00ff");
}

// fromAscii

TEST(SecureBytes, FromAscii_RoundTrip) {
    SecureBytes sb = SecureBytes::fromAscii("Hello");
    EXPECT_EQ(sb.size(), 5u);
    EXPECT_EQ(sb.toAscii(), "Hello");
}

TEST(SecureBytes, FromAscii_Empty) {
    SecureBytes sb = SecureBytes::fromAscii("");
    EXPECT_TRUE(sb.empty());
}

TEST(SecureBytes, FromAscii_ByteValues) {
    SecureBytes sb = SecureBytes::fromAscii("AB");
    EXPECT_EQ(sb[0], 0x41);
    EXPECT_EQ(sb[1], 0x42);
}

// fromVector

TEST(SecureBytes, FromVector_RoundTrip) {
    std::vector<uint8_t> v = {0x01, 0x02, 0x03};
    SecureBytes sb = SecureBytes::fromVector(v);
    EXPECT_EQ(sb.size(), 3u);
    EXPECT_EQ(sb.toVector(), v);
}

TEST(SecureBytes, FromVector_Empty) {
    SecureBytes sb = SecureBytes::fromVector({});
    EXPECT_TRUE(sb.empty());
}

// random

TEST(SecureBytes, Random_CorrectSize) {
    SecureBytes sb = SecureBytes::random(16);
    EXPECT_EQ(sb.size(), 16u);
}

TEST(SecureBytes, Random_ZeroSize) {
    SecureBytes sb = SecureBytes::random(0);
    EXPECT_TRUE(sb.empty());
}

TEST(SecureBytes, Random_TwoCallsDiffer) {
    // With 128 bits of entropy, collisions are astronomically unlikely.
    SecureBytes a = SecureBytes::random(16);
    SecureBytes b = SecureBytes::random(16);
    EXPECT_NE(a, b);
}

// toHex / toAscii / toVector

TEST(SecureBytes, ToHex_AllZeros) {
    SecureBytes sb(4, 0x00);
    EXPECT_EQ(sb.toHex(), "00000000");
}

TEST(SecureBytes, ToHex_AllFF) {
    SecureBytes sb(2, 0xff);
    EXPECT_EQ(sb.toHex(), "ffff");
}

TEST(SecureBytes, ToAscii_Correctness) {
    SecureBytes sb = SecureBytes::fromHex("48656c6c6f"); // "Hello"
    EXPECT_EQ(sb.toAscii(), "Hello");
}

TEST(SecureBytes, ToVector_Independence) {
    SecureBytes sb = SecureBytes::fromHex("aabb");
    auto v = sb.toVector();
    v[0] = 0xff; // mutating the returned vector must not affect sb
    EXPECT_EQ(sb[0], 0xaa);
}

// append / prepend / operator+

TEST(SecureBytes, Append_Correctness) {
    SecureBytes a = SecureBytes::fromHex("0102");
    SecureBytes b = SecureBytes::fromHex("0304");
    a.append(b);
    EXPECT_EQ(a.toHex(), "01020304");
}

TEST(SecureBytes, Prepend_Correctness) {
    SecureBytes a = SecureBytes::fromHex("0304");
    SecureBytes b = SecureBytes::fromHex("0102");
    a.prepend(b);
    EXPECT_EQ(a.toHex(), "01020304");
}

TEST(SecureBytes, OperatorPlus_Correctness) {
    SecureBytes a = SecureBytes::fromHex("0102");
    SecureBytes b = SecureBytes::fromHex("0304");
    SecureBytes c = a + b;
    EXPECT_EQ(c.toHex(), "01020304");
    // originals are unchanged
    EXPECT_EQ(a.toHex(), "0102");
    EXPECT_EQ(b.toHex(), "0304");
}

TEST(SecureBytes, AppendEmpty_Unchanged) {
    SecureBytes a = SecureBytes::fromHex("aabb");
    a.append(SecureBytes{});
    EXPECT_EQ(a.toHex(), "aabb");
}

TEST(SecureBytes, PrependEmpty_Unchanged) {
    SecureBytes a = SecureBytes::fromHex("aabb");
    a.prepend(SecureBytes{});
    EXPECT_EQ(a.toHex(), "aabb");
}

// operator== / operator!=

TEST(SecureBytes, EqualityTrue) {
    EXPECT_EQ(SecureBytes::fromHex("deadbeef"), SecureBytes::fromHex("deadbeef"));
}

TEST(SecureBytes, EqualityFalse_DifferentContent) {
    EXPECT_NE(SecureBytes::fromHex("deadbeef"), SecureBytes::fromHex("cafebabe"));
}

TEST(SecureBytes, EqualityFalse_DifferentSize) {
    EXPECT_NE(SecureBytes::fromHex("dead"), SecureBytes::fromHex("deadbeef"));
}

TEST(SecureBytes, EmptyEquality) {
    EXPECT_EQ(SecureBytes{}, SecureBytes{});
}

// zeroize

TEST(SecureBytes, Zeroize_ClearsBuffer) {
    SecureBytes sb = SecureBytes::fromHex("deadbeef");
    sb.zeroize();
    EXPECT_TRUE(sb.empty());
    EXPECT_EQ(sb.size(), 0u);
}

TEST(SecureBytes, Zeroize_IdempotentOnEmpty) {
    SecureBytes sb;
    sb.zeroize(); // must not crash or throw
    EXPECT_TRUE(sb.empty());
}

// Copy semantics

TEST(SecureBytes, CopyConstructor_IndependentBuffer) {
    SecureBytes original = SecureBytes::fromHex("aabbccdd");
    SecureBytes copy(original);
    copy[0] = 0xff;
    EXPECT_EQ(original[0], 0xaa); // original must be unmodified
}

TEST(SecureBytes, CopyAssignment_IndependentBuffer) {
    SecureBytes original = SecureBytes::fromHex("aabbccdd");
    SecureBytes copy;
    copy = original;
    copy[1] = 0xff;
    EXPECT_EQ(original[1], 0xbb);
}

// size / data / operator[]

TEST(SecureBytes, SizeAndIndex) {
    SecureBytes sb = SecureBytes::fromHex("010203");
    EXPECT_EQ(sb.size(), 3u);
    EXPECT_EQ(sb[0], 0x01);
    EXPECT_EQ(sb[1], 0x02);
    EXPECT_EQ(sb[2], 0x03);
}

TEST(SecureBytes, DataPointer) {
    SecureBytes sb = SecureBytes::fromHex("aabb");
    const uint8_t* p = sb.data();
    EXPECT_EQ(p[0], 0xaa);
    EXPECT_EQ(p[1], 0xbb);
}

TEST(SecureBytes, RangeFor) {
    SecureBytes sb = SecureBytes::fromHex("010203");
    uint32_t sum = 0;
    for (uint8_t byte : sb) sum += byte;
    EXPECT_EQ(sum, 6u);
}

// Constructor with fill

TEST(SecureBytes, FillConstructor) {
    SecureBytes sb(4, 0xab);
    EXPECT_EQ(sb.toHex(), "abababab");
}
