/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_aes_gcm.cpp
 *
 */

 #include "gtest/gtest.h"

 #include <gestalt/aes.h>
 #include "aes/aesCore.h"
 #include "modes/gcm/gcm.h"
 #include "utils.h"
 #include "vectors/vectors_aes_gcm.h"

#include <array>
#include <cstring>

TEST_P(AES_GCM_Test, encrypt) {
    const AES_GCM_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    auto result = encryptAESGCM(SecureBytes::fromHex(test.pt), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key), SecureBytes::fromHex(test.aad));
    
    EXPECT_EQ(result.ciphertext, SecureBytes::fromHex(test.ct));
    EXPECT_EQ(result.tag, SecureBytes::fromHex(test.tag));
}

TEST_P(AES_GCM_Test, decrypt) {
    const AES_GCM_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    auto result = decryptAESGCM(SecureBytes::fromHex(test.ct), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key), SecureBytes::fromHex(test.tag), SecureBytes::fromHex(test.aad));
    
    EXPECT_EQ(result.plaintext, SecureBytes::fromHex(test.pt));
    EXPECT_TRUE(result.authenticated);
}

TEST_P(AES_GCM_Test, authFailure) {
    const AES_GCM_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    // Tamper with the tag (flip last byte) and verify authentication fails
    auto tag = SecureBytes::fromHex(test.tag);
    tag[tag.size() - 1] ^= 0xFF;

    auto result = decryptAESGCM(SecureBytes::fromHex(test.ct), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key), tag, SecureBytes::fromHex(test.aad));

    EXPECT_FALSE(result.authenticated);
    EXPECT_TRUE(result.plaintext.empty());
}

 /*
  * References:
  *     [1] https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
  *
  */

  // Helpers for internal GCM primitive tests
static std::array<uint8_t, 16> hexToArr16(const std::string& hex) {
    auto sb = SecureBytes::fromHex(hex);
    std::array<uint8_t, 16> arr = {};
    std::memcpy(arr.data(), sb.data(), 16);
    return arr;
}

static std::string arr16ToHex(const std::array<uint8_t, 16>& arr) {
    SecureBytes sb(16);
    std::memcpy(sb.data(), arr.data(), 16);
    return sb.toHex();
}

// ghashMultiply test vector: X=2, H=E(K=0^128, 0^128) from TC2 of [1]
TEST(GCM_Internal, ghashMultiply) {
    auto X = hexToArr16("00000000000000000000000000000002");
    auto H = hexToArr16("66e94bd4ef8a2c3b884cfa59ca342b2e");
    ghashMultiply(X, H);
    EXPECT_EQ(arr16ToHex(X), "a549b97029ca95c365a4805fb8dd7092");
}

// ghash test vector derived from TC2 of [1]:
TEST(GCM_Internal, ghash) {
    auto H   = hexToArr16("66e94bd4ef8a2c3b884cfa59ca342b2e");
    auto ct  = SecureBytes::fromHex("0388dace60b6a392f328c2b971b2fe78");
    auto result = ghash(H, SecureBytes{}, ct);
    EXPECT_EQ(arr16ToHex(result), "f38cbb1ad69223dcc3457ae5b6b0f885");
}

// ghash with empty AAD and empty data always returns zero (length block is all-zero)
TEST(GCM_Internal, ghash_emptyInputs) {
    auto H = hexToArr16("66e94bd4ef8a2c3b884cfa59ca342b2e");
    auto result = ghash(H, SecureBytes{}, SecureBytes{});
    EXPECT_EQ(arr16ToHex(result), "00000000000000000000000000000000");
}

// inc32 increments only the last 4 bytes (big-endian 32-bit counter)
TEST(GCM_Internal, inc32_basic) {
    auto ctr = hexToArr16("000000000000000000000000000000ff");
    inc32(ctr);
    EXPECT_EQ(arr16ToHex(ctr), "00000000000000000000000000000100");
}

// inc32 wraps the 32-bit counter without carrying into bytes 0–11
TEST(GCM_Internal, inc32_wrap) {
    auto ctr = hexToArr16("000000000000000000000000ffffffff");
    inc32(ctr);
    EXPECT_EQ(arr16ToHex(ctr), "00000000000000000000000000000000");
}

// inc32 leaves bytes 0–11 untouched even when they are non-zero
TEST(GCM_Internal, inc32_upperBytesPreserved) {
    auto ctr = hexToArr16("cafebabefacedbaddecaf88800000001");
    inc32(ctr);
    EXPECT_EQ(arr16ToHex(ctr), "cafebabefacedbaddecaf88800000002");
}
