/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_chacha_poly1305.cpp
 *
 * Tests for the ChaCha20-Poly1305 AEAD construction using RFC 8439 §2.8.2 vectors.
 */

#include "gtest/gtest.h"

#include <gestalt/chacha.h>

// RFC 8439 §2.8.2 test vector inputs
static const SecureBytes key   = SecureBytes::fromHex("0x808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
static const SecureBytes nonce = SecureBytes::fromHex("0x070000004041424344454647");
static const SecureBytes aad   = SecureBytes::fromHex("0x50515253c0c1c2c3c4c5c6c7");
static const SecureBytes plaintext = SecureBytes::fromAscii(
    "Ladies and Gentlemen of the class of '99: "
    "If I could offer you only one tip for the future, sunscreen would be it.");

static const SecureBytes expected_ciphertext = SecureBytes::fromHex(
    "0xd31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116");

static const SecureBytes expected_tag = SecureBytes::fromHex("0x1ae10b594f09e26a7e902ecbd0600691");

TEST(ChaCha20Poly1305, Encrypt) {
    auto result = encryptChaCha20Poly1305(plaintext, key, nonce, aad);

    EXPECT_EQ(result.ciphertext, expected_ciphertext);
    EXPECT_EQ(result.tag, expected_tag);
}

TEST(ChaCha20Poly1305, Decrypt) {
    auto result = decryptChaCha20Poly1305(expected_ciphertext, key, nonce, expected_tag, aad);

    EXPECT_TRUE(result.authenticated);
    EXPECT_EQ(result.plaintext, plaintext);
}

TEST(ChaCha20Poly1305, DecryptRejectsModifiedTag) {
    SecureBytes bad_tag = expected_tag;
    bad_tag[0] ^= 0xff;

    auto result = decryptChaCha20Poly1305(expected_ciphertext, key, nonce, bad_tag, aad);

    EXPECT_FALSE(result.authenticated);
    EXPECT_TRUE(result.plaintext.empty());
}
