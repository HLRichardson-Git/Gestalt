/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_chacha_functions.cpp
 *
 */

#include <cstring>

#include "gtest/gtest.h"

#include "poly1305/poly1305.h"

TEST(Poly1305, Poly1305_key_gen) {
    SecureBytes key   = SecureBytes::fromHex("0x808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    SecureBytes nonce = SecureBytes::fromHex("0x000000000001020304050607");

    SecureBytes result = poly1305_key_gen(key, nonce);

    SecureBytes expected = SecureBytes::fromHex("0x8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646");

    EXPECT_EQ(result, expected);
}

TEST(Poly1305, Poly1305_mac) {
    SecureBytes key     = SecureBytes::fromHex("0x85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    SecureBytes message = SecureBytes::fromAscii("Cryptographic Forum Research Group");

    SecureBytes tag = poly1305_mac(message, key);

    SecureBytes expected_tag = SecureBytes::fromHex("0xa8061dc1305136c6c22b8baf0c0127a9");

    EXPECT_EQ(tag, expected_tag);
}
