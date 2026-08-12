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

TEST(Poly1305, Poly1305) {
    SecureBytes key     = SecureBytes::fromHex("0x85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    SecureBytes message = SecureBytes::fromAscii("Cryptographic Forum Research Group");

    SecureBytes tag = poly1305_mac(message, key);

    SecureBytes expected_tag = SecureBytes::fromHex("0xa8061dc1305136c6c22b8baf0c0127a9");

    EXPECT_EQ(tag, expected_tag);
}
