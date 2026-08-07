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

#include <gestalt/secure_bytes.h>
#include <gestalt/chacha.h>
#include "chacha/chachaCore.h"

class ChaCha_Functions : public ::testing::Test {
private:
	ChaCha chachaObject;
	
public:

	ChaCha_Functions() : chachaObject(SecureBytes::fromHex("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                                      SecureBytes::fromHex("0x000000090000004a00000000"),
                                      0x00000001) {}

    void set_block(SecureBytes key, SecureBytes counter, SecureBytes nonce) { return this->chachaObject.setState(key, counter, nonce); };

    void test_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) { return this->chachaObject.quarter_round(a, b, c, d); }
    void test_innter_block() { return this->chachaObject.inner_block(); }
    std::array<uint32_t, 16> test_chacha20_block() { return this->chachaObject.chacha20_block(); }
};

TEST_F(ChaCha_Functions, QuarterRound) {
    uint32_t a = 0x11111111;
    uint32_t b = 0x01020304;
    uint32_t c = 0x9b8d6f43;
    uint32_t d = 0x01234567;

    test_quarter_round(a, b, c, d);

    uint32_t expected_a = 0xea2a92f4;
    uint32_t expected_b = 0xcb1cf8ce;
    uint32_t expected_c = 0x4581472e;
    uint32_t expected_d = 0x5881c4bb;

	EXPECT_EQ(a, expected_a);
    EXPECT_EQ(b, expected_b);
    EXPECT_EQ(c, expected_c);
    EXPECT_EQ(d, expected_d);
}

TEST_F(ChaCha_Functions, ChaCha20Block) {
    std::array<uint32_t, 16> output = test_chacha20_block();

    uint32_t expected[16] = {
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    };

    for (int i = 0; i < 16; ++i)
        EXPECT_EQ(output[i], expected[i]);
}

TEST(ChaCha, ChaCha20_Encrypt) {
    SecureBytes key     = SecureBytes::fromHex("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    SecureBytes nonce   = SecureBytes::fromHex("000000000000004a00000000");
    uint32_t    counter = 0x00000001;

    SecureBytes plaintext = SecureBytes::fromAscii("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

    SecureBytes ciphertext = encryptChaCha20(plaintext, key, nonce, counter);

    SecureBytes expected_ciphertext = SecureBytes::fromHex("0x6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");

    EXPECT_EQ(ciphertext, expected_ciphertext);
}

TEST(ChaCha, ChaCha20_Decrypt) {
    SecureBytes key     = SecureBytes::fromHex("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    SecureBytes nonce   = SecureBytes::fromHex("000000000000004a00000000");
    uint32_t    counter = 0x00000001;

    SecureBytes ciphertext = SecureBytes::fromHex("0x6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");

    SecureBytes plaintext = decryptChaCha20(ciphertext, key, nonce, counter);

    SecureBytes expected_plaintext = SecureBytes::fromAscii("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

    EXPECT_EQ(plaintext, expected_plaintext);
}
