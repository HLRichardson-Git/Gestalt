/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_aes_cfb.cpp
 *
 */

#include "gtest/gtest.h"

#include "utils.h"
#include <gestalt/aes.h>
#include "vectors/vectors_aes_cfb.h"

TEST_P(AES_CFB_Test, encrypt) {
    const AES_CFB_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = encryptAESCFB(SecureBytes::fromHex(test.pt), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key));

    EXPECT_EQ(result, SecureBytes::fromHex(test.ct));
}

TEST_P(AES_CFB_Test, decrypt) {
    const AES_CFB_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = decryptAESCFB(SecureBytes::fromHex(test.ct), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key));

    EXPECT_EQ(result, SecureBytes::fromHex(test.pt));
}

// CFB8 — NIST SP 800-38A vectors (F.3.7, F.3.9, F.3.11)

TEST_P(AES_CFB8_Test, encrypt) {
    const AES_CFB8_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = encryptAESCFB8(SecureBytes::fromHex(test.pt), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key));

    EXPECT_EQ(result, SecureBytes::fromHex(test.ct));
}

TEST_P(AES_CFB8_Test, decrypt) {
    const AES_CFB8_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    SecureBytes result = decryptAESCFB8(SecureBytes::fromHex(test.ct), SecureBytes::fromHex(test.iv), SecureBytes::fromHex(test.key));

    EXPECT_EQ(result, SecureBytes::fromHex(test.pt));
}

/* 
 * CFB1 round-trip tests (NIST SP 800-38A F.3.1-F.3.6 vectors operate at the bit level
 * and are not easily expressed as hex strings; round-trip confirms encrypt/decrypt symmetry)
*/

TEST(AES_CFB1_Test, roundtrip_128) {
    SecureBytes key = SecureBytes::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    SecureBytes iv  = SecureBytes::fromHex("000102030405060708090a0b0c0d0e0f");
    SecureBytes pt  = SecureBytes::fromHex("6bc1bee22e409f96e93d7e117393172a");

    SecureBytes ct = encryptAESCFB1(pt, iv, key);
    EXPECT_EQ(decryptAESCFB1(ct, iv, key), pt);
}

TEST(AES_CFB1_Test, roundtrip_192) {
    SecureBytes key = SecureBytes::fromHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    SecureBytes iv  = SecureBytes::fromHex("000102030405060708090a0b0c0d0e0f");
    SecureBytes pt  = SecureBytes::fromHex("6bc1bee22e409f96e93d7e117393172a");

    SecureBytes ct = encryptAESCFB1(pt, iv, key);
    EXPECT_EQ(decryptAESCFB1(ct, iv, key), pt);
}

TEST(AES_CFB1_Test, roundtrip_256) {
    SecureBytes key = SecureBytes::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    SecureBytes iv  = SecureBytes::fromHex("000102030405060708090a0b0c0d0e0f");
    SecureBytes pt  = SecureBytes::fromHex("6bc1bee22e409f96e93d7e117393172a");

    SecureBytes ct = encryptAESCFB1(pt, iv, key);
    EXPECT_EQ(decryptAESCFB1(ct, iv, key), pt);
}

// CFB64 round-trip tests (NIST SP 800-38A does not include CFB64 vectors for AES)

TEST(AES_CFB64_Test, roundtrip_128) {
    SecureBytes key = SecureBytes::fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    SecureBytes iv  = SecureBytes::fromHex("000102030405060708090a0b0c0d0e0f");
    SecureBytes pt  = SecureBytes::fromHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c");

    SecureBytes ct = encryptAESCFB64(pt, iv, key);
    EXPECT_EQ(decryptAESCFB64(ct, iv, key), pt);
}

TEST(AES_CFB64_Test, roundtrip_256) {
    SecureBytes key = SecureBytes::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    SecureBytes iv  = SecureBytes::fromHex("000102030405060708090a0b0c0d0e0f");
    SecureBytes pt  = SecureBytes::fromHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c");

    SecureBytes ct = encryptAESCFB64(pt, iv, key);
    EXPECT_EQ(decryptAESCFB64(ct, iv, key), pt);
}
