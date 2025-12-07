/*
 * Copyright 2023-2025 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

#include "asn1/der/der.h"

#include <gtest/gtest.h>

// Test encoding to PKCS#8 format
TEST(DEREncoder_Test, encode_pkcs8_rsa_public_key) {
    RSAPublicKey key = {
        "0xa399caf6d93b62a6b6a5311efe93c4d647397ca05a98fa5cddb72d6816ab16fc85f940efe9cf2233975c8925c60f4cd356767cc8445686313a0caeae32930070ca90591a1b249c2fcef9280f5a11d8f1990579d86a05b2523f52c4a876da2d635ca27fbff195e6f7015f834928f033a20b2cd0216a852958b3e58d0f9bd54233",
        65537
    };

    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeRSAPublicKeyToPKCS8(key);

    // Decode it back to verify
    DERDecoder decoder(encoded);
    RSAPublicKey decoded = decoder.decodeRSAPublicKeyFromPKCS8();

    EXPECT_TRUE(key.n == decoded.n);
    EXPECT_TRUE(key.e == decoded.e);
}

// Test encoding to PKCS#1 format
TEST(DEREncoder_Test, encode_pkcs1_rsa_public_key) {
    RSAPublicKey key = {
        "0xa8f7e069311610fdd2f70d2d82c89c5117e8fa72d6d3dff429f38f8a7858678a2ecd4fb7c42e294a5129f14b7d1602f4020a8db2535a2b7e0aabe3598cef4301",
        65537
    };

    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeRSAPublicKeyToPKCS1(key);

    // Decode it back to verify
    DERDecoder decoder(encoded);
    RSAPublicKey decoded = decoder.decodeRSAPublicKeyFromPKCS1();

    EXPECT_TRUE(key.n == decoded.n);
    EXPECT_TRUE(key.e == decoded.e);
}

