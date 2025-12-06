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

// Test encode with small exponent (e=3)
TEST(DEREncoder_Test, encode_key_with_exponent_3) {
    RSAPublicKey key = {
        "0xa8f7e069311610fdd2f70d2d82c89c5117e8fa72d6d3dff429f38f8a7858678a2ecd4fb7c42e294a5129f14b7d1602f4020a8db2535a2b7e0aabe3598cef4301",
        3
    };

    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeRSAPublicKeyToPKCS1(key);

    // Decode it back to verify
    DERDecoder decoder(encoded);
    RSAPublicKey decoded = decoder.decodeRSAPublicKeyFromPKCS1();

    EXPECT_TRUE(key.n == decoded.n);
    EXPECT_TRUE(key.e == decoded.e);
    EXPECT_TRUE(decoded.e == 3);
}

// Test encode with exponent 17
TEST(DEREncoder_Test, encode_key_with_exponent_17) {
    RSAPublicKey key = {
        "0xa8f7e069311610fdd2f70d2d82c89c5117e8fa72d6d3dff429f38f8a7858678a2ecd4fb7c42e294a5129f14b7d1602f4020a8db2535a2b7e0aabe3598cef4301",
        17
    };

    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeRSAPublicKeyToPKCS1(key);

    // Decode it back to verify
    DERDecoder decoder(encoded);
    RSAPublicKey decoded = decoder.decodeRSAPublicKeyFromPKCS1();

    EXPECT_TRUE(key.n == decoded.n);
    EXPECT_TRUE(key.e == decoded.e);
    EXPECT_TRUE(decoded.e == 17);
}

// Test roundtrip: decode existing key, encode it, decode again
TEST(DEREncoder_Test, roundtrip_pkcs1) {
    const std::vector<uint8_t> originalDER = {
        0x30, 0x48, 0x02, 0x41, 0x00, 0xa8, 0xf7, 0xe0, 0x69, 0x31, 0x16, 0x10,
        0xfd, 0xd2, 0xf7, 0x0d, 0x2d, 0x82, 0xc8, 0x9c, 0x51, 0x17, 0xe8, 0xfa,
        0x72, 0xd6, 0xd3, 0xdf, 0xf4, 0x29, 0xf3, 0x8f, 0x8a, 0x78, 0x58, 0x67,
        0x8a, 0x2e, 0xcd, 0x4f, 0xb7, 0xc4, 0x2e, 0x29, 0x4a, 0x51, 0x29, 0xf1,
        0x4b, 0x7d, 0x16, 0x02, 0xf4, 0x02, 0x0a, 0x8d, 0xb2, 0x53, 0x5a, 0x2b,
        0x7e, 0x0a, 0xab, 0xe3, 0x59, 0x8c, 0xef, 0x43, 0x01,
        0x02, 0x03, 0x01, 0x00, 0x01
    };

    // Decode
    DERDecoder decoder1(originalDER);
    RSAPublicKey key = decoder1.decodeRSAPublicKeyFromPKCS1();

    // Encode
    DEREncoder encoder;
    std::vector<uint8_t> reencoded = encoder.encodeRSAPublicKeyToPKCS1(key);

    // Decode again
    DERDecoder decoder2(reencoded);
    RSAPublicKey key2 = decoder2.decodeRSAPublicKeyFromPKCS1();

    // Should match
    EXPECT_TRUE(key.n == key2.n);
    EXPECT_TRUE(key.e == key2.e);
    
    // The DER should be identical
    EXPECT_EQ(originalDER, reencoded);
}

// Test roundtrip: PKCS#8
TEST(DEREncoder_Test, roundtrip_pkcs8) {
    const std::vector<uint8_t> originalDER = {
        0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 
        0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xa3, 
        0x99, 0xca, 0xf6, 0xd9, 0x3b, 0x62, 0xa6, 0xb6, 0xa5, 0x31, 
        0x1e, 0xfe, 0x93, 0xc4, 0xd6, 0x47, 0x39, 0x7c, 0xa0, 0x5a, 
        0x98, 0xfa, 0x5c, 0xdd, 0xb7, 0x2d, 0x68, 0x16, 0xab, 0x16, 
        0xfc, 0x85, 0xf9, 0x40, 0xef, 0xe9, 0xcf, 0x22, 0x33, 0x97, 
        0x5c, 0x89, 0x25, 0xc6, 0x0f, 0x4c, 0xd3, 0x56, 0x76, 0x7c, 
        0xc8, 0x44, 0x56, 0x86, 0x31, 0x3a, 0x0c, 0xae, 0xae, 0x32, 
        0x93, 0x00, 0x70, 0xca, 0x90, 0x59, 0x1a, 0x1b, 0x24, 0x9c, 
        0x2f, 0xce, 0xf9, 0x28, 0x0f, 0x5a, 0x11, 0xd8, 0xf1, 0x99, 
        0x05, 0x79, 0xd8, 0x6a, 0x05, 0xb2, 0x52, 0x3f, 0x52, 0xc4, 
        0xa8, 0x76, 0xda, 0x2d, 0x63, 0x5c, 0xa2, 0x7f, 0xbf, 0xf1, 
        0x95, 0xe6, 0xf7, 0x01, 0x5f, 0x83, 0x49, 0x28, 0xf0, 0x33, 
        0xa2, 0x0b, 0x2c, 0xd0, 0x21, 0x6a, 0x85, 0x29, 0x58, 0xb3, 
        0xe5, 0x8d, 0x0f, 0x9b, 0xd5, 0x42, 0x33, 0x02, 0x03, 0x01, 
        0x00, 0x01
    };

    // Decode
    DERDecoder decoder1(originalDER);
    RSAPublicKey key = decoder1.decodeRSAPublicKeyFromPKCS8();

    // Encode
    DEREncoder encoder;
    std::vector<uint8_t> reencoded = encoder.encodeRSAPublicKeyToPKCS8(key);

    // Decode again
    DERDecoder decoder2(reencoded);
    RSAPublicKey key2 = decoder2.decodeRSAPublicKeyFromPKCS8();

    // Should match
    EXPECT_TRUE(key.n == key2.n);
    EXPECT_TRUE(key.e == key2.e);
    
    // The DER should be identical
    EXPECT_EQ(originalDER, reencoded);
}

// Test format parameter in generic encode method
TEST(DEREncoder_Test, encode_with_format_parameter) {
    RSAPublicKey key = {
        "0xa8f7e069311610fdd2f70d2d82c89c5117e8fa72d6d3dff429f38f8a7858678a2ecd4fb7c42e294a5129f14b7d1602f4020a8db2535a2b7e0aabe3598cef4301",
        65537
    };

    DEREncoder encoder;
    
    // Encode as PKCS#1
    std::vector<uint8_t> pkcs1 = encoder.encodeRSAPublicKeyToDER(key, KeyFormat::PKCS1);
    
    // Encode as PKCS#8
    std::vector<uint8_t> pkcs8 = encoder.encodeRSAPublicKeyToDER(key, KeyFormat::PKCS8);
    
    // They should be different
    EXPECT_NE(pkcs1, pkcs8);
    
    // Both should decode correctly
    DERDecoder decoder1(pkcs1);
    RSAPublicKey decoded1 = decoder1.decodeRSAPublicKeyFromPKCS1();
    EXPECT_TRUE(key.n == decoded1.n);
    EXPECT_TRUE(key.e == decoded1.e);
    
    DERDecoder decoder2(pkcs8);
    RSAPublicKey decoded2 = decoder2.decodeRSAPublicKeyFromPKCS8();
    EXPECT_TRUE(key.n == decoded2.n);
    EXPECT_TRUE(key.e == decoded2.e);
}

// Test encoder rejects zero modulus
TEST(DEREncoder_Test, reject_zero_modulus) {
    RSAPublicKey invalidKey = {
        "0x0",  // Zero modulus
        65537
    };

    DEREncoder encoder;
    EXPECT_THROW(encoder.encodeRSAPublicKeyToPKCS1(invalidKey), std::runtime_error);
}

// Test encoder rejects even modulus
TEST(DEREncoder_Test, reject_even_modulus) {
    RSAPublicKey invalidKey = {
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",  // Even
        65537
    };

    DEREncoder encoder;
    EXPECT_THROW(encoder.encodeRSAPublicKeyToPKCS1(invalidKey), std::runtime_error);
}

// Test encoder rejects even exponent
TEST(DEREncoder_Test, reject_even_exponent) {
    RSAPublicKey invalidKey = {
        "0xa8f7e069311610fdd2f70d2d82c89c5117e8fa72d6d3dff429f38f8a7858678a2ecd4fb7c42e294a5129f14b7d1602f4020a8db2535a2b7e0aabe3598cef4301",
        4  // Even exponent
    };

    DEREncoder encoder;
    EXPECT_THROW(encoder.encodeRSAPublicKeyToPKCS1(invalidKey), std::runtime_error);
}

// Test encoder rejects small exponent (e < 3)
TEST(DEREncoder_Test, reject_small_exponent) {
    RSAPublicKey invalidKey = {
        "0xa8f7e069311610fdd2f70d2d82c89c5117e8fa72d6d3dff429f38f8a7858678a2ecd4fb7c42e294a5129f14b7d1602f4020a8db2535a2b7e0aabe3598cef4301",
        1  // Too small
    };

    DEREncoder encoder;
    EXPECT_THROW(encoder.encodeRSAPublicKeyToPKCS1(invalidKey), std::runtime_error);
}

// Test encoder rejects small modulus
TEST(DEREncoder_Test, reject_small_modulus) {
    RSAPublicKey invalidKey = {
        "0xFFFF",  // Only 16 bits
        65537
    };

    DEREncoder encoder;
    EXPECT_THROW(encoder.encodeRSAPublicKeyToPKCS1(invalidKey), std::runtime_error);
}

// Test encoder rejects exponent >= modulus
TEST(DEREncoder_Test, reject_exponent_too_large) {
    RSAPublicKey invalidKey = {
        "0xFF",  // Small modulus
        65537   // Exponent larger than modulus
    };

    DEREncoder encoder;
    EXPECT_THROW(encoder.encodeRSAPublicKeyToPKCS1(invalidKey), std::runtime_error);
}

// Test encoding and decoding with auto-detect
TEST(DEREncoder_Test, encode_decode_auto_detect) {
    RSAPublicKey key = {
        "0xa8f7e069311610fdd2f70d2d82c89c5117e8fa72d6d3dff429f38f8a7858678a2ecd4fb7c42e294a5129f14b7d1602f4020a8db2535a2b7e0aabe3598cef4301",
        65537
    };

    DEREncoder encoder;
    
    // Encode as PKCS#1
    std::vector<uint8_t> pkcs1 = encoder.encodeRSAPublicKeyToPKCS1(key);
    
    // Auto-detect should work
    DERDecoder decoder1(pkcs1);
    RSAPublicKey decoded1 = decoder1.decodeRSAPublicKeyFromDER();
    EXPECT_TRUE(key.n == decoded1.n);
    EXPECT_TRUE(key.e == decoded1.e);
    
    // Encode as PKCS#8
    std::vector<uint8_t> pkcs8 = encoder.encodeRSAPublicKeyToPKCS8(key);
    
    // Auto-detect should work
    DERDecoder decoder2(pkcs8);
    RSAPublicKey decoded2 = decoder2.decodeRSAPublicKeyFromDER();
    EXPECT_TRUE(key.n == decoded2.n);
    EXPECT_TRUE(key.e == decoded2.e);
}