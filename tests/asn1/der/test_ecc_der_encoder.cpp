/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_ecc_der_encoder.cpp
 *
 * Unit tests for DER encoding of ECC public and private keys.
 * Round-trip tests: encode → decode to verify correctness.
 * Known-answer tests (KAT): compare encoder output to OpenSSL reference bytes.
 */

#include "asn1/der/der.h"

#include <gtest/gtest.h>

static const std::string kPriv = "0x1";
static const std::string kPubX = "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
static const std::string kPubY = "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

static KeyPair makeTestKeyPair() {
    ECDSAPublicKey pub(Point(kPubX, kPubY), StandardCurve::secp256k1);
    return KeyPair(kPriv, pub);
}

// EC Public Key — SEC1 (raw uncompressed point)

TEST(DEREncoder_ECC_Test, encode_sec1_ec_public_key) {
    KeyPair kp = makeTestKeyPair();

    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeECPublicKeyToSEC1(kp.publicKey);

    DERDecoder decoder(encoded);
    ECDSAPublicKey decoded = decoder.decodeECPublicKeyFromSEC1();

    Point orig = kp.publicKey.getPublicKey();
    Point dec  = decoded.getPublicKey();

    EXPECT_EQ(orig.x, dec.x);
    EXPECT_EQ(orig.y, dec.y);
}

// EC Public Key — PKCS8 (SubjectPublicKeyInfo)

TEST(DEREncoder_ECC_Test, encode_pkcs8_ec_public_key) {
    KeyPair kp = makeTestKeyPair();

    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeECPublicKeyToPKCS8(kp.publicKey);

    DERDecoder decoder(encoded);
    ECDSAPublicKey decoded = decoder.decodeECPublicKeyFromPKCS8();

    Point orig = kp.publicKey.getPublicKey();
    Point dec  = decoded.getPublicKey();

    EXPECT_EQ(orig.x, dec.x);
    EXPECT_EQ(orig.y, dec.y);
    EXPECT_EQ(kp.publicKey.getPublicKeyCurve(), decoded.getPublicKeyCurve());
}

// EC Private Key — SEC1 (ECPrivateKey)

TEST(DEREncoder_ECC_Test, encode_sec1_ec_private_key) {
    KeyPair kp = makeTestKeyPair();

    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeECPrivateKeyToSEC1(kp);

    DERDecoder decoder(encoded);
    KeyPair decoded = decoder.decodeECPrivateKeyFromSEC1();

    Point origPub = kp.getPublicKey();
    Point decPub  = decoded.getPublicKey();

    EXPECT_EQ(kp.privateKey, decoded.privateKey);
    EXPECT_EQ(origPub.x, decPub.x);
    EXPECT_EQ(origPub.y, decPub.y);
}

// EC Private Key — PKCS8 (PrivateKeyInfo)

TEST(DEREncoder_ECC_Test, encode_pkcs8_ec_private_key) {
    KeyPair kp = makeTestKeyPair();

    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeECPrivateKeyToPKCS8(kp);

    DERDecoder decoder(encoded);
    KeyPair decoded = decoder.decodeECPrivateKeyFromPKCS8();

    Point origPub = kp.getPublicKey();
    Point decPub  = decoded.getPublicKey();

    EXPECT_EQ(kp.privateKey, decoded.privateKey);
    EXPECT_EQ(origPub.x, decPub.x);
    EXPECT_EQ(origPub.y, decPub.y);
    EXPECT_EQ(kp.publicKey.getPublicKeyCurve(), decoded.publicKey.getPublicKeyCurve());
}

// Known Answer Tests

static const std::vector<uint8_t> testPkcs8ECPublicKey = {
    0x30,0x56, 0x30,0x10, 0x06,0x07, 0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
    0x06,0x05, 0x2b,0x81,0x04,0x00,0x0a, 0x03,0x42, 0x00, 0x04,
    0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,
    0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,
    0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98,
    0x48,0x3a,0xda,0x77,0x26,0xa3,0xc4,0x65,0x5d,0xa4,0xfb,0xfc,
    0x0e,0x11,0x08,0xa8,0xfd,0x17,0xb4,0x48,0xa6,0x85,0x54,0x19,
    0x9c,0x47,0xd0,0x8f,0xfb,0x10,0xd4,0xb8
};

// SEC1 public key is the raw uncompressed point: 0x04 || Gx || Gy (65 bytes)
static const std::vector<uint8_t> testSec1ECPublicKey = {
    0x04,
    0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,
    0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,
    0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98,
    0x48,0x3a,0xda,0x77,0x26,0xa3,0xc4,0x65,0x5d,0xa4,0xfb,0xfc,
    0x0e,0x11,0x08,0xa8,0xfd,0x17,0xb4,0x48,0xa6,0x85,0x54,0x19,
    0x9c,0x47,0xd0,0x8f,0xfb,0x10,0xd4,0xb8
};

TEST(DEREncoder_ECC_Test, encode_pkcs8_ec_public_key_kat) {
    KeyPair kp = makeTestKeyPair();
    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeECPublicKeyToPKCS8(kp.publicKey);
    EXPECT_EQ(encoded, testPkcs8ECPublicKey);
}

TEST(DEREncoder_ECC_Test, encode_sec1_ec_public_key_kat) {
    KeyPair kp = makeTestKeyPair();
    DEREncoder encoder;
    std::vector<uint8_t> encoded = encoder.encodeECPublicKeyToSEC1(kp.publicKey);
    EXPECT_EQ(encoded, testSec1ECPublicKey);
}
