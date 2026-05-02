/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_ecc_der_decoder.cpp
 *
 * Unit tests for DER decoding of ECC public and private keys.
 * Round-trip tests: DER bytes are produced by encodeECC* and then decoded to verify correctness.
 * Known-answer tests (KAT): DER bytes produced by OpenSSL are decoded and verified.
 */

#include "asn1/der/der.h"

#include <gtest/gtest.h>

static const std::string kPriv = "0x1";
static const std::string kPubX = "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
static const std::string kPubY = "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

static ECCKeyPair makeTestKeyPair() {
    ECDSAPublicKey pub(Point(kPubX, kPubY), StandardCurve::secp256k1);
    return ECCKeyPair(kPriv, pub);
}

// EC Public Key — SEC1

TEST(DERDecoder_ECC_Test, decode_sec1_ec_public_key) {
    ECCKeyPair kp = makeTestKeyPair();

    // Produce known-good DER bytes via the encoder
    DEREncoder encoder;
    std::vector<uint8_t> der = encoder.encodeECPublicKeyToSEC1(kp.publicKey);

    DERDecoder decoder(der);
    ECDSAPublicKey decoded = decoder.decodeECPublicKeyFromSEC1();

    Point expected = kp.publicKey.getPublicKey();
    Point actual   = decoded.getPublicKey();

    EXPECT_EQ(expected.x, actual.x);
    EXPECT_EQ(expected.y, actual.y);
}

// EC Public Key — PKCS8

TEST(DERDecoder_ECC_Test, decode_pkcs8_ec_public_key) {
    ECCKeyPair kp = makeTestKeyPair();

    DEREncoder encoder;
    std::vector<uint8_t> der = encoder.encodeECPublicKeyToPKCS8(kp.publicKey);

    DERDecoder decoder(der);
    ECDSAPublicKey decoded = decoder.decodeECPublicKeyFromPKCS8();

    Point expected = kp.publicKey.getPublicKey();
    Point actual   = decoded.getPublicKey();

    EXPECT_EQ(expected.x, actual.x);
    EXPECT_EQ(expected.y, actual.y);
    EXPECT_EQ(kp.publicKey.getPublicKeyCurve(), decoded.getPublicKeyCurve());
}

// EC Public Key — auto-detect

TEST(DERDecoder_ECC_Test, decode_ec_public_key_auto_detect_pkcs8) {
    ECCKeyPair kp = makeTestKeyPair();

    DEREncoder encoder;
    std::vector<uint8_t> der = encoder.encodeECPublicKeyToPKCS8(kp.publicKey);

    DERDecoder decoder(der);
    ECDSAPublicKey decoded = decoder.decodeECPublicKeyFromDER();

    Point expected = kp.publicKey.getPublicKey();
    Point actual   = decoded.getPublicKey();

    EXPECT_EQ(expected.x, actual.x);
    EXPECT_EQ(expected.y, actual.y);
}

// EC Private Key — SEC1

TEST(DERDecoder_ECC_Test, decode_sec1_ec_private_key) {
    ECCKeyPair kp = makeTestKeyPair();

    DEREncoder encoder;
    std::vector<uint8_t> der = encoder.encodeECPrivateKeyToSEC1(kp);

    DERDecoder decoder(der);
    ECCKeyPair decoded = decoder.decodeECPrivateKeyFromSEC1();

    Point origPub = kp.getPublicKey();
    Point decPub  = decoded.getPublicKey();

    EXPECT_EQ(kp.privateKey, decoded.privateKey);
    EXPECT_EQ(origPub.x, decPub.x);
    EXPECT_EQ(origPub.y, decPub.y);
}

// EC Private Key — PKCS8

TEST(DERDecoder_ECC_Test, decode_pkcs8_ec_private_key) {
    ECCKeyPair kp = makeTestKeyPair();

    DEREncoder encoder;
    std::vector<uint8_t> der = encoder.encodeECPrivateKeyToPKCS8(kp);

    DERDecoder decoder(der);
    ECCKeyPair decoded = decoder.decodeECPrivateKeyFromPKCS8();

    Point origPub = kp.getPublicKey();
    Point decPub  = decoded.getPublicKey();

    EXPECT_EQ(kp.privateKey, decoded.privateKey);
    EXPECT_EQ(origPub.x, decPub.x);
    EXPECT_EQ(origPub.y, decPub.y);
    EXPECT_EQ(kp.publicKey.getPublicKeyCurve(), decoded.publicKey.getPublicKeyCurve());
}

// EC Private Key — auto-detect

TEST(DERDecoder_ECC_Test, decode_ec_private_key_auto_detect_pkcs8) {
    ECCKeyPair kp = makeTestKeyPair();

    DEREncoder encoder;
    std::vector<uint8_t> der = encoder.encodeECPrivateKeyToPKCS8(kp);

    DERDecoder decoder(der);
    ECCKeyPair decoded = decoder.decodeECPrivateKeyFromDER();

    EXPECT_EQ(kp.privateKey, decoded.privateKey);
}

// Known Answer Tests

static const std::vector<uint8_t> testPkcs8EcPublicKey = {
    0x30,0x56, 0x30,0x10, 0x06,0x07, 0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
    0x06,0x05, 0x2b,0x81,0x04,0x00,0x0a, 0x03,0x42, 0x00, 0x04,
    0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,
    0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,
    0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98,
    0x48,0x3a,0xda,0x77,0x26,0xa3,0xc4,0x65,0x5d,0xa4,0xfb,0xfc,
    0x0e,0x11,0x08,0xa8,0xfd,0x17,0xb4,0x48,0xa6,0x85,0x54,0x19,
    0x9c,0x47,0xd0,0x8f,0xfb,0x10,0xd4,0xb8
};

static const std::vector<uint8_t> testSec1EcPrivateKey = {
    0x30,0x2e, 0x02,0x01,0x01, 0x04,0x20,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
    0xa0,0x07, 0x06,0x05, 0x2b,0x81,0x04,0x00,0x0a
};

static const std::vector<uint8_t> testPkcs8EcPrivateKey = {
    0x30,0x3e, 0x02,0x01,0x00,
    0x30,0x10, 0x06,0x07, 0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
    0x06,0x05, 0x2b,0x81,0x04,0x00,0x0a,
    0x04,0x27, 0x30,0x25, 0x02,0x01,0x01, 0x04,0x20,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};

TEST(DERDecoder_ECC_Test, decode_pkcs8_ec_public_key_kat) {
    DERDecoder decoder(testPkcs8EcPublicKey);
    ECDSAPublicKey decoded = decoder.decodeECPublicKeyFromPKCS8();

    Point pt = decoded.getPublicKey();
    EXPECT_EQ(pt.x, BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
    EXPECT_EQ(pt.y, BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
    EXPECT_EQ(decoded.getPublicKeyCurve(), StandardCurve::secp256k1);
}

TEST(DERDecoder_ECC_Test, decode_sec1_ec_private_key_kat) {
    DERDecoder decoder(testSec1EcPrivateKey);
    ECCKeyPair decoded = decoder.decodeECPrivateKeyFromSEC1();

    EXPECT_EQ(decoded.privateKey, 1u);
    EXPECT_EQ(decoded.publicKey.getPublicKeyCurve(), StandardCurve::secp256k1);
}

TEST(DERDecoder_ECC_Test, decode_pkcs8_ec_private_key_kat) {
    DERDecoder decoder(testPkcs8EcPrivateKey);
    ECCKeyPair decoded = decoder.decodeECPrivateKeyFromPKCS8();

    EXPECT_EQ(decoded.privateKey, 1u);
    EXPECT_EQ(decoded.publicKey.getPublicKeyCurve(), StandardCurve::secp256k1);
}