/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_ecc_pem_encoder.cpp
 *
 * Unit tests for PEM encoding of ECC public and private keys.
 * Round-trip tests: encode then decode to verify correctness.
 * Known-answer tests (KAT): compare encoder output to OpenSSL reference PEM.
 */

#include "asn1/pem/pem.h"

#include <gtest/gtest.h>
#include <string>

static const std::string kPriv = "0x1";
static const std::string kPubX = "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
static const std::string kPubY = "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

static ECCKeyPair makeTestKeyPair() {
    ECDSAPublicKey pub(Point(kPubX, kPubY), StandardCurve::secp256k1);
    return ECCKeyPair(kPriv, pub);
}

// EC Public Key — SEC1

TEST(PEMEncoder_ECC_Test, encode_sec1_ec_public_key) {
    ECCKeyPair kp = makeTestKeyPair();
    std::string pem = PEMEncoder::encodeECPublicKeyToSEC1(kp.publicKey);

    EXPECT_NE(pem.find("-----BEGIN EC PUBLIC KEY-----"), std::string::npos);
    EXPECT_NE(pem.find("-----END EC PUBLIC KEY-----"),   std::string::npos);

    // Round-trip
    ECDSAPublicKey decoded = PEMDecoder::decodeECPublicKeyFromSEC1(pem);
    Point orig = kp.publicKey.getPublicKey();
    Point dec  = decoded.getPublicKey();
    
    EXPECT_EQ(orig.x, dec.x);
    EXPECT_EQ(orig.y, dec.y);
}

// EC Public Key — PKCS8

TEST(PEMEncoder_ECC_Test, encode_pkcs8_ec_public_key) {
    ECCKeyPair kp = makeTestKeyPair();
    std::string pem = PEMEncoder::encodeECPublicKeyToPKCS8(kp.publicKey);

    EXPECT_NE(pem.find("-----BEGIN PUBLIC KEY-----"), std::string::npos);
    EXPECT_NE(pem.find("-----END PUBLIC KEY-----"),   std::string::npos);

    // Round-trip
    ECDSAPublicKey decoded = PEMDecoder::decodeECPublicKeyFromPKCS8(pem);
    Point orig = kp.publicKey.getPublicKey();
    Point dec  = decoded.getPublicKey();

    EXPECT_EQ(orig.x, dec.x);
    EXPECT_EQ(orig.y, dec.y);
    EXPECT_EQ(kp.publicKey.getPublicKeyCurve(), decoded.getPublicKeyCurve());
}

// EC Private Key — SEC1

TEST(PEMEncoder_ECC_Test, encode_sec1_ec_private_key) {
    ECCKeyPair kp = makeTestKeyPair();
    std::string pem = PEMEncoder::encodeECPrivateKeyToSEC1(kp);

    EXPECT_NE(pem.find("-----BEGIN EC PRIVATE KEY-----"), std::string::npos);
    EXPECT_NE(pem.find("-----END EC PRIVATE KEY-----"),   std::string::npos);

    // Round-trip
    ECCKeyPair decoded = PEMDecoder::decodeECPrivateKeyFromSEC1(pem);

    EXPECT_EQ(kp.privateKey, decoded.privateKey);

    Point origPub = kp.getPublicKey();
    Point decPub  = decoded.getPublicKey();

    EXPECT_EQ(origPub.x, decPub.x);
    EXPECT_EQ(origPub.y, decPub.y);
}

// EC Private Key — PKCS8

TEST(PEMEncoder_ECC_Test, encode_pkcs8_ec_private_key) {
    ECCKeyPair kp = makeTestKeyPair();
    std::string pem = PEMEncoder::encodeECPrivateKeyToPKCS8(kp);

    EXPECT_NE(pem.find("-----BEGIN PRIVATE KEY-----"), std::string::npos);
    EXPECT_NE(pem.find("-----END PRIVATE KEY-----"),   std::string::npos);

    // Round-trip
    ECCKeyPair decoded = PEMDecoder::decodeECPrivateKeyFromPKCS8(pem);

    EXPECT_EQ(kp.privateKey, decoded.privateKey);

    Point origPub = kp.getPublicKey();
    Point decPub  = decoded.getPublicKey();

    EXPECT_EQ(origPub.x, decPub.x);
    EXPECT_EQ(origPub.y, decPub.y);
    EXPECT_EQ(kp.publicKey.getPublicKeyCurve(), decoded.publicKey.getPublicKeyCurve());
}

// Known Answer Test

static const std::string testKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEeb5mfvncu6xVoGKVzocLBwKb/NstzijZ\n"
    "WfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuA==\n"
    "-----END PUBLIC KEY-----\n";

TEST(PEMEncoder_ECC_Test, encode_pkcs8_ec_public_key_kat) {
    ECCKeyPair kp = makeTestKeyPair();
    std::string pem = PEMEncoder::encodeECPublicKeyToPKCS8(kp.publicKey);
    EXPECT_EQ(pem, testKey);
}