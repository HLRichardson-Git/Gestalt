/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_ecc_pem_decoder.cpp
 *
 * Unit tests for PEM decoding of ECC public and private keys.
 * Round-trip tests: PEM strings produced via PEMEncoder then decoded to verify correctness.
 * Known-answer tests (KAT): PEM strings produced by OpenSSL decoded to verify correctness.
 */

#include "asn1/pem/pem.h"

#include <gtest/gtest.h>

static const std::string kPriv = "0x1";
static const std::string kPubX = "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
static const std::string kPubY = "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

static ECCKeyPair makeTestKeyPair() {
    ECDSAPublicKey pub(Point(kPubX, kPubY), StandardCurve::secp256k1);
    return ECCKeyPair(kPriv, pub);
}

// EC Public Key — SEC1

TEST(PEMDecoder_ECC_Test, decode_sec1_ec_public_key) {
    ECCKeyPair kp = makeTestKeyPair();
    std::string pem = PEMEncoder::encodeECPublicKeyToSEC1(kp.publicKey);

    ECDSAPublicKey decoded = PEMDecoder::decodeECPublicKeyFromSEC1(pem);

    Point expected = kp.publicKey.getPublicKey();
    Point actual   = decoded.getPublicKey();
    EXPECT_EQ(expected.x, actual.x);
    EXPECT_EQ(expected.y, actual.y);
}

// EC Public Key — PKCS8

TEST(PEMDecoder_ECC_Test, decode_pkcs8_ec_public_key) {
    ECCKeyPair kp = makeTestKeyPair();
    std::string pem = PEMEncoder::encodeECPublicKeyToPKCS8(kp.publicKey);

    ECDSAPublicKey decoded = PEMDecoder::decodeECPublicKeyFromPKCS8(pem);

    Point expected = kp.publicKey.getPublicKey();
    Point actual   = decoded.getPublicKey();
    EXPECT_EQ(expected.x, actual.x);
    EXPECT_EQ(expected.y, actual.y);
    EXPECT_EQ(kp.publicKey.getPublicKeyCurve(), decoded.getPublicKeyCurve());
}

// EC Private Key — SEC1

TEST(PEMDecoder_ECC_Test, decode_sec1_ec_private_key) {
    ECCKeyPair kp = makeTestKeyPair();
    std::string pem = PEMEncoder::encodeECPrivateKeyToSEC1(kp);

    ECCKeyPair decoded = PEMDecoder::decodeECPrivateKeyFromSEC1(pem);

    EXPECT_EQ(kp.privateKey, decoded.privateKey);

    Point origPub = kp.getPublicKey();
    Point decPub  = decoded.getPublicKey();
    
    EXPECT_EQ(origPub.x, decPub.x);
    EXPECT_EQ(origPub.y, decPub.y);
}

// EC Private Key — PKCS8

TEST(PEMDecoder_ECC_Test, decode_pkcs8_ec_private_key) {
    ECCKeyPair kp = makeTestKeyPair();
    std::string pem = PEMEncoder::encodeECPrivateKeyToPKCS8(kp);

    ECCKeyPair decoded = PEMDecoder::decodeECPrivateKeyFromPKCS8(pem);

    EXPECT_EQ(kp.privateKey, decoded.privateKey);

    Point origPub = kp.getPublicKey();
    Point decPub  = decoded.getPublicKey();

    EXPECT_EQ(origPub.x, decPub.x);
    EXPECT_EQ(origPub.y, decPub.y);
    EXPECT_EQ(kp.publicKey.getPublicKeyCurve(), decoded.publicKey.getPublicKeyCurve());
}

// Invalid PEM — wrong header

TEST(PEMDecoder_ECC_Test, decode_ec_private_key_wrong_header_throws) {
    ECCKeyPair kp = makeTestKeyPair();
    // Encode as PKCS8 but try to decode as SEC1 (wrong header)
    std::string pem = PEMEncoder::encodeECPrivateKeyToPKCS8(kp);
    EXPECT_THROW(PEMDecoder::decodeECPrivateKeyFromSEC1(pem), std::runtime_error);
}

// Known Answer Tests

static const std::string testPkcs8EcPublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEeb5mfvncu6xVoGKVzocLBwKb/NstzijZ\n"
    "WfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuA==\n"
    "-----END PUBLIC KEY-----\n";

// openssl ec -in key.pem (SEC1 format; no public key embedded)
static const std::string testSec1EcPrivatekey =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MC4CAQEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABoAcGBSuBBAAK\n"
    "-----END EC PRIVATE KEY-----\n";

// openssl pkcs8 -topk8 -nocrypt -in key.pem
static const std::string testPkcs8EcPrivatekey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MD4CAQAwEAYHKoZIzj0CAQYFK4EEAAoEJzAlAgEBBCAAAAAAAAAAAAAAAAAAAAAA\n"
    "AAAAAAAAAAAAAAAAAAAAAQ==\n"
    "-----END PRIVATE KEY-----\n";

TEST(PEMDecoder_ECC_Test, decode_pkcs8_ec_public_key_kat) {
    ECDSAPublicKey decoded = PEMDecoder::decodeECPublicKeyFromPKCS8(testPkcs8EcPublicKey);
    Point pt = decoded.getPublicKey();
    EXPECT_EQ(pt.x, BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"));
    EXPECT_EQ(pt.y, BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
    EXPECT_EQ(decoded.getPublicKeyCurve(), StandardCurve::secp256k1);
}

TEST(PEMDecoder_ECC_Test, decode_sec1_ec_private_key_kat) {
    ECCKeyPair decoded = PEMDecoder::decodeECPrivateKeyFromSEC1(testSec1EcPrivatekey);
    EXPECT_EQ(decoded.privateKey, 1u);
    EXPECT_EQ(decoded.publicKey.getPublicKeyCurve(), StandardCurve::secp256k1);
}

TEST(PEMDecoder_ECC_Test, decode_pkcs8_ec_private_key_kat) {
    ECCKeyPair decoded = PEMDecoder::decodeECPrivateKeyFromPKCS8(testPkcs8EcPrivatekey);
    EXPECT_EQ(decoded.privateKey, 1u);
    EXPECT_EQ(decoded.publicKey.getPublicKeyCurve(), StandardCurve::secp256k1);
}