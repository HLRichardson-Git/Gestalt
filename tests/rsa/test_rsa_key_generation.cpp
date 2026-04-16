/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_functions.cpp
 *
 * This file contains unit tests for RSA key pair generation, validation, and edge cases. 
 * The tests cover key pair generation, custom initialization, invalid key handling, and ensuring key components like 
 * modulus and exponents meet the required cryptographic standards.
 * 
 */

#include "gtest/gtest.h"

#include "rsa/rsa_key_generation/rsaKeyGen.h"
#include "vectors/vectors_rsa_key_gen.h"

const bool skipRSAKeyGen = true; // RSA key gen can take awhile, so set to false if you'd like to test RSA keyGen

TEST(RSA_KeyPair_Test, testKeyGen) {
    if(skipRSAKeyGen) GTEST_SKIP();

    RSAKeyPair rsa;

    EXPECT_TRUE(rsa.validateKeyPair()) << "Generated key pair was invalid";
}

TEST(RSA_KeyPair_Test, testKeyReGen) {
    if(skipRSAKeyGen) GTEST_SKIP();

    RSAKeyPair rsa;

    RSAPrivateKey privateKey1 = rsa.getPrivateKey();
    RSAPublicKey publicKey1 = rsa.getPublicKey();

    rsa.regenerateKeyPair({RSASecurityStrength::RSA_2048, RandomPrimeMethod::probable});

    RSAPrivateKey privateKey2 = rsa.getPrivateKey();
    RSAPublicKey publicKey2 = rsa.getPublicKey();

    EXPECT_FALSE(privateKey1.d == privateKey2.d) << "Both generated private keys are the same";
    EXPECT_FALSE(publicKey1.n == publicKey2.n) << "Both generated public keys are the same";
}

TEST(RSA_KeyPair_Test, customKeyPairInitialization) {
    RSAPrivateKey privateKey(d, p, q);
    RSAPublicKey publicKey(n, e);

    RSAKeyPair rsa(RSASecurityStrength::RSA_2048, privateKey, publicKey);

    EXPECT_TRUE(rsa.getPrivateKey().d == privateKey.d) << "Custom private exponent intialization failed";
    EXPECT_TRUE(rsa.getPublicKey().n == publicKey.n) << "Custom public modulus intialization failed";
    EXPECT_TRUE(rsa.getPublicKey().e == publicKey.e) << "Custom public exponent intialization failed";
}

TEST(RSA_KeyPair_Test, invalidKeyPairInitialization) {
    BigInt invalidP = "4";  // Non-prime number
    BigInt invalidQ = "6";  // Non-prime number

    EXPECT_THROW({
        RSAPrivateKey invalidPrivateKey(BigInt("123"), invalidP, invalidQ);
        RSAKeyPair invalidKeyPair(RSASecurityStrength::RSA_2048, invalidPrivateKey, RSAPublicKey());
    }, std::runtime_error);
}

TEST(RSA_KeyPair_Test, specifiedWrongSecurityStrength) {
    RSAPrivateKey privateKey(d);
    RSAPublicKey publicKey(n, e);

    EXPECT_THROW({
        // The keys are intialized with components that are 2048-bits
        RSAKeyPair invalidKeyPair(RSASecurityStrength::RSA_3072, privateKey, publicKey);
    }, std::invalid_argument) << "Private key bit length validation failed";
}

TEST(RSA_KeyPair_Test, smallPublicExponent) {
    RSAPrivateKey privateKey(d, p, q);
    RSAPublicKey publicKey(n, "3");

    EXPECT_THROW({
        RSAKeyPair rsa(RSASecurityStrength::RSA_2048, privateKey, publicKey);
    }, std::invalid_argument) << "Failed to set a small public exponent";
}


TEST(RSA_KeyPair_Test, modulusBitLength) {
    if(skipRSAKeyGen) GTEST_SKIP();
    RSAKeyPair rsa;
    EXPECT_NEAR(rsa.getModulusBitLength(), 2048, 10);
}

TEST(RSA_KeyPair_Test, privateExponentBitLength) {
    if(skipRSAKeyGen) GTEST_SKIP();
    RSAKeyPair rsa;
    EXPECT_NEAR(rsa.getPrivateExponentBitLength(), 2048, 10);
}

TEST(RSA_KeyPair_Test, CRTComponents) {
    RSAPrivateKey privateKey(d, p, q);

    EXPECT_TRUE(privateKey.dP == dP);
    EXPECT_TRUE(privateKey.dQ == dQ);
    EXPECT_TRUE(privateKey.qInv == qInv);
}

TEST(RSA_DER_Test, publicKey_PKCS8_roundtrip) {
    RSAPublicKey pubKey(n, e);

    // Encode to DER
    std::vector<uint8_t> der = pubKey.toDER(RsaKeyFormat::PKCS8);

    // Decode back
    RSAPublicKey decoded;
    decoded.fromDER(der, RsaKeyFormat::PKCS8);

    EXPECT_EQ(pubKey.n, decoded.n);
    EXPECT_EQ(pubKey.e, decoded.e);
}

TEST(RSA_DER_Test, publicKey_PKCS1_roundtrip) {
    RSAPublicKey pubKey(n, e);

    std::vector<uint8_t> der = pubKey.toDER(RsaKeyFormat::PKCS1);
    RSAPublicKey decoded;
    decoded.fromDER(der, RsaKeyFormat::PKCS1);

    EXPECT_EQ(pubKey.n, decoded.n);
    EXPECT_EQ(pubKey.e, decoded.e);
}

TEST(RSA_DER_Test, privateKey_PKCS8_roundtrip) {
    RSAPrivateKey privKey(d, p, q);

    // Encode to DER requires the public key
    RSAPublicKey pubKey(n, e);
    std::vector<uint8_t> der = privKey.toDER(RsaKeyFormat::PKCS8, &pubKey);

    // Decode back
    RSAPrivateKey decoded;
    decoded.fromDER(der, RsaKeyFormat::PKCS8);

    EXPECT_EQ(privKey.d, decoded.d);
    EXPECT_EQ(privKey.p, decoded.p);
    EXPECT_EQ(privKey.q, decoded.q);
    EXPECT_EQ(privKey.dP, decoded.dP);
    EXPECT_EQ(privKey.dQ, decoded.dQ);
    EXPECT_EQ(privKey.qInv, decoded.qInv);
}

TEST(RSA_DER_Test, privateKey_PKCS1_roundtrip) {
    RSAPrivateKey privKey(d, p, q);
    RSAPublicKey pubKey(n, e);

    std::vector<uint8_t> der = privKey.toDER(RsaKeyFormat::PKCS1, &pubKey);
    RSAPrivateKey decoded;
    decoded.fromDER(der, RsaKeyFormat::PKCS1);

    EXPECT_EQ(privKey.d, decoded.d);
    EXPECT_EQ(privKey.p, decoded.p);
    EXPECT_EQ(privKey.q, decoded.q);
    EXPECT_EQ(privKey.dP, decoded.dP);
    EXPECT_EQ(privKey.dQ, decoded.dQ);
    EXPECT_EQ(privKey.qInv, decoded.qInv);
}

TEST(RSA_DER_Test, roundTrip_PKCS8) {
    RSAPrivateKey priv(d, p, q, dP, dQ, qInv);
    RSAPublicKey pub(n, e);
    RSAKeyPair rsa(priv, pub);

    // Encode to DER (PKCS8)
    std::vector<uint8_t> der = rsa.toDER(RsaKeyFormat::PKCS8);
    ASSERT_FALSE(der.empty());

    // Decode from DER
    RSAKeyPair rsa2(priv, pub);
    rsa2.fromDER(der, RsaKeyFormat::PKCS8);

    // Check that all components match
    EXPECT_EQ(rsa.getPublicKey().n,  rsa2.getPublicKey().n);
    EXPECT_EQ(rsa.getPublicKey().e,  rsa2.getPublicKey().e);
    EXPECT_EQ(rsa.getPrivateKey().d,  rsa2.getPrivateKey().d);
    EXPECT_EQ(rsa.getPrivateKey().p,  rsa2.getPrivateKey().p);
    EXPECT_EQ(rsa.getPrivateKey().q,  rsa2.getPrivateKey().q);
    EXPECT_EQ(rsa.getPrivateKey().dP, rsa2.getPrivateKey().dP);
    EXPECT_EQ(rsa.getPrivateKey().dQ, rsa2.getPrivateKey().dQ);
    EXPECT_EQ(rsa.getPrivateKey().qInv, rsa2.getPrivateKey().qInv);
}

TEST(RSA_DER_Test, roundTrip_PKCS1) {
    RSAPrivateKey priv(d, p, q, dP, dQ, qInv);
    RSAPublicKey pub(n, e);
    RSAKeyPair rsa(priv, pub);

    // Encode to DER (PKCS1)
    std::vector<uint8_t> der = rsa.toDER(RsaKeyFormat::PKCS1);
    ASSERT_FALSE(der.empty());

    // Decode from DER
    RSAKeyPair rsa2(priv, pub);
    rsa2.fromDER(der, RsaKeyFormat::PKCS1);

    // Check that all components match
    EXPECT_EQ(rsa.getPublicKey().n,  rsa2.getPublicKey().n);
    EXPECT_EQ(rsa.getPublicKey().e,  rsa2.getPublicKey().e);
    EXPECT_EQ(rsa.getPrivateKey().d,  rsa2.getPrivateKey().d);
    EXPECT_EQ(rsa.getPrivateKey().p,  rsa2.getPrivateKey().p);
    EXPECT_EQ(rsa.getPrivateKey().q,  rsa2.getPrivateKey().q);
    EXPECT_EQ(rsa.getPrivateKey().dP, rsa2.getPrivateKey().dP);
    EXPECT_EQ(rsa.getPrivateKey().dQ, rsa2.getPrivateKey().dQ);
    EXPECT_EQ(rsa.getPrivateKey().qInv, rsa2.getPrivateKey().qInv);
}

TEST(RSA_PEM_Test, publicKey_PKCS8_roundtrip) {
    RSAPublicKey pubKey(n, e);

    // Encode to PEM
    std::string pem = pubKey.toPEM(RsaKeyFormat::PKCS8);

    // Decode back
    RSAPublicKey decoded;
    decoded.fromPEM(pem, RsaKeyFormat::PKCS8);

    EXPECT_EQ(pubKey.n, decoded.n);
    EXPECT_EQ(pubKey.e, decoded.e);
}

TEST(RSA_PEM_Test, publicKey_PKCS1_roundtrip) {
    RSAPublicKey pubKey(n, e);

    std::string pem = pubKey.toPEM(RsaKeyFormat::PKCS1);
    RSAPublicKey decoded;
    decoded.fromPEM(pem, RsaKeyFormat::PKCS1);

    EXPECT_EQ(pubKey.n, decoded.n);
    EXPECT_EQ(pubKey.e, decoded.e);
}

TEST(RSA_PEM_Test, privateKey_PKCS8_roundtrip) {
    RSAPrivateKey privKey(d, p, q);
    RSAPublicKey pubKey(n, e);

    std::string pem = privKey.toPEM(RsaKeyFormat::PKCS8, &pubKey);
    RSAPrivateKey decoded;
    decoded.fromPEM(pem, RsaKeyFormat::PKCS8);

    EXPECT_EQ(privKey.d, decoded.d);
    EXPECT_EQ(privKey.p, decoded.p);
    EXPECT_EQ(privKey.q, decoded.q);
    EXPECT_EQ(privKey.dP, decoded.dP);
    EXPECT_EQ(privKey.dQ, decoded.dQ);
    EXPECT_EQ(privKey.qInv, decoded.qInv);
}

TEST(RSA_PEM_Test, privateKey_PKCS1_roundtrip) {
    RSAPrivateKey privKey(d, p, q);
    RSAPublicKey pubKey(n, e);

    std::string pem = privKey.toPEM(RsaKeyFormat::PKCS1, &pubKey);
    RSAPrivateKey decoded;
    decoded.fromPEM(pem, RsaKeyFormat::PKCS1);

    EXPECT_EQ(privKey.d, decoded.d);
    EXPECT_EQ(privKey.p, decoded.p);
    EXPECT_EQ(privKey.q, decoded.q);
    EXPECT_EQ(privKey.dP, decoded.dP);
    EXPECT_EQ(privKey.dQ, decoded.dQ);
    EXPECT_EQ(privKey.qInv, decoded.qInv);
}

TEST(RSA_PEM_Test, roundTrip_PKCS8) {
    RSAPrivateKey priv(d, p, q, dP, dQ, qInv);
    RSAPublicKey pub(n, e);
    RSAKeyPair rsa(priv, pub);

    // Encode to PEM
    std::string pem = rsa.toPEM(RsaKeyFormat::PKCS8);
    ASSERT_FALSE(pem.empty());

    // Decode from PEM
    RSAKeyPair rsa2(priv, pub);
    rsa2.fromPEM(pem, RsaKeyFormat::PKCS8);

    EXPECT_EQ(rsa.getPublicKey().n,  rsa2.getPublicKey().n);
    EXPECT_EQ(rsa.getPublicKey().e,  rsa2.getPublicKey().e);
    EXPECT_EQ(rsa.getPrivateKey().d,  rsa2.getPrivateKey().d);
    EXPECT_EQ(rsa.getPrivateKey().p,  rsa2.getPrivateKey().p);
    EXPECT_EQ(rsa.getPrivateKey().q,  rsa2.getPrivateKey().q);
    EXPECT_EQ(rsa.getPrivateKey().dP, rsa2.getPrivateKey().dP);
    EXPECT_EQ(rsa.getPrivateKey().dQ, rsa2.getPrivateKey().dQ);
    EXPECT_EQ(rsa.getPrivateKey().qInv, rsa2.getPrivateKey().qInv);
}

TEST(RSA_PEM_Test, roundTrip_PKCS1) {
    RSAPrivateKey priv(d, p, q, dP, dQ, qInv);
    RSAPublicKey pub(n, e);
    RSAKeyPair rsa(priv, pub);

    std::string pem = rsa.toPEM(RsaKeyFormat::PKCS1);
    ASSERT_FALSE(pem.empty());

    RSAKeyPair rsa2(priv, pub);
    rsa2.fromPEM(pem, RsaKeyFormat::PKCS1);

    EXPECT_EQ(rsa.getPublicKey().n,  rsa2.getPublicKey().n);
    EXPECT_EQ(rsa.getPublicKey().e,  rsa2.getPublicKey().e);
    EXPECT_EQ(rsa.getPrivateKey().d,  rsa2.getPrivateKey().d);
    EXPECT_EQ(rsa.getPrivateKey().p,  rsa2.getPrivateKey().p);
    EXPECT_EQ(rsa.getPrivateKey().q,  rsa2.getPrivateKey().q);
    EXPECT_EQ(rsa.getPrivateKey().dP, rsa2.getPrivateKey().dP);
    EXPECT_EQ(rsa.getPrivateKey().dQ, rsa2.getPrivateKey().dQ);
    EXPECT_EQ(rsa.getPrivateKey().qInv, rsa2.getPrivateKey().qInv);
}
