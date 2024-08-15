/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_functions.cpp
 *
 */

#include "gtest/gtest.h"

#include "rsa/rsaObjects.h"
#include "vectors/vectors_rsa.h"

const bool skipRSAKeyGen = true; // RSA key gen can take awhile, so set to false if you'd like to test RSA keyGen

TEST(RSA_KeyPair_Test, testKeyGen) {
    if(skipRSAKeyGen) GTEST_SKIP();

    RSAKeyPair rsa;

    RSAPrivateKey privateKey = rsa.getPrivateKey();
    RSAPublicKey publicKey = rsa.getPublicKey();

    EXPECT_TRUE(rsa.validateKeyPair()) << "Generated key pair was invalid";
}

TEST(RSA_KeyPair_Test, testKeyReGen) {
    if(skipRSAKeyGen) GTEST_SKIP();

    RSAKeyPair rsa;

    RSAPrivateKey privateKey1 = rsa.getPrivateKey();
    RSAPublicKey publicKey1 = rsa.getPublicKey();

    rsa.regenerateKeyPair({RSA_SECURITY_STRENGTH::RSA_2048, RANDOM_PRIME_METHOD::probable});

    RSAPrivateKey privateKey2 = rsa.getPrivateKey();
    RSAPublicKey publicKey2 = rsa.getPublicKey();

    EXPECT_FALSE(privateKey1.d == privateKey2.d) << "Both generated private keys are the same";
    EXPECT_FALSE(publicKey1.n == publicKey2.n) << "Both generated public keys are the same";
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