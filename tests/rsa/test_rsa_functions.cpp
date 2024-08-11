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

class RSA_Test : public ::testing::Test {
private:
    RSAKeyPair rsa;
protected:
    void getSeed(RSA_SECURITY_STRENGTH securityStrength, mpz_t& result) { rsa.getSeed(securityStrength, result); }
};

TEST_F(RSA_Test, testGetSeed) {
    mpz_t seed;
    mpz_init(seed);

    getSeed(RSA_SECURITY_STRENGTH::bits_3072, seed);

    int seedBitLength = mpz_sizeinbase(seed, 2);
    EXPECT_EQ(seedBitLength, 256);  // 2 * 128 bits (security strength of 3072-bit modulus)

    mpz_clear(seed);
}