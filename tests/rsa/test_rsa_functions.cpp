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
    void generateKeyPair(RSAKeyGenOptions options) { rsa.generateKeyPair(options); }
};

TEST(RSA_Test, testKeyGen) {
    RSAKeyPair rsa({RSA_SECURITY_STRENGTH::RSA_2048, RANDOM_PRIME_METHOD::probable});

    RSAPrivateKey privateKey = rsa.getPrivateKey();
    RSAPublicKey publicKey = rsa.getPublicKey();

    unsigned int expected_bit_length = 2048;
    unsigned int n_bit_length = mpz_sizeinbase(publicKey.n.n, 2);
    ASSERT_GE(n_bit_length, expected_bit_length - 1) << "Public modulus n has an incorrect bit length";
    ASSERT_LE(n_bit_length, expected_bit_length) << "Public modulus n exceeds the expected bit length";

    unsigned int d_bit_length = mpz_sizeinbase(privateKey.d.n, 2);
    ASSERT_LE(d_bit_length, n_bit_length) << "Private exponent d has a bit length greater than n";
}