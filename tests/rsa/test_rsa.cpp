/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa.cpp
 *
 */

#include "gtest/gtest.h"
#include <iostream>

#include "utils.h"
#include <gestalt/rsa.h>
#include "vectors/vectors_rsa.h"

TEST(RSA, encrypt) {
    RSA rsa(privateKeyVector, publicKeyVector);
    BigInt computedCiphertext = rsa.encrypt(pt);
    EXPECT_TRUE("0x" + computedCiphertext.toHexString() == ct);
}

TEST(RSA, decrypt) {
    RSA rsa(privateKeyVector, publicKeyVector);
    BigInt computedPlaintext = rsa.decrypt(ct, ENCRYPTION_PADDING_SCHEME::NO_PADDING);
    EXPECT_TRUE("0x" + computedPlaintext.toHexString() == pt);
}

TEST(RSA_Encrypt, encrypt_OAEP) {
    OAEPParams parameters = { RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, MGF1, "", "aafd12f659cae63489b479e5076ddec2f06cb58f" };
    RSA rsa(privateKeyVector1, publicKeyVector1);
    //std::cout << rsa.getPrivateKey().d.toHexString() << std::endl;
    rsa.getPrivateKey().debugCRTComponents();
    std::string input = hexToBytes(pt1);
    std::cout << "hex input2: " << convertToHex(input) << std::endl;
    BigInt computedCiphertext = rsa.encrypt(input, parameters);
    std::cout << "output " << computedCiphertext.toHexString() << std::endl;
    EXPECT_TRUE(computedCiphertext.toHexString() == ct1);
}