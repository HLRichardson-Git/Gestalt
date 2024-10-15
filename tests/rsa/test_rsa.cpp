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
//#include "vectors/vectors_rsa.h"
#include "vectors/vectors_rsa_oaep.h"

static std::string pt = "0x102030405060708090a0b0c0d0e0f";
static std::string ct = "0x2eab1c8d5315c5094fcc5ed524c312f5bb30bc8516f080f3f10a8d5bb4031e316087d5a0357cd13a0064a5b53df9d9cb39b2ae0835b7c1dac78c06302fdd2a85fa488534ddde50afff6563d9803dacac3716f9005151869717f2aa7da76b5b33acf6185aebe7e2c97cc408cb9a8a7e6293445ed18af827c40fc983397f4564e03d59f0d1e1032d911e551e3bad62b01afa27dd62375d4e8faeea83ebf4a7ac5908c7bc0b95b707753f69de0720d2009c905719035138af5ad14a999226505132e1b6187e5183e01393b3bc14506c6bdcb3475f3e5fe0a250c3979196767ea32bc049e72bb536cf69df9516e412d363ac7c8a4f086d382e96ef7f95a735f2cdfd";


TEST(RSA, encrypt) {
    RSA rsa(RSA_SECURITY_STRENGTH::RSA_2048, privateKeyVector, publicKeyVector);
    BigInt computedCiphertext = rsa.encrypt(pt, publicKeyVector);
    EXPECT_TRUE("0x" + computedCiphertext.toHexString() == ct);
}

TEST(RSA, decrypt) {
    RSA rsa(RSA_SECURITY_STRENGTH::RSA_2048, privateKeyVector, publicKeyVector);
    BigInt computedPlaintext = rsa.decrypt(ct, ENCRYPTION_PADDING_SCHEME::NO_PADDING);
    EXPECT_TRUE("0x" + computedPlaintext.toHexString() == pt);
}
/*
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

TEST(RSA_Encrypt, encrypt_OAEP2) {
    OAEPParams parameters = { RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, MGF1, "", "47e1ab7119fee56c95ee5eaad86f40d0aa63bd33" };
    RSA rsa(privateKeyVector2, publicKeyVector2);
    //std::cout << rsa.getPrivateKey().d.toHexString() << std::endl;
    rsa.getPrivateKey().debugCRTComponents();
    std::string input = hexToBytes(pt2);
    std::cout << "hex input2: " << convertToHex(input) << std::endl;
    BigInt computedCiphertext = rsa.encrypt(input, parameters);
    std::cout << "output " << computedCiphertext.toHexString() << std::endl;
    EXPECT_TRUE(computedCiphertext.toHexString() == ct2);
}
*/
TEST_P(RSA_OAEP_Test, encrypt) {
    const RSA_OAEP_TestVectors &test = GetParam();
    SCOPED_TRACE(test.name);

    RSA rsa(test.keySecurityStrength, test.privateKey, test.publicKey);
    BigInt computedCiphertext = rsa.encrypt(hexToBytes(test.pt), test.publicKey, test.parameters);
    std::string output = computedCiphertext.toHexString();
    std::cout << "Output: " << output << std::endl;

    EXPECT_TRUE(output == test.ct);
}