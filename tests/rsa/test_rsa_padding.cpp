/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_padding.cpp
 *
 */

#include "gtest/gtest.h"
#include <iostream> // for debugging

//#include <gestalt/rsa.h>
#include "utils.h"
#include "rsa/padding_schemes/rsa_padding.h"
#include "rsa/padding_schemes/oaep/oaep.h"
#include "vectors/vectors_rsa.h"

TEST(RSA_Padding, mgf1) {
    std::string input = "d6e168c5f256a2dcff7ef12facd390f393c7a88d";
    std::string output = mgf1(hexToBytes(input), 256, RSA_ENCRYPTION_HASH_FUNCTIONS::SHA256);
    std::string expected = "0742ba966813af75536bb6149cc44fc256fd64064f0f352bafb940fda7b5e44bdf79665bc31dc5a62f70535e52c53015b9d37d41736de6808d10576cb636a9912ff3c1193439599e1b628774c50d9ccb78d82c42d1ea38aa0c449704071e92a05e4521ee47b8c36a4bcffe8b8112a89312fc044238fed47cebc38a76bdface9a0a39de99223890e74ce10378bc515a212b97b8a6d743cb766fc8d3d66a51546e447ba6a8870278f0262727ca041fa1aa9f7b5d1cb58a05e29076bd0b22d18674f7f308232fe86164eb275553fef2ff2b766d5ab57cd64d5946e19c93b7ab920acb9d6b246b51d9cd04b1e14e10375971b453c3a64db9d7e58c64f92bdeaba673";
    EXPECT_EQ(output, expected);
}

TEST(RSA_Padding, oaep) {
    std::string input = "Hello, Gestalt!";
    OAEPParams parameters = { RSA_ENCRYPTION_HASH_FUNCTIONS::SHA256, MGF1, ""};
    std::string output = applyOAEP_Padding(input, parameters, 256);
    EXPECT_EQ(output.length(), 256);
}

TEST(RSA_Padding, oaep2) {
    std::string input = "Hello, Gestalt!";
    OAEPParams parameters = { RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1, MGF1, ""};
    std::string output = applyOAEP_Padding(input, parameters, 512);
    EXPECT_EQ(output.length(), 512);
}