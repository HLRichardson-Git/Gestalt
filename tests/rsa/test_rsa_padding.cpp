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
    std::string output = mgf1(hexToBytes(input), 256, RSA_HASH_FUNCTIONS::SHA256);
    std::string expected = "0742ba966813af75536bb6149cc44fc256fd64064f0f352bafb940fda7b5e44bdf79665bc31dc5a62f70535e52c53015b9d37d41736de6808d10576cb636a9912ff3c1193439599e1b628774c50d9ccb78d82c42d1ea38aa0c449704071e92a05e4521ee47b8c36a4bcffe8b8112a89312fc044238fed47cebc38a76bdface9a0a39de99223890e74ce10378bc515a212b97b8a6d743cb766fc8d3d66a51546e447ba6a8870278f0262727ca041fa1aa9f7b5d1cb58a05e29076bd0b22d18674f7f308232fe86164eb275553fef2ff2b766d5ab57cd64d5946e19c93b7ab920acb9d6b246b51d9cd04b1e14e10375971b453c3a64db9d7e58c64f92bdeaba673";
    EXPECT_EQ(output, expected);
}

TEST(RSA_Padding, oaep) {
    std::string input = "Hello, Gestalt!";
    OAEPParams parameters = { RSA_HASH_FUNCTIONS::SHA256, MGF1, ""};
    std::string output = applyOAEP_Padding(input, parameters, 256);
    EXPECT_EQ(output.length(), 256);
}

TEST(RSA_Padding, oaep2) {
    std::string input = "Hello, Gestalt!";
    OAEPParams parameters = { RSA_HASH_FUNCTIONS::SHA1, MGF1, "", "aafd12f659cae63489b479e5076ddec2f06cb58f"};
    std::string output = applyOAEP_Padding(input, parameters, 512);
    EXPECT_EQ(output.length(), 512);
}

TEST(RSA_Remove_Padding, removeOaep) {
    std::string input = "0094bb1acb6d6afeb3ea24ebf89dbe86e57bc25180dcd87d5c68f1eea8f55267c31b2e8bb4251f84d7e0b2c04626f5aff93edcfb25c9c2b3ff8ae10e839a2ddb4cdcfe4ff47728b4a1b7c1362baad29ab48d2869d5024121435811591be392f982fb3e87d095aeb40448db972f3ac14eaff49c8c3b7cfc951a51ecd1dde6126444090df10ac69ea81cc59af486bd90d15946463f31b2feba76b2e26b34b81578e8b170b55e156daa4602e5eea0ded2f10f9d8b8fcc310dc53077586fb9b0dfa330fc4002a7b7252e3ac51dab47b9205c5d950ddf4fec864e5a1c4e3410d2a89e211bcbf003f72698b6cf13cef257939e971a2341d9661552d8e7a7efdf2ef36a88f336a0e6d66bc261bd7748bc9ad834122ec5147a411fcaa20204d6a9540bf79c6c0b5cf1c5928bb114b729b3b895737262d4ed9e60526878cf7ee78841cf9d5c4db24d99912caac7782255a6c0cc5adfd63485562d131912ec9614a7aa388ab3d4100d89a84365acca5467cb07cc80a2d1ab32ff119b6f5968987f2d61967596375364e860d5e52c2c551464a68a87ad7173a042c2e5c1eb82c1ad94fc020fa7e771ff51e5a14b195d5ebf419d92e86068707c24f3687ffbec326d7a5333f936aec4ee9311d69e5d8b0afdb549a096590086383d59c3aacecf28e14c37d5ba692fa16e3d0af43c70bf4397c37ca892b32557363acf2b293718edb7b1094ba5";
    OAEPParams parameters = { RSA_HASH_FUNCTIONS::SHA1, MGF1, ""};
    std::string output = removeOAEP_Padding(hexToBytes(input), parameters, 512);
    EXPECT_EQ(output, "Hello, Gestalt!");
}