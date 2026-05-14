/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_aes_cfb.h
 *
 */

 #pragma once
 
 /*
  * Test Vector sources:
  *  [1] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
  *
 */
 
 static const struct AES_CFB_TestVectors {
   std::string name;
   std::string key;
   std::string pt;
   std::string iv;
   std::string ct;
 } kAES_CFB_TestVectors[] = {
    {  // Source [1]
        /* test */ "128",
        /* key  */ "2b7e151628aed2a6abf7158809cf4f3c",
        /* pt   */ "6bc1bee22e409f96e93d7e117393172a",
        /* iv   */ "000102030405060708090a0b0c0d0e0f",
        /* ct   */ "3b3fd92eb72dad20333449f8e83cfb4a"
    },
    {  // Source [1]
        /* test */ "192",
        /* key  */ "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        /* pt   */ "6bc1bee22e409f96e93d7e117393172a",
        /* iv   */ "000102030405060708090a0b0c0d0e0f",
        /* ct   */ "cdc80d6fddf18cab34c25909c99a4174"
    },
    {  // Source [1]
        /* test */ "256",
        /* key  */ "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        /* pt   */ "6bc1bee22e409f96e93d7e117393172a",
        /* iv   */ "000102030405060708090a0b0c0d0e0f",
        /* ct   */ "dc7e84bfda79164b7ecd8486985d3860"
    },
    {  // Source [1] - F.3.13, 4 segments concatenated
        /* test */ "128_multiblock",
        /* key  */ "2b7e151628aed2a6abf7158809cf4f3c",
        /* pt   */ "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        /* iv   */ "000102030405060708090a0b0c0d0e0f",
        /* ct   */ "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"
    },
    {  // Source [1] - F.3.15, 4 segments concatenated
        /* test */ "192_multiblock",
        /* key  */ "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        /* pt   */ "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        /* iv   */ "000102030405060708090a0b0c0d0e0f",
        /* ct   */ "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff"
    },
    {  // Source [1] - F.3.17, 4 segments concatenated
        /* test */ "256_multiblock",
        /* key  */ "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        /* pt   */ "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        /* iv   */ "000102030405060708090a0b0c0d0e0f",
        /* ct   */ "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471"
    }
 };

 std::ostream& operator<<(std::ostream& os, const AES_CFB_TestVectors& test) {
    return os << "Test: " << test.name;
}
 
 // Define a custom name generator function
 inline std::string CustomNameGenerator(const testing::TestParamInfo<AES_CFB_TestVectors>& info) {
     const AES_CFB_TestVectors& test = info.param;
     return test.name;
 }
 class AES_CFB_Test : public testing::TestWithParam<AES_CFB_TestVectors> {};
 
 #include <algorithm>
INSTANTIATE_TEST_SUITE_P(AES_CFB_Encryption, AES_CFB_Test, testing::ValuesIn(kAES_CFB_TestVectors), CustomNameGenerator);
