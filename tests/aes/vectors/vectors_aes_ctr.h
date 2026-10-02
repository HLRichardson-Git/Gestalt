/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_aes_ctr.h
 *
 */

 #pragma once
 
 /*
  * Test Vector sources:
  *  [1] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
  *
 */
 
 static const struct AES_CTR_TestVectors {
   std::string name;
   std::string key;
   std::string pt;
   std::string iv;
   std::string ct;
 } kAES_CTR_TestVectors[] = {
    {  // Source [1]
        /* test */ "128",
        /* key  */ "2b7e151628aed2a6abf7158809cf4f3c",
        /* pt   */ "6bc1bee22e409f96e93d7e117393172a",
        /* iv   */ "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        /* ct   */ "874d6191b620e3261bef6864990db6ce"
    },
    {  // Source [1]
        /* test */ "192",
        /* key  */ "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        /* pt   */ "6bc1bee22e409f96e93d7e117393172a",
        /* iv   */ "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        /* ct   */ "1abc932417521ca24f2b0459fe7e6e0b"
    },
    {  // Source [1]
        /* test */ "256",
        /* key  */ "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        /* pt   */ "6bc1bee22e409f96e93d7e117393172a",
        /* iv   */ "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        /* ct   */ "601ec313775789a5b7a7f504bbf3d228"
    }
 };

 std::ostream& operator<<(std::ostream& os, const AES_CTR_TestVectors& test) {
    return os << "Test: " << test.name;
}
 
 // Define a custom name generator function
 inline std::string CustomNameGenerator(const testing::TestParamInfo<AES_CTR_TestVectors>& info) {
     const AES_CTR_TestVectors& test = info.param;
     return test.name;
 }
 class AES_CTR_Test : public testing::TestWithParam<AES_CTR_TestVectors> {};
 
 #include <algorithm>
INSTANTIATE_TEST_SUITE_P(AES_CTR_Encryption, AES_CTR_Test, testing::ValuesIn(kAES_CTR_TestVectors), CustomNameGenerator);
