/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_tdes_ctr.h
 *
 */

 #pragma once
 
 static const struct TDES_CTR_TestVectors {
   std::string name;
   std::string key1;
   std::string key2;
   std::string key3;
   std::string pt;
   std::string iv;
   std::string ct;
 } kTDES_CTR_TestVectors[] = {
    {  
        /* test */ "triple",
        /* key1 */ "752878397493cb70",
        /* key2 */ "10316e028c8f3b4a",
        /* key3 */ "7ca110454a1a6e57",
        /* pt   */ "6bc1bee22e409f966bc1bee22e409f96",
        /* iv   */ "f0f1f2f3f4f5f6f7",
        /* ct   */ "ce4c726dff9ba6e4c8723d05e54b0391"
    },
 };

 std::ostream& operator<<(std::ostream& os, const TDES_CTR_TestVectors& test) {
    return os << "Test: " << test.name;
}
 
 // Define a custom name generator function
 inline std::string CustomNameGenerator(const testing::TestParamInfo<TDES_CTR_TestVectors>& info) {
     const TDES_CTR_TestVectors& test = info.param;
     return test.name;
 }
 class TDES_CTR_Test : public testing::TestWithParam<TDES_CTR_TestVectors> {};
 
 #include <algorithm>
INSTANTIATE_TEST_SUITE_P(TDES_CTR_Encryption, TDES_CTR_Test, testing::ValuesIn(kTDES_CTR_TestVectors), CustomNameGenerator);
