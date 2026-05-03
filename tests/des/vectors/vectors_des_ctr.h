/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * vectors_des_ctr.h
 *
 */

 #pragma once
 
 static const struct DES_CTR_TestVectors {
   std::string name;
   std::string key;
   std::string pt;
   std::string iv;
   std::string ct;
 } kDES_CTR_TestVectors[] = {
    {  
        /* test */ "single",
        /* key  */ "0133457799bbcdff",
        /* pt   */ "6bc1bee22e409f966bc1bee22e409f96",
        /* iv   */ "f0f1f2f3f4f5f6f7",
        /* ct   */ "c11054c29df56e427cb0bfa068dcd4a7"
    },
 };

 std::ostream& operator<<(std::ostream& os, const DES_CTR_TestVectors& test) {
    return os << "Test: " << test.name;
}
 
 // Define a custom name generator function
 inline std::string CustomNameGenerator(const testing::TestParamInfo<DES_CTR_TestVectors>& info) {
     const DES_CTR_TestVectors& test = info.param;
     return test.name;
 }
 class DES_CTR_Test : public testing::TestWithParam<DES_CTR_TestVectors> {};
 
 #include <algorithm>
INSTANTIATE_TEST_SUITE_P(DES_CTR_Encryption, DES_CTR_Test, testing::ValuesIn(kDES_CTR_TestVectors), CustomNameGenerator);
