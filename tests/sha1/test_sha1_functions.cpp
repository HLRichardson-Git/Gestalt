/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_sha1.cpp
 *
 * This file contains the unit tests for the SHA1 (Secure Hashing Algorithm 1) algorithm implementation.
 */

#include "gtest/gtest.h"
#include <string>

#include <gestalt/sha1.h>
#include "sha1/sha1Core.h"
#include "utils.h"

class SHA1_Test : public ::testing::Test {
private:

    static const unsigned int BLOCK_SIZE = 80;
    SHA1 SHA1Object;
public:

    void testSHA1FillBlock(std::string in, uint32_t computedW[BLOCK_SIZE]) {
        SHA1Object.applySha1Padding(in);
        this->SHA1Object.fillBlock(in, computedW);
    }
    void testSHA1Padding(std::string& in){
        this->SHA1Object.applySha1Padding(in);
    }
};

// Unit test for fillBlock function.
TEST_F(SHA1_Test, fillBlock) {
    std::string in = "abc";
    uint32_t expectedW[80] = {
        0x61626380, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000018, 
        0xc2c4c700, 0x00000000, 0x00000030, 0x85898e01, 0x00000000, 0x00000060, 0x0b131c03, 0x00000030, 
        0x85898ec1, 0x16263806, 0x00000000, 0x00000180, 0x2c4c700c, 0x000000f0, 0x93afb507, 0x5898e048, 
        0x8e9a9202, 0x00000600, 0xb131c0f0, 0x16263bc6, 0x4ebed41e, 0x626380a1, 0x16263806, 0x000018c0, 
        0xd2e138c4, 0x00000f00, 0x3afb5079, 0x898e04e5, 0xe2ba3c2b, 0x000060c0, 0x053a37cd, 0x74458547, 
        0xda9415ed, 0x26380a16, 0x626383a1, 0x4ebf54de, 0x3835b44b, 0x0000f600, 0x1e84c7a3, 0x98e04d98, 
        0x651d16a0, 0x62658ca1, 0x458544d6, 0x44584cb7, 0x7ba06619, 0x6380aea2, 0x0ae55269, 0x627b49a1, 
        0x7cd45c9d, 0x000f0000, 0xfb50753a, 0xec6765e8, 0xba3c2be2, 0x0060c000, 0x3a37cd05, 0x458546f4, 
        0xb8599dd6, 0x380a1a26, 0x01e02203, 0xe7cc3456, 0xe6e60b69, 0x00f60a00, 0x5795ef4f, 0x822e0879 };

    uint32_t computedW[80]; // Array to store computed values
    testSHA1FillBlock(in, computedW);

    bool arraysEqual = true;
    for (int i = 0; i < 80; i++) {
        if (computedW[i] != expectedW[i]) {
            std::cout << "Computed W: " << computedW[i] << " At: " << i << std::endl;
            std::cout << "Expected W: " << expectedW[i] << " At: " << i << std::endl;
            arraysEqual = false;
        }
    }


    EXPECT_EQ(arraysEqual, 1);
}

// Known Answer Test(KAT) for SHA1 Padding from https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf
TEST_F(SHA1_Test, paddingKatSHA1) { 
    // See pg.12 for test vector.
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = 
        "6162638000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000018";

    testSHA1Padding(shortKAT);
    
    EXPECT_EQ(convertToHex(shortKAT), expectedShortKAT);

    // See pg.15 for test vector.
    std::string longKAT = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const std::string expectedLongKAT = 
        "6162636462636465636465666465666765666768666768696768696a68696a6b"
        "696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70718000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000001c0";

    testSHA1Padding(longKAT);

    EXPECT_EQ(convertToHex(longKAT), expectedLongKAT);

    std::string longLongKAT = 
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const std::string expectedLongLongKAT = 
        "61626364656667686263646566676869636465666768696a6465666768696a6b"
        "65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f"
        "696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f70717273"
        "6d6e6f70717273746e6f70717273747580000000000000000000000000000380";

    testSHA1Padding(longLongKAT);

    EXPECT_EQ(convertToHex(longLongKAT), expectedLongLongKAT);

    std::string emptyStringKAT = "";
    const std::string expectedEmptyStringKAT = 
        "8000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000";

    testSHA1Padding(emptyStringKAT);

    EXPECT_EQ(convertToHex(emptyStringKAT), expectedEmptyStringKAT);
}