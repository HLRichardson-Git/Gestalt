/*
 * sha1Tests.cpp
 *
 * This file contains the unit tests for the SHA1 (Secure Hashing Algorithm 1) algorithm implementation.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-02-11
 */

#include "gtest/gtest.h"

#include <gestalt/sha1.h>
#include "../src/sha1/sha1Core.h"
#include "../tools/utils.h"

#include <string>

testSHA1Functions testSHA1Object;

// Known Answer Test(KAT) for SHA1 Padding from https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf
TEST(testSHA1Padding, paddingKatSHA1)
{
    SHA1 SHA1Object;
    
    // See pg.12 for test vector.
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "61626380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018";

    testSHA1Object.testSHA1Padding(shortKAT);
    
    EXPECT_EQ(convertToHex(shortKAT), expectedShortKAT);

    // See pg.15 for test vector.
    std::string longKAT = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const std::string expectedLongKAT = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70718000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0";

    testSHA1Object.testSHA1Padding(longKAT);

    EXPECT_EQ(convertToHex(longKAT), expectedLongKAT);

    std::string longLongKAT = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const std::string expectedLongLongKAT = "61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f70717273747580000000000000000000000000000380";

    testSHA1Object.testSHA1Padding(longLongKAT);

    EXPECT_EQ(convertToHex(longLongKAT), expectedLongLongKAT);

    std::string emptyStringKAT = "";
    const std::string expectedEmptyStringKAT = "80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    testSHA1Object.testSHA1Padding(emptyStringKAT);

    EXPECT_EQ(convertToHex(emptyStringKAT), expectedEmptyStringKAT);
}