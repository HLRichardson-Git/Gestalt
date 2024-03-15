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
}