/*
 * sha1Tests.cpp
 *
 * This file contains the unit tests for the SHA1 (Secure Hashing Algorithm 1) algorithm implementation.
 * 
 * Author: Hunter L, Richardson
 * Date: 2024-03-17
 */

#include "gtest/gtest.h"

#include <gestalt/sha1.h>
#include "../src/sha1/sha1Core.h"
#include "../tools/utils.h"

#include <string>

testSHA1Functions testSHA1Object;

// Known Answer Test(KAT) for SHA1 from:
// [1] - https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf
// [2] - https://www.di-mgt.com.au/sha_testvectors.html
TEST(testSHA1Hash, hashKatSHA1) {
    // See [1] pg.12 for test vector.
    std::string shortKAT = "abc";
    const std::string expectedShortKAT = "a9993e364706816aba3e25717850c26c9cd0d89d";

    std::string shortDigest = hashSHA1(shortKAT);

    EXPECT_EQ(shortDigest, expectedShortKAT);

    // See [1] pg.15 for test vector.
    std::string longKAT = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const std::string expectedLongKAT = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";

    std::string longDigest = hashSHA1(longKAT);

    EXPECT_EQ(longDigest, expectedLongKAT);

    // See [2] test vector 4.
    std::string longLongKAT = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const std::string expectedLongLongKAT = "a49b2446a02c645bf419f995b67091253a04a259";

    std::string longLongDigest = hashSHA1(longLongKAT);

    EXPECT_EQ(longLongDigest, expectedLongLongKAT);

    // See [2] test vector 2.
    std::string emptyStringKAT = "";
    const std::string expectedEmptyStringKAT = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    std::string emptyStringDigest = hashSHA1(emptyStringKAT);

    EXPECT_EQ(emptyStringDigest, expectedEmptyStringKAT);
}

/*
 * These tests are commented out for your as these tests
 * take a long time to complete. Only run these if you are
 * okay with that.
 *
// Large Known Answer Test(KAT) for SHA1 from:
// [1] - https://www.di-mgt.com.au/sha_testvectors.html
TEST(testLargeSHA1Hash, hashLargeKatSHA1) {

    // Prompt for confirmation before running the test
    std::cout << "Do you want to run the extremely long test? (Y/N): ";
    char confirmation;
    std::cin >> confirmation;
    if (confirmation == 'Y' || confirmation == 'y') {
        // See [2] test vector 5.
        std::string largeSeed = "a"; // repeated 1,000,000 times.
        std::string largeKAT = "";
        const size_t largeRepetitions = 1000000;
        std::cout << "Generating large input" << std::endl;
        for (size_t i = 0; i < largeRepetitions; i++) {
            largeKAT += largeSeed;
        }
        const std::string expectedLargeKAT = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";
        std::cout << "Beginning Hashing large input" << std::endl;
        std::string largeDigest = hashSHA1(largeKAT);
        std::cout << "Completed Hashing large input" << std::endl;
        EXPECT_EQ(largeDigest, expectedLargeKAT);

        // Gestalt cannot yet hash a string larger than 2^32-1 bits.
        // See [2] test vector 6.
        // repeated 16,777,216 times
        std::string extremelyLongSeed = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
        std::string extremelyLongKAT = "";
        const size_t extremelyLongRepetitions = 16777216;
        std::cout << "Generating extremely large input" << std::endl;
        for (size_t i = 0; i < extremelyLongRepetitions; i++) {
            extremelyLongKAT += extremelyLongSeed;
        }
        const std::string expectedExtremelyLongKAT = "7789f0c9ef7bfc40d93311143dfbe69e2017f592";
        std::cout << "Beginning Hashing extremely large input" << std::endl;
        std::string expectedExtremelyLongDigest = hashSHA1(extremelyLongKAT);
        std::cout << "Completed Hashing extremely large input" << std::endl;
        EXPECT_EQ(expectedExtremelyLongDigest, expectedExtremelyLongKAT);
    } else {
        std::cout << "Skipping extremely long test." << std::endl;
    }
}
*/

// Unit test for fillBlock function.
TEST(testSHA1Functions, fillBlock) {
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
    testSHA1Object.testSHA1FillBlock(in, computedW, 0);

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
TEST(testSHA1Padding, paddingKatSHA1) { 
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