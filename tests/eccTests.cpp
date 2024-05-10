/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * eccTests.cpp
 */

#include "ecc/ecc.h"

#include "gtest/gtest.h"
#include <string>
#include <iostream>
#include <sstream>
#include <tuple>

class TestECC : public ::testing::Test {
private:
    ECC ecc;
protected:
    Point addPoints(Point P, Point Q) {return ecc.addPoints(P, Q);};
    Point doublePoint(Point P) {return ecc.doublePoint(P);};
    Point scalarMultiplyPoints(const mpz_t& k, Point P) {return ecc.scalarMultiplyPoints(k, P);};
};

TEST_F(TestECC, testPointAddition)
{
    Point P("0x1a9b50177520875bf4bdeea006703f39066bf2126a0e19695639ebd71d27890e", 
            "0x4db72d506fb060bca6b2fd5d5806d65e00b675d146cf3f89d93941612bf8dcb9");
    Point Q("0xd901df95be82c8953b83e569b9b63b0b52e6ee9a2e6fc400e852090e3f6fec69", 
            "0x99a666ff41bf66483e1fd92960b931df1effeb4465673c52cc011e4a0a803df3");

    Point R = addPoints(P, Q);

    Point expected("0x3be0eb288273201f90f975710f08f41076dd79587499283ad471f2f33a03c81", 
                   "0x328a64c3e38dc5e5b1734b91fae70425703c74e400d1740389a8424280d915b3");

    EXPECT_TRUE(mpz_cmp(R.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(R.y, expected.y) == 0);
}

TEST_F(TestECC, testPointDouble)
{
    Point P("0x1a9b50177520875bf4bdeea006703f39066bf2126a0e19695639ebd71d27890e", 
            "0x4db72d506fb060bca6b2fd5d5806d65e00b675d146cf3f89d93941612bf8dcb9");

    Point R = doublePoint(P);

    Point expected("0x102effa403b27f4252a0c8d52522a54812b78646638e1e4ef9dcaf725c587f95", 
                   "0x8a556d2f948557616ed4b3360fa83f2fe43815a80375c2f8f35d5c0e94467750");

    EXPECT_TRUE(mpz_cmp(R.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(R.y, expected.y) == 0);
}

TEST_F(TestECC, testPointMultiplication)
{
    Point P("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 
            "0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2");

    BigInt N("0x8");

    Point R = scalarMultiplyPoints(N.n, P);

    Point expected("0x86a5ee3b95e14201a8dc231aedbf5b0c48b31d2f1e6ccee090a8d798dd37e896", 
                   "0x4c571310c823401a22185452f49473f315757896ac032cfcbdbc15b0cd74a422");

    EXPECT_TRUE(mpz_cmp(R.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(R.y, expected.y) == 0);
}

TEST(TestECC_Objects, BigIntInitialization)
{
    // Check Hexidecimal value initialization
    BigInt P("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577");

    BigInt N = "0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577";

    EXPECT_TRUE(mpz_cmp(P.n, N.n) == 0);

    // Check decimal value initialization
    BigInt Q = "60903095697897716130768633358908066527972563868462147701232486991401305237654";

    N = "60903095697897716130768633358908066527972563868462147701232486991401305237654";

    EXPECT_TRUE(mpz_cmp(Q.n, N.n) == 0);

    // Make sure P != Q
    EXPECT_TRUE(mpz_cmp(P.n, Q.n) != 0);

    // Check proper NULL initialization
    BigInt T;
    mpz_t t;
    mpz_init(t);

    EXPECT_TRUE(mpz_cmp(T.n, t) == 0);
    EXPECT_TRUE(mpz_cmp(T.n, t) == 0);

    mpz_clears(t, NULL);
}

TEST(TestECC_Objects, BigIntAssignmentOperator)
{
    BigInt P("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577");

    BigInt Q = P;

    EXPECT_TRUE(mpz_cmp(P.n, Q.n) == 0);
    EXPECT_TRUE(mpz_cmp(P.n, Q.n) == 0);
}

TEST(TestECC_Objects, PointInitialization)
{
    // Check Hexidecimal value initialization
    Point P("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 
            "0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2");

    mpz_t x, y;
    mpz_init_set_str(x, "9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 16);
    mpz_init_set_str(y, "ed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2", 16);

    EXPECT_TRUE(mpz_cmp(P.x, x) == 0);
    EXPECT_TRUE(mpz_cmp(P.y, y) == 0);

    // Check decimal value initialization
    Point Q("60903095697897716130768633358908066527972563868462147701232486991401305237654", 
            "34529623772580660154832064486849267429105394335284591488752759902855262151714");

    mpz_set_str(x, "60903095697897716130768633358908066527972563868462147701232486991401305237654", 10);
    mpz_set_str(y, "34529623772580660154832064486849267429105394335284591488752759902855262151714", 10);

    EXPECT_TRUE(mpz_cmp(Q.x, x) == 0);
    EXPECT_TRUE(mpz_cmp(Q.y, y) == 0);

    // Make sure P != Q
    EXPECT_TRUE(mpz_cmp(P.x, Q.x) != 0);
    EXPECT_TRUE(mpz_cmp(P.y, Q.y) != 0);

    // Check proper NULL initialization
    Point T;
    mpz_t n;
    mpz_init(n);

    EXPECT_TRUE(mpz_cmp(T.x, n) == 0);
    EXPECT_TRUE(mpz_cmp(T.y, n) == 0);

    mpz_clears(x, y, n, NULL);
}

TEST(TestECC_Objects, PointAssignmentOperator)
{
    Point P("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 
            "0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2");

    Point Q = P;

    EXPECT_TRUE(mpz_cmp(P.x, Q.x) == 0);
    EXPECT_TRUE(mpz_cmp(P.y, Q.y) == 0);
}

TEST(TestECC_Objects, KeyPairInitialization)
{
    // Check Hexidecimal value initialization
    Point publicKey1("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE", 
                    "0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD");
    KeyPair P("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464", publicKey1);

    mpz_t priv, x, y;
    mpz_init_set_str(priv, "519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464", 16);
    mpz_init_set_str(x, "CEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE", 16);
    mpz_init_set_str(y, "EFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD", 16);

    EXPECT_TRUE(mpz_cmp(P.privateKey, priv) == 0);
    EXPECT_TRUE(mpz_cmp(P.publicKey.x, x) == 0);
    EXPECT_TRUE(mpz_cmp(P.publicKey.y, y) == 0);

    // Check decimal value initialization
    Point publicKey2("41508913618560943505682868066484155222795806420711968987006339848963526306366", 
                    "47779048823291371033741797327759287667537405354646831765410899091079836405219");
    KeyPair Q("10528738585638442885886470026673783468944086105714080698941011408558582127129", publicKey2);

    mpz_set_str(priv, "10528738585638442885886470026673783468944086105714080698941011408558582127129", 10);
    mpz_set_str(x,    "41508913618560943505682868066484155222795806420711968987006339848963526306366", 10);
    mpz_set_str(y,    "47779048823291371033741797327759287667537405354646831765410899091079836405219", 10);

    EXPECT_TRUE(mpz_cmp(Q.privateKey, priv) == 0);
    EXPECT_TRUE(mpz_cmp(Q.publicKey.x, x) == 0);
    EXPECT_TRUE(mpz_cmp(Q.publicKey.y, y) == 0);

    // Make sure keyPair1 != keyPair2
    EXPECT_TRUE(mpz_cmp(P.publicKey.x, Q.publicKey.x) != 0);
    EXPECT_TRUE(mpz_cmp(P.publicKey.y, Q.publicKey.y) != 0);

    // Check proper NULL initialization
    KeyPair T;
    mpz_t n;
    mpz_init(n);

    EXPECT_TRUE(mpz_cmp(T.privateKey, n) == 0);
    EXPECT_TRUE(mpz_cmp(T.publicKey.x, n) == 0);
    EXPECT_TRUE(mpz_cmp(T.publicKey.y, n) == 0);

    mpz_clears(x, y, n, NULL);
}

TEST(TestECC_Objects, KeyPairAssignmentOperator)
{
    Point publicKey("0xCEC028EE08D09E02672A68310814354F9EABFFF0DE6DACC1CD3A774496076AE", 
                    "0xEFF471FBA0409897B6A48E8801AD12F95D0009B753CF8F51C128BF6B0BD27FBD");
    KeyPair P("0x519B423D715F8B581F4FA8EE59F4771A5B44C8130B4E3EACCA54A56DDA72B464", publicKey);

    KeyPair Q = P;

    EXPECT_TRUE(mpz_cmp(P.privateKey, Q.privateKey) == 0);
    EXPECT_TRUE(mpz_cmp(P.publicKey.x, Q.publicKey.x) == 0);
    EXPECT_TRUE(mpz_cmp(P.publicKey.y, Q.publicKey.y) == 0);
}

TEST(TestECC_Objects, SignatureInitialization)
{
    // Check Hexidecimal value initialization
    Signature P("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 
                "0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2");

    mpz_t r, s;
    mpz_init_set_str(r, "9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 16);
    mpz_init_set_str(s, "ed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2", 16);

    EXPECT_TRUE(mpz_cmp(P.r, r) == 0);
    EXPECT_TRUE(mpz_cmp(P.s, s) == 0);

    // Check decimal value initialization
    Signature Q("82423284279682547824030103895721849412830885604189378105816723310541529430329", 
                "35263610418498196156348668935316331728327496388338009892027000938310937883631");

    mpz_set_str(r, "82423284279682547824030103895721849412830885604189378105816723310541529430329", 10);
    mpz_set_str(s, "35263610418498196156348668935316331728327496388338009892027000938310937883631", 10);

    EXPECT_TRUE(mpz_cmp(Q.r, r) == 0);
    EXPECT_TRUE(mpz_cmp(Q.s, s) == 0);

    // Make sure P != Q
    EXPECT_TRUE(mpz_cmp(P.r, Q.r) != 0);
    EXPECT_TRUE(mpz_cmp(P.s, Q.s) != 0);

    // Check proper NULL initialization
    Signature T;
    mpz_t n;
    mpz_init(n);

    EXPECT_TRUE(mpz_cmp(T.r, n) == 0);
    EXPECT_TRUE(mpz_cmp(T.s, n) == 0);

    mpz_clears(r, s, n, NULL);
}

TEST(TestECC_Objects, SignatureAssignmentOperator)
{
    Signature P("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 
                "0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2");

    Signature Q = P;

    EXPECT_TRUE(mpz_cmp(P.r, Q.r) == 0);
    EXPECT_TRUE(mpz_cmp(P.s, Q.s) == 0);
}