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

TEST(TestECC_Arithmetic, testPointAddition)
{
    ECC ecc(StandardCurve::P256);

    // Set point P & Q
    Point P("67228059374187986264907871817984995299114694677537144137068659840319595636958", 
            "36911659202040455512047859400253132650624032136469391266733306307680092206180");
    Point Q("79584758605949253762341734104702304948499678541099118250653347730022630682716", 
            "82005680352103069544532681048882113537922206207710011425498220375837764433226");

    // Perform point addition
    Point R = ecc.addPoints(P, Q);

    // Set expected point
    Point expected("16247106453250244225622460159038600432635777869376973139750787284798796257055", 
                   "84741935852476448650405200364169101653520738128916381383119006842903426464819");

    // Compare the points
    EXPECT_TRUE(mpz_cmp(R.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(R.y, expected.y) == 0);
}

TEST(TestECC_Arithmetic, testPointDouble)
{
    ECC ecc(StandardCurve::P256);
    
    // Set point P
    Point P("16247106453250244225622460159038600432635777869376973139750787284798796257055", 
            "84741935852476448650405200364169101653520738128916381383119006842903426464819");

    Point R = ecc.doublePoint(P);

    // Set expected point
    Point expected("94661065609916795805170830853666726936855561355503933991787557860394254628829", 
                   "22871027890686529937969966456841486853953364797665548725333072814274627436453");
    
    // Compare the points
    EXPECT_TRUE(mpz_cmp(R.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(R.y, expected.y) == 0);
}

TEST(TestECC_Arithmetic, testPointMultiplication)
{
    ECC ecc(StandardCurve::secp256k1);

    // Set point P
    Point P("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 
            "0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2");

    // Set scalar value
    mpz_t n;
    mpz_init_set_str(n, "8", 16);

    Point R = ecc.scalarMultiplyPoints(n, P);

    mpz_clear(n); // Clean Up

    // Set expected Point
    Point expected("0x86a5ee3b95e14201a8dc231aedbf5b0c48b31d2f1e6ccee090a8d798dd37e896", 
                   "0x4c571310c823401a22185452f49473f315757896ac032cfcbdbc15b0cd74a422");

    // Compare the points
    EXPECT_TRUE(mpz_cmp(R.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(R.y, expected.y) == 0);
}

TEST(TestECC_Objects, PointInitialization)
{
    // Check Heexidecimal value initialization
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

    mpz_clears(x, y, n, NULL); // Clean Up
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
    // Check Heexidecimal value initialization
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

    mpz_clears(x, y, n, NULL); // Clean Up
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
    // Check Heexidecimal value initialization
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

    mpz_clears(r, s, n, NULL); // Clean Up
}

TEST(TestECC_Objects, SignatureAssignmentOperator)
{
    Signature P("0x9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 
                "0xed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2");

    Signature Q = P;

    EXPECT_TRUE(mpz_cmp(P.r, Q.r) == 0);
    EXPECT_TRUE(mpz_cmp(P.s, Q.s) == 0);
}