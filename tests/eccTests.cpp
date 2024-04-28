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

    // Initialize and set point P
    Point P;
    mpz_init_set_str(P.x, "67228059374187986264907871817984995299114694677537144137068659840319595636958", 10);
    mpz_init_set_str(P.y, "36911659202040455512047859400253132650624032136469391266733306307680092206180", 10);

    // Initialize and set point Q
    Point Q;
    mpz_init_set_str(Q.x, "79584758605949253762341734104702304948499678541099118250653347730022630682716", 10);
    mpz_init_set_str(Q.y, "82005680352103069544532681048882113537922206207710011425498220375837764433226", 10);

    // Perform point addition
    Point R = ecc.addPoints(P, Q);

    // Initialize and set expected point
    Point expected;
    mpz_init_set_str(expected.x, "16247106453250244225622460159038600432635777869376973139750787284798796257055", 10);
    mpz_init_set_str(expected.y, "84741935852476448650405200364169101653520738128916381383119006842903426464819", 10);
    
    // Compare the point coordinates
    EXPECT_TRUE(mpz_cmp(R.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(R.y, expected.y) == 0);

    // Clear memory
    mpz_clear(P.x);
    mpz_clear(P.y);
    mpz_clear(Q.x);
    mpz_clear(Q.y);
    mpz_clear(R.x);
    mpz_clear(R.y);
    mpz_clear(expected.x);
    mpz_clear(expected.y);

    /*ECC ecc(StandardCurve::P256);

    Point P = {"67228059374187986264907871817984995299114694677537144137068659840319595636958",
               "36911659202040455512047859400253132650624032136469391266733306307680092206180"};
    Point Q = {"79584758605949253762341734104702304948499678541099118250653347730022630682716", 
               "82005680352103069544532681048882113537922206207710011425498220375837764433226"};

    Point R = ecc.addPoints(P, Q);

    Point expected = {"16247106453250244225622460159038600432635777869376973139750787284798796257055",
                      "84741935852476448650405200364169101653520738128916381383119006842903426464819"};
    
    EXPECT_EQ(R.x, expected.x);
    EXPECT_EQ(R.y, expected.y);*/
}

TEST(TestECC_Arithmetic, testPointDoulbe)
{
    ECC ecc(StandardCurve::P256);

    //mpz_t x, y;
    //mpz_inits(x, y, NULL);
    //mpz_set_str(x, "16247106453250244225622460159038600432635777869376973139750787284798796257055", 10);
    //mpz_set_str(y, "84741935852476448650405200364169101653520738128916381383119006842903426464819", 10);

    Point P;
    mpz_init_set_str(P.x, "16247106453250244225622460159038600432635777869376973139750787284798796257055", 10);
    mpz_init_set_str(P.y, "84741935852476448650405200364169101653520738128916381383119006842903426464819", 10);

    Point R = ecc.doublePoint(P);
    //Point R;

    Point expected;
    mpz_init_set_str(expected.x, "94661065609916795805170830853666726936855561355503933991787557860394254628829", 10);
    mpz_init_set_str(expected.y, "22871027890686529937969966456841486853953364797665548725333072814274627436453", 10);
    
    EXPECT_TRUE(mpz_cmp(R.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(R.y, expected.y) == 0);

    mpz_clears(P.x, P.y, expected.x, expected.y, NULL);

    /*ECC ecc(StandardCurve::P256);

    Point P = {"16247106453250244225622460159038600432635777869376973139750787284798796257055",
               "84741935852476448650405200364169101653520738128916381383119006842903426464819"};

    Point R = ecc.doublePoint(P);

    Point expected = {"94661065609916795805170830853666726936855561355503933991787557860394254628829",
                      "22871027890686529937969966456841486853953364797665548725333072814274627436453"};
    
    EXPECT_EQ(R.x, expected.x);
    EXPECT_EQ(R.y, expected.y);*/
}

TEST(TestECC_Arithmetic, testPointMultiplication)
{
    ECC ecc(StandardCurve::secp256k1);

    Point P;
    //mpz_init_set_str(P.x, "88764801008590816877766665490322569426078893736160224298871996999069541569081", 10);
    //mpz_init_set_str(P.y, "64549562702257555313735637722402300165514114834696882062669884644749455809738", 10);
    mpz_init_set_str(P.x, "9f43093f2741d67bae528e5ee34de5175a0fdc9bd95945423980c07edab9a577", 16);
    mpz_init_set_str(P.y, "ed9bfdb22f5c2d9dbd47e420948e55e0a23412479f56492afd194f3b648ae9b2", 16);

    mpz_t n;
    mpz_init_set_str(n, "8", 16);

    Point R = ecc.scalarMultiplyPoints(n, P);

    Point expected;
    //mpz_init_set_str(expected.x, "580578379796884640291629975597379928185276275272807587279982663300338316316", 10);
    //mpz_init_set_str(expected.y, "36453294428164904118977036101609216276810108334259481990292799215351578729756", 10);
    //mpz_init_set_str(expected.x, "aca7bf3956cdc40b439adc6362badc096348b3c0a70a2116ee1e5269563f05f3", 16);
    //mpz_init_set_str(expected.y, "ff7528d9211fd687c106a047e94a4599243b85d317ef9acc444cf7539712d55e", 16);
    mpz_init_set_str(expected.x, "86a5ee3b95e14201a8dc231aedbf5b0c48b31d2f1e6ccee090a8d798dd37e896", 16);
    mpz_init_set_str(expected.y, "4c571310c823401a22185452f49473f315757896ac032cfcbdbc15b0cd74a422", 16);

    EXPECT_TRUE(mpz_cmp(R.x, expected.x) == 0);
    EXPECT_TRUE(mpz_cmp(R.y, expected.y) == 0);

    mpz_clears(P.x, P.y, expected.x, expected.y, NULL);

    /*ECC ecc(StandardCurve::secp256k1);

    Point P = {"88764801008590816877766665490322569426078893736160224298871996999069541569081",
               "64549562702257555313735637722402300165514114834696882062669884644749455809738"};
    int n = 20;

    Point R = ecc.scalarMultiplyPoints(n, P);
    
    Point expected = {"580578379796884640291629975597379928185276275272807587279982663300338316316",
                      "36453294428164904118977036101609216276810108334259481990292799215351578729756"};
    
    EXPECT_EQ(R.x, expected.x);
    EXPECT_EQ(R.y, expected.y);*/
}

/*TEST(TestECC_Arithmetic, testExtendedEuclideanAlgorithm)
{
    ECC ecc;

    InfInt a = "74137112295098844335251337610803238244776982320014880532548593813303018932166";
    const InfInt m = "115792089210356248762697446949407573529996955224135760342422259061068512044369";

    InfInt result = ecc.extendedEuclidean(a, m);

    InfInt expected = "23565630754992692729219419855554292010885827551965781088758971789715527090584";

    EXPECT_EQ(result, expected);
}

TEST(TestECC_Arithmetic, testFlooredMod)
{
    ECC ecc;

    const InfInt m = "115792089210356248762697446949407573529996955224135760342422259061068512044369";

    InfInt a = "23565630754992692729219419855554292010885827551965781088758971789715527090584";
    InfInt result = ecc.mod(a, m);
    InfInt expected = "23565630754992692729219419855554292010885827551965781088758971789715527090584";
    EXPECT_EQ(result, expected);

    a = "231584178420712497525394893898815147059993910448271520684844518122137024499999";
    result = ecc.mod(a, m);
    expected = "411261"; 
    EXPECT_EQ(result, expected);

    a = "231584178420712497525394893898815147059993910448271520684844518122137024088738";
    result = ecc.mod(a, m);
    expected = "0";
    EXPECT_EQ(result, expected);
}

TEST(TestECC_Arithmetic, testModInverse)
{
    ECC ecc;

    const InfInt m = "115792089210356248762697446949407573529996955224135760342422259061068512044369";

    InfInt s = "74137112295098844335251337610803238244776982320014880532548593813303018932166";
    InfInt result = ecc.modInverse(s, m);
    InfInt expected = "23565630754992692729219419855554292010885827551965781088758971789715527090584";
    EXPECT_EQ(result, expected);

    s = "231584178420712497525394893898815147059993910448271520684844518122137024499999";
    result = ecc.modInverse(s, m);
    expected = "48626871829401322682084402277836295240230034308639192709688995407242801157102";
    EXPECT_EQ(result, expected);

    s = "231584178420712497525394893898815147059993910448271520684844518122137024088738";
    std::stringstream buffer;
    std::streambuf* old = std::cerr.rdbuf(buffer.rdbuf());
    result = ecc.modInverse(s, m);
    std::cerr.rdbuf(old);
    std::string output = buffer.str();
    EXPECT_TRUE(output.find("Modular inverse does not exist.") != std::string::npos);
    
    expected = "-1";
    EXPECT_EQ(result, expected);
}*/