/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * eccTests.cpp
 */

#include "../src/ecc/ecc.h"

#include "gtest/gtest.h"
#include <string>
#include <iostream>
#include <sstream>
#include <tuple>

TEST(TestECC_Arithmetic, testPointAddition)
{
    ECC ecc(StandardCurve::P256);

    Point P = {"67228059374187986264907871817984995299114694677537144137068659840319595636958",
               "36911659202040455512047859400253132650624032136469391266733306307680092206180"};
    Point Q = {"79584758605949253762341734104702304948499678541099118250653347730022630682716", 
               "82005680352103069544532681048882113537922206207710011425498220375837764433226"};

    Point R = ecc.addPoints(P, Q);

    Point expected = {"16247106453250244225622460159038600432635777869376973139750787284798796257055",
                      "84741935852476448650405200364169101653520738128916381383119006842903426464819"};
    bool pointsEqual = true;
    if (R.x != expected.x || R.y != expected.y)
        pointsEqual = false;

    EXPECT_EQ(pointsEqual, 1);
}

TEST(TestECC_Arithmetic, testPointDoulbe)
{
    ECC ecc(StandardCurve::P256);

    Point P = {"16247106453250244225622460159038600432635777869376973139750787284798796257055",
               "84741935852476448650405200364169101653520738128916381383119006842903426464819"};

    Point R = ecc.doublePoint(P);

    Point expected = {"94661065609916795805170830853666726936855561355503933991787557860394254628829",
                      "22871027890686529937969966456841486853953364797665548725333072814274627436453"};
    bool pointsEqual = true;
    if (R.x != expected.x || R.y != expected.y)
        pointsEqual = false;

    EXPECT_EQ(pointsEqual, 1);
}

TEST(TestECC_Arithmetic, testPointMultiplication)
{
    ECC ecc;

    Point P = {9, 1};
    int n = 14;

    Point R = ecc.scalarMultiplyPoints(n, P, ecc.curve.n);
    
    Point expected = {16, 13};
    bool pointsEqual = true;
    if (R.x != expected.x || R.y != expected.y)
        pointsEqual = false;

    EXPECT_EQ(pointsEqual, 1);
}

TEST(TestECC_Arithmetic, testExtendedEuclideanAlgorithm)
{
    ECC ecc;

    InfInt a = "74137112295098844335251337610803238244776982320014880532548593813303018932166";
    const InfInt m = "115792089210356248762697446949407573529996955224135760342422259061068512044369";
    std::tuple<InfInt, InfInt, InfInt> result = ecc.extendedEuclidean(a, m);
    std::tuple<InfInt, InfInt, InfInt> expected;
    expected = std::make_tuple(1, 
                          "23565630754992692729219419855554292010885827551965781088758971789715527090584",
                          "-15088144842208025732070556293866869663563346026362057237435181386682119668447");

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
}