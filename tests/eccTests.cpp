/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * eccTests.cpp
 */

#include "../src/ecc/ecc.h"
#include "../src/ecc/standardCurves.h"

#include "gtest/gtest.h"
#include <string>
#include <iostream>

TEST(TestECC_Arithmetic, testPointAddition)
{
    ECC ecc;

    Point P = {6, 3};
    Point Q = {3, 1};

    Point R = ecc.addPoints(P, Q);

    Point expected = {16, 13};
    bool pointsEqual = true;
    if (R.x != expected.x || R.y != expected.y)
        pointsEqual = false;

    EXPECT_EQ(pointsEqual, 1);
}

TEST(TestECC_Arithmetic, testPointDoulbe)
{
    ECC ecc;

    Point P = {9, 1};

    Point R = ecc.doublePoint(P);

    Point expected = {7, 6};
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

    Point R = ecc.scalarMultiplyPoints(n, P);
    
    Point expected = {16, 13};
    bool pointsEqual = true;
    if (R.x != expected.x || R.y != expected.y)
        pointsEqual = false;

    EXPECT_EQ(pointsEqual, 1);
}