/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * standardCurves.h
 *
 * This file contains popular standard curves uses in Elliptic Curve Cryptography.
 *
 * References:
 * - 
 */
#pragma once

struct Point {
    int x;
    int y;
};

struct Curve {
    int a;
    int b;
    int p;
    Point basePoint;
    int n;
};

const Curve test = {
    2,
    2,
    17,
    {5, 1},
    19
};

const Curve Curve25519 = {
    2,
    2,
    17,
    {5, 1},
    19
};

const Curve Curve383187 = {
    3,
    4,
    23,
    {7, 2},
    29
};

const Curve Curve41417 = {
    5,
    6,
    31,
    {11, 3},
    41
};