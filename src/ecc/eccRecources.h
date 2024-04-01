/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * eccResources.cpp
 *
 * This file contains standard strong Ellicptic Curves.
 *
 * References:
 * - The Design of Rijndael: AES - The Advanced Encryption Standard (https://csrc.nist.gov/publications/detail/fips/197/final)
 */

#pragma once

struct Point {
    int x;
    int y;
};

struct ECDSA_KeyPair {
    Point publicKey;
    int privateKey;
};

struct Curve {
    const int a;
    const int b;
    const int p;
    const Point basePoint;
    const int n;
};