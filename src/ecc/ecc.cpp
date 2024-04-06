/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecc.cpp
 *
 * This file contains the implementation of Gestalts ECC security functions.
 */

#include <math.h>
#include <random>
#include <tuple>
#include <iostream>

#include "ecc.h"
#include "../../tools/utils.h"

Point ECC::addPoints(Point P, Point Q) {
    Point T;
    int s = ((P.y - Q.y) * ((int)pow(Q.x - P.x, curve.p - 2) % curve.p)) % curve.p;

    T.x = ((int)pow(s, 2) - P.x - Q.x) % curve.p;
    T.y = (s * (P.x - T.x) - P.y) % curve.p;

    return T;
}

Point ECC::doublePoint(Point P) {
    Point T;
    int s = ((3 * (int)pow(P.x, 2) + curve.a) * ((int)pow(2 * P.y, curve.p - 2) % curve.p)) % curve.p;

    T.x = ((int)pow(s, 2) - P.x - P.x) % curve.p;
    T.y = (s * (P.x - T.x) - P.y) % curve.p;

    return T;
}

Point ECC::scalarMultiplyPoints(int k, Point P) {
    Point T = P;
    std::string binaryK = DecimalToBinary(k);
    for (size_t i = 0; i < binaryK.length(); i++) {
        T = doublePoint(T);
        if (binaryK[i] == '1')
            T = addPoints(T, P);
    }
    return T;
}

int ECC::getRandomNumber(int min, int max) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(min, max);
    return dis(gen);
}

std::tuple<int, int, int> ECC::extendedEuclidean(int a, int b) {
    int x0 = 1, y0 = 0, x1 = 0, y1 = 1;

    while (b != 0) {
        int q = a / b;
        int temp = b;
        b = a % b;
        a = temp;

        int x2 = x0 - q * x1;
        int y2 = y0 - q * y1;

        x0 = x1;
        y0 = y1;
        x1 = x2;
        y1 = y2;
    }

    return std::make_tuple(a, x0, y0);
}

// Function to compute the modular multiplicative inverse
int ECC::modInverse(int a, int m) {
    int gcd, x, y;
    std::tie(gcd, x, y) = extendedEuclidean(a, m);

    if (gcd != 1) {
        std::cerr << "Modular inverse does not exist." << std::endl;
        return -1; // Modular inverse does not exist
    }

    return (x % m + m) % m; // Ensure positive result
}