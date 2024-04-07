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

// Function to add two points
Point ECC::addPoints(Point P, Point Q) {
    Point T = {-1, -1}; // Initialize T to an invalid point
    int deltaX = mod(Q.x - P.x, curve.p);
    int deltaY = mod(Q.y - P.y, curve.p);
    int invDeltaX = modInverse(deltaX, curve.p);

    if (invDeltaX == -1) {
        // Handle case where modular inverse doesn't exist
        std::cerr << "Modular inverse does not exist." << std::endl;
        return T;
    }

    int slope = mod(deltaY * invDeltaX, curve.p);
    int x3 = mod(slope * slope - P.x - Q.x, curve.p);
    int y3 = mod(slope * (P.x - x3) - P.y, curve.p);

    T.x = x3;
    T.y = y3;

    return T;
}

// Function to double a point
Point ECC::doublePoint(Point P) {
    Point T;
 
    int s = (3 * P.x * P.x + curve.a) * mod(modInverse(2 * P.y, curve.p), curve.p);

    T.x = mod(((int)pow(s, 2) - P.x - P.x), curve.p);
    T.y = mod((s * (P.x - T.x) - P.y), curve.p);

    return T;
}

// Implementation of the double-and-add algoirthm
Point ECC::scalarMultiplyPoints(int k, Point P) {
    if (k == 0)
        return {0, 0};
    else if (k == 1)
        return P;
    else if (k % 2 == 1)
        return addPoints(P, scalarMultiplyPoints(k - 1, P));
    else
        return scalarMultiplyPoints(k / 2, doublePoint(P));
}

// Function to generate random numbers
int ECC::getRandomNumber(int min, int max) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(min, max);
    return dis(gen);
}

// Function to complete the extended euclidean algorithm
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

// Function to compute the floored division
int ECC::mod(int a, int n) {
    return ((a % n) + n) % n;
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