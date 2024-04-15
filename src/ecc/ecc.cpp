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
#include <string>
#include <sstream>

#include "ecc.h"
#include "../../tools/utils.h"

InfInt ECC::hexStringToInteger(const std::string& hexString) {
    InfInt result;
    for (char c : hexString) {
        result *= 16;
        if (c >= '0' && c <= '9') {
            result += (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            result += (c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            result += (c - 'A' + 10);
        } else {
            // Invalid character in hex string
            throw std::invalid_argument("Invalid hexadecimal character");
        }
    }
    return result;
}

// Function to add two points
Point ECC::addPoints(Point P, Point Q) {
    Point T = {-1, -1}; // Initialize T to an invalid point
    InfInt deltaX = mod(Q.x - P.x, curve.p);
    InfInt deltaY = mod(Q.y - P.y, curve.p);
    InfInt invDeltaX = modInverse(deltaX, curve.p);

    if (invDeltaX == -1) {
        // Handle case where modular inverse doesn't exist
        std::cerr << "Modular inverse does not exist." << std::endl;
        return T;
    }

    InfInt slope = mod(deltaY * invDeltaX, curve.p);
    InfInt x3 = mod(slope * slope - P.x - Q.x, curve.p);
    InfInt y3 = mod(slope * (P.x - x3) - P.y, curve.p);

    T.x = x3;
    T.y = y3;

    return T;
}

// Function to double a point
Point ECC::doublePoint(Point P) {
    Point T;

    InfInt s = mod((InfInt)3 * P.x * P.x + curve.a, curve.p) * mod(modInverse((InfInt)2 * P.y, curve.p), curve.p);

    T.x = mod(((s * s) - P.x - P.x), curve.p);
    T.y = mod((s * (P.x - T.x) - P.y), curve.p);

    return T;
}

// Implementation of the double-and-add algoirthm
Point ECC::scalarMultiplyPoints(InfInt k, Point P) {
    if (k == 0)
        return {0, 0};
    else if (k == 1) {
        return P;
    }
    else if (k % 2 == 1)
        return addPoints(P, scalarMultiplyPoints(k - 1, P));
    else
        return scalarMultiplyPoints(k / 2, doublePoint(P));
}

// Function to generate random numbers
InfInt ECC::getRandomNumber(const InfInt min, const InfInt max) {
    InfInt range = max - min + 1;
    if (range <= 0) {
        throw std::invalid_argument("Invalid range: min must be less than or equal to max.");
    }

    // Determine the number of digits needed to represent the range
    size_t numDigits = range.numberOfDigits();

    // Generate random digits
    std::string randomString;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> digitDistribution(0, 9);
    for (size_t i = 0; i < numDigits; ++i) {
        int digit = digitDistribution(gen);
        randomString += std::to_string(digit);
    }

    // Convert the random digits string to an InfInt value
    InfInt result(randomString);

    // Ensure the result is within the specified range [min, max]
    result %= range;
    result += min;

    return result;
}

// Function to complete the extended euclidean algorithm
std::tuple<InfInt, InfInt, InfInt> ECC::extendedEuclidean(InfInt a, InfInt b) {
    InfInt x0 = 1, y0 = 0, x1 = 0, y1 = 1;

    while (b != 0) {
        InfInt q = a / b;
        InfInt temp = b;
        b = a % b;
        a = temp;

        InfInt x2 = x0 - q * x1;
        InfInt y2 = y0 - q * y1;

        x0 = x1;
        y0 = y1;
        x1 = x2;
        y1 = y2;
    }

    return std::make_tuple(a, x0, y0);
}

// Function to compute the floored division
InfInt ECC::mod(InfInt a, InfInt n) {
    return ((a % n) + n) % n;
}

// Function to compute the modular multiplicative inverse
InfInt ECC::modInverse(InfInt a, InfInt m) {
    InfInt gcd, x, y;
    std::tie(gcd, x, y) = extendedEuclidean(a, m);

    if (gcd != 1) {
        std::cerr << "Modular inverse does not exist." << std::endl;
        return -1; // Modular inverse does not exist
    }

    //return (x % m + m) % m; // Ensure positive result
    return mod(x, m);
}