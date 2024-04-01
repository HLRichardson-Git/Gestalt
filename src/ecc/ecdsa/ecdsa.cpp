/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsa.cpp
 *
 * This file contains the implementation of Gestalts AES security functions.
 */

#include <math.h>
#include <random>
#include <tuple>

#include <gestalt/ecdsa.h>
#include "infint/InfInt.h"
#include "../../../tools/utils.h"

InfInt myint1 = "15432154865413186646848435184100510168404641560358";
InfInt myint2 = 156341300544608LL;

Curve test = {
    2,
    2,
    17,
    {5, 1},
    19
};

ECDSA::ECDSA() {
    // Constructor definition
}

Point ECDSA::addPoints(Point P, Point Q) {
    Point T;
    int s = ((P.y - Q.y) * ((int)pow(Q.x - P.x, test.p - 2) % test.p)) % test.p;

    T.x = ((int)pow(s, 2) - P.x - Q.x) % test.p;
    T.y = (s * (P.x - T.x) - P.y) % test.p;

    return T;
}

Point ECDSA::doublePoint(Point P) {
    Point T;
    int s = ((3 * (int)pow(P.x, 2) + test.a) * ((int)pow(2 * P.y, test.p - 2) % test.p)) % test.p;

    T.x = ((int)pow(s, 2) - P.x - P.x) % test.p;
    T.y = (s * (P.x - T.x) - P.y) % test.p;

    return T;
}

Point ECDSA::scalarMultiplyPoints(int k, Point P) {
    Point T = P;
    std::string binaryK = DecimalToBinary(k);
    for (size_t i = 0; i < k; i++) {
        T = doublePoint(T);
        if (binaryK[i] == '1')
            T = addPoints(T, P);
    }
    return T;
}

int ECDSA::getRandomNumber(int min, int max) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(min, max);
    return dis(gen);
}

ECDSA_KeyPair ECDSA::generateKeyPair() {
    int privateKey = getRandomNumber(1, test.n - 1);
    Point publicKey = scalarMultiplyPoints(privateKey, test.basePoint);
    return {publicKey, privateKey};
}

Signature ECDSA::signMessage(const std::string& message, const ECDSA_KeyPair& keyPair) {
    Signature S;
    int k = getRandomNumber(0, test.n);
    Point R = scalarMultiplyPoints(k, test.basePoint);
    S.r = R.x % test.n;
    int e = hexStringToInt(message);
    int kInverse = modInverse(k, test.n); 
    S.s = ((e + keyPair.privateKey * S.r) * kInverse) % test.n;
    return S;
}

bool ECDSA::verifySignature(const std::string& message, const Signature signature, const Point& publicKey) {
    int sInverse = modInverse(signature.s, test.n);
    int w = sInverse % test.n;
    int e = hexStringToInt(message);
    int u1 = w*e % test.n;
    int u2 = w*signature.r % test.n;
    Point P = (addPoints(scalarMultiplyPoints(u1, test.basePoint), scalarMultiplyPoints(u2, publicKey)));
    return signature.r == P.x % test.n;
}

std::tuple<int, int, int> extendedEuclidean(int a, int b) {
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
int modInverse(int a, int m) {
    int gcd, x, y;
    std::tie(gcd, x, y) = extendedEuclidean(a, m);

    if (gcd != 1) {
        std::cerr << "Modular inverse does not exist." << std::endl;
        return -1; // Modular inverse does not exist
    }

    return (x % m + m) % m; // Ensure positive result
}