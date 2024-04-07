/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecc.cpp
 *
 * This file contains standard strong Ellicptic Curves.
 *
 * References:
 * - 
 */

#pragma once

#include <iostream>

#include "standardCurves.h"

// Enumerate the available standard curves
enum class StandardCurve {
    test,
    Curve25519,
    Curve383187,
    Curve41417,
    // Add more standard curves as needed
};

struct KeyPair {
    Point publicKey;
    int privateKey;
};

class CurveManager {
public:
    // Method to get curve parameters based on the selected standard curve
    static Curve getCurveParams(StandardCurve curve) {
        switch (curve) {
            case StandardCurve::test:
                return test;
            case StandardCurve::Curve25519:
                return Curve25519;
            case StandardCurve::Curve383187:
                return Curve383187;
            case StandardCurve::Curve41417:
                return Curve41417;
            // Add more cases for additional standard curves
            default:
                throw std::invalid_argument("Invalid standard curve");
        }
    }
};

class ECC {
private:

    std::tuple<int, int, int> extendedEuclidean(int a, int b);

public:
    KeyPair keyPair;
    Curve curve;

    ECC(StandardCurve curve = StandardCurve::test) : curve(CurveManager::getCurveParams(curve)) {
        keyPair = {{0,0}, 0};
    }

    Point addPoints(Point P, Point Q);
    Point doublePoint(Point P);
    Point scalarMultiplyPoints(int k, Point P);

    int getRandomNumber(int min, int max);
    int mod(int a, int n);
    int modInverse(int a, int m);
};