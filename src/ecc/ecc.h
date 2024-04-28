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
    //Curve25519,
    //Curve383187,
    //Curve41417,
    P256,
    secp256k1,
    // Add more standard curves as needed
};

struct KeyPair {
    Point publicKey;
    mpz_t privateKey;
};

class CurveManager {
public:
    // Method to get curve parameters based on the selected standard curve
    static Curve getCurveParams(StandardCurve curve) {
        switch (curve) {
            case StandardCurve::test:
                return init_test();
            //case StandardCurve::Curve25519:
            //    return Curve25519;
            //case StandardCurve::Curve383187:
            //    return Curve383187;
            //case StandardCurve::Curve41417:
            //    return Curve41417;
            case StandardCurve::P256:
                return init_p256();
            case StandardCurve::secp256k1:
                return init_secp256k1();
            // Add more cases for additional standard curves
            default:
                throw std::invalid_argument("Invalid standard curve");
        }
    }
};

class ECC {
private:
    //void clear_point(Point point);
    //void cswap(Point &a, Point &b, int swap);
    //void ladder_step(Point &x2y2, Point &x3y3, const mpz_t a24, const mpz_t x1);

    void clearCurve(Curve &curve) {
        mpz_clears(curve.a, curve.b, curve.p, curve.basePoint.x, curve.basePoint.y, curve.n, NULL);
    }

public:
    KeyPair keyPair;
    Curve curve;

    ECC(StandardCurve curve = StandardCurve::test) : curve(CurveManager::getCurveParams(curve)) {
        keyPair = {{0,0}, 0};
    }

    // Destructor
    ~ECC() {
        clearCurve(curve);
    }

    // Method to set the curve to a new standard curve
    void setCurve(StandardCurve curveType) {
        // Clear the memory allocated for the current curve
        if (curve.n != 0) clearCurve(curve);

        // Initialize the new curve
        curve = CurveManager::getCurveParams(curveType);
    }

    //InfInt hexStringToInteger(const std::string& hexString);

    Point addPoints(Point P, Point Q);
    Point doublePoint(Point P);
    //Point scalarMultiplyPoints(const mpz_t scalar, Point P);
    Point ECC::scalarMultiplyPoints(const mpz_t& k, Point P);

    //InfInt getRandomNumber(const InfInt min, const InfInt max);
    void ECC::getRandomNumber(const mpz_t min, const mpz_t max, mpz_t& result);

    //InfInt extendedEuclidean(InfInt num, InfInt n);
    //InfInt mod(InfInt a, InfInt n);
    //InfInt modInverse(InfInt a, InfInt m);
};