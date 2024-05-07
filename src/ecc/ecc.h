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
//#include <gmp.h>

#include "eccObjects.h"

class ECC {
private:

public:
    //KeyPair keyPair;
    Curve curve;

    ECC(StandardCurve curve = StandardCurve::test) : curve(getCurveParams(curve)) {}

    // Destructor
    ~ECC() {}

    // Method to set the curve to a new standard curve
    void setCurve(StandardCurve curveType) {
        curve = getCurveParams(curveType);
    }

    Point addPoints(Point P, Point Q);
    Point doublePoint(Point P);
    Point scalarMultiplyPoints(const mpz_t& k, Point P);

    void getRandomNumber(const mpz_t min, const mpz_t max, mpz_t& result);
};