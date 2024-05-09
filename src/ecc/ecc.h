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

#include "eccObjects.h"
#include "standardCurves.h"

class ECC {
private:

    KeyPair keyPair;
    Curve ellipticCurve;

    Point addPoints(Point P, Point Q);
    Point doublePoint(Point P);
    Point scalarMultiplyPoints(const mpz_t& k, Point P);

    void getRandomNumber(const mpz_t min, const mpz_t max, mpz_t& result);
    
    friend class ECDSA;
    //friend class ECDH;
public:

    ECC(StandardCurve curve = StandardCurve::secp256k1) : ellipticCurve(getCurveParams(curve)) {}

    ~ECC() {}

    KeyPair generateKeyPair();

    void setKeyPair(const KeyPair& newKeyPair) { keyPair = newKeyPair; }
    void setKeyPair(const std::string& strKey);
    void setCurve(StandardCurve curveType) { ellipticCurve = getCurveParams(curveType); }
    KeyPair getKeyPair() const { return keyPair; }

    friend class TestECC;
};