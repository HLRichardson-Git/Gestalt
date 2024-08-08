/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecc.h
 *
 * This file contains declarations for Elliptic Curve Cryptography (ECC) class for Gestalt.
 * ECC is a public-key cryptography method based on the algebraic structure of elliptic curves
 * over finite fields.
 *
 * The class provides functionality for key generation, point arithmetic, and generating random numbers.
 *
 * References:
 * - "Guide to Elliptic Curve Cryptography" by Darrel Hankerson, Alfred Menezes, Scott Vanstone
 * - "Elliptic Curves: Number Theory and Cryptography" by Lawrence C. Washington
 * - "Understanding Cryptography" by Christof Paar and Jan Pelzl
 *
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
    void fieldElementToInteger(const mpz_t& fieldElement, mpz_t result);
    bool isInDomainRange(const mpz_t k);
    bool isIdentityPoint(Point P);
    bool isPointOnCurve(Point P);
    std::string isValidPublicKey(const Point P);
    std::string isValidKeyPair(const KeyPair& K);

    friend class ECDSA;
    friend class ECDH;
    friend class ECC_Test;
public:

    ECC(StandardCurve curve = StandardCurve::secp256k1) : ellipticCurve(getCurveParams(curve)) {}

    ~ECC() {}

    KeyPair generateKeyPair();

    void setKeyPair(const KeyPair& newKeyPair);
    void setKeyPair(const std::string& strKey);
    void setCurve(StandardCurve curveType) { ellipticCurve = getCurveParams(curveType); }
    KeyPair getKeyPair() const { return keyPair; }
};