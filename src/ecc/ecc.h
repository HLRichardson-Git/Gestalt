/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
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

class ECC {
private:

    KeyPair keyPair;
    Curve ellipticCurve;

    Point addPoints(Point P, Point Q);
    Point doublePoint(Point P);
    Point scalarMultiplyPoints(const BigInt& k, Point P);

    BigInt fieldElementToInteger(const BigInt& fieldElement);
    bool isInDomainRange(const BigInt& k);
    bool isIdentityPoint(Point P);
    bool isPointOnCurve(Point P);
    std::string isValidPublicKey(const ECDSAPublicKey P);
    std::string isValidKeyPair(const KeyPair& K);

    friend class ECDSA;
    friend class ECDH;
    friend class ECC_Test;
public:

    ECC(StandardCurve curve = StandardCurve::secp256k1) : ellipticCurve(getCurveParams(curve)) {
        keyPair.publicKey.setCurve(curve);
    }

    ~ECC() {}

    KeyPair generateKeyPair();

    void setKeyPair(const KeyPair& newKeyPair);
    void setKeyPair(const BigInt& key);
    void setCurve(StandardCurve curveType) { 
        ellipticCurve = getCurveParams(curveType);
        keyPair.publicKey.setCurve(curveType); 
    }
    KeyPair getKeyPair() const { return keyPair; }
};