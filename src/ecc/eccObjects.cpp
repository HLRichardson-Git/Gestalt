/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * eccObjects.cpp
 *
 * This file contains the implementation of Gestalts ECC security functions.
 */

#include <gmp.h>
#include <string>
#include <iostream>

#include "eccObjects.h"

void stringToGMP(const std::string& str, mpz_t& result) {
    //mpz_init(result);
    
    // Check if the string starts with "0x" to determine if it's hexadecimal
    if (str.substr(0, 2) == "0x") {
        std::string truncatedStr = str.substr(2, str.length());
        mpz_set_str(result, truncatedStr.c_str(), 16);
    } else {
        mpz_set_str(result, str.c_str(), 10);
    }
}

/*  Point Object  */

Point::Point() {
    mpz_inits(x, y, NULL);
}

Point::Point(const std::string& strX, const std::string& strY) {
    mpz_inits(x, y, NULL);
    stringToGMP(strX, x);
    stringToGMP(strY, y);
}

// Copy constructor definition
Point::Point(const Point& other) {
    // Initialize x and y with the same values as other
    mpz_init_set(x, other.x);
    mpz_init_set(y, other.y);
}

void Point::operator =(const Point& R) {
    mpz_set(this->x, R.x);
    mpz_set(this->y, R.y);
}

Point::~Point() {
    mpz_clear(x);
    mpz_clear(y);
}

Point Point::setPoint(const std::string& strX, const std::string& strY) {
    return Point(strX, strY);
}

/*  KeyPair Object  */

KeyPair::KeyPair() {
    mpz_init(privateKey);
}

KeyPair::KeyPair(const mpz_t& gmpPriv, const Point& strPub) {
    mpz_init(privateKey);
    mpz_set(privateKey, gmpPriv);
    publicKey = strPub;
}

KeyPair::KeyPair(const std::string& strPriv, const Point& strPub) {
    mpz_init(privateKey);
    stringToGMP(strPriv, privateKey);
    publicKey = strPub;
}

KeyPair::KeyPair(const KeyPair& other) {
    mpz_init_set(privateKey, other.privateKey);
    publicKey = other.publicKey;
}

void KeyPair::operator =(const KeyPair& R) {
    mpz_set(this->privateKey, R.privateKey);
    this->publicKey = R.publicKey;
}

KeyPair::~KeyPair() {
    mpz_clear(privateKey);
}

/*  Signature Object  */

Signature::Signature() {
    mpz_inits(r, s, NULL);
}

Signature::Signature(const std::string& strR, const std::string& strS) {
    mpz_inits(r, s, NULL);
    stringToGMP(strR, r);
    stringToGMP(strS, s);
}

// Copy constructor definition
Signature::Signature(const Signature& other) {
    // Initialize x and y with the same values as other
    mpz_init_set(r, other.r);
    mpz_init_set(s, other.s);
}

void Signature::operator =(const Signature& other) {
    mpz_set(this->r, other.r);
    mpz_set(this->s, other.s);
}

Signature::~Signature() {
    mpz_clear(r);
    mpz_clear(s);
}

inline Curve init_test() {
    Curve test;
    mpz_inits(test.a, test.b, test.p, test.basePoint.x, test.basePoint.y, test.n, NULL);
    mpz_set_str(test.a, "2", 16);
    mpz_set_str(test.b, "2", 16);
    mpz_set_str(test.p, "11", 16);
    mpz_set_str(test.basePoint.x, "5", 16);
    mpz_set_str(test.basePoint.y, "1", 16);
    mpz_set_str(test.n, "13", 16);
    test.bitLength = 1;
    return test;
}

inline Curve init_p256() {
    Curve P256;
    mpz_inits(P256.a, P256.b, P256.p, P256.basePoint.x, P256.basePoint.y, P256.n, NULL);
    mpz_set_str(P256.a, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
    mpz_set_str(P256.b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    mpz_set_str(P256.p, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    mpz_set_str(P256.basePoint.x, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    mpz_set_str(P256.basePoint.y, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    mpz_set_str(P256.n, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    P256.bitLength = 256;
    return P256;
}

inline Curve init_secp256k1() {
    Curve secp256k1;
    mpz_inits(secp256k1.a, secp256k1.b, secp256k1.p, secp256k1.basePoint.x, secp256k1.basePoint.y, secp256k1.n, NULL);
    mpz_set_str(secp256k1.a, "0", 16);
    mpz_set_str(secp256k1.b, "7", 16);
    mpz_set_str(secp256k1.p, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    mpz_set_str(secp256k1.basePoint.x, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    mpz_set_str(secp256k1.basePoint.y, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
    mpz_set_str(secp256k1.n, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    secp256k1.bitLength = 256;
    return secp256k1;
}

Curve getCurveParams(StandardCurve curve) {
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