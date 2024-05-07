/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * eccObjects.h
 *
 * This file contains popular standard curves uses in Elliptic Curve Cryptography.
 *
 * References:
 * - 
 */
#pragma once

#include <gmp.h>

void stringToGMP(const std::string& str, mpz_t& result);

class Point {
public:
    mpz_t x, y;

    Point();
    Point(const std::string& strX, const std::string& strY);

    Point(const Point& other);
    void operator =(const Point& R);

    ~Point();

    Point setPoint(const std::string& strX, const std::string& strY);
};

class KeyPair {
public:
    mpz_t privateKey;
    Point publicKey;

    KeyPair();
    KeyPair(const mpz_t& gmpPriv, const Point& strPub);
    KeyPair(const std::string& strPriv, const Point& strPub);

    KeyPair(const KeyPair& other);
    void operator =(const KeyPair& R); 

    ~KeyPair();
};

class Signature {
public:
    mpz_t r, s;

    Signature();
    Signature(const std::string& strR, const std::string& strS);

    Signature(const Signature& other);
    void operator =(const Signature& other);

    ~Signature();
};

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

struct Curve {
    mpz_t a;
    mpz_t b;
    mpz_t p;
    Point basePoint;
    mpz_t n;
    size_t bitLength;
};

inline Curve init_test();
inline Curve init_p256();
inline Curve init_secp256k1();

Curve getCurveParams(StandardCurve curve);