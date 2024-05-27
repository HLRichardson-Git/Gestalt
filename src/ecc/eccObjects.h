/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * eccObjects.h
 *
 * This file contains data objects used in Elliptic Curve Cryptography.
 *
 */
#pragma once

#include <string>
#include <gmp.h>

inline void stringToGMP(const std::string& str, mpz_t& result) {
    if (str.substr(0, 2) == "0x") {
        std::string truncatedStr = str.substr(2, str.length());
        mpz_set_str(result, truncatedStr.c_str(), 16);
    } else {
        mpz_set_str(result, str.c_str(), 10);
    }
}

class BigInt {
public:
    mpz_t n;

    BigInt() { mpz_init(n); }
    BigInt(const std::string& strN) {
        mpz_init(n);
        stringToGMP(strN, n);
    }
    BigInt(const BigInt& other) {
        mpz_init_set(n, other.n);
    }
    void operator =(const BigInt& other) {
        mpz_set(this->n, other.n);
    }
    void operator =(const std::string& strN) {
        mpz_init(n);
        stringToGMP(strN, n);
    }

    ~BigInt() {
        mpz_clear(n);
    }
};

class Point {
public:
    mpz_t x, y;

    Point() { mpz_inits(x, y, NULL); }
    Point(const std::string& strX, const std::string& strY) {
        mpz_inits(x, y, NULL);
        stringToGMP(strX, x);
        stringToGMP(strY, y);
    }
    Point(const Point& other) {
        mpz_init_set(x, other.x);
        mpz_init_set(y, other.y);
    }
    void operator =(const Point& other) {
        mpz_set(this->x, other.x);
        mpz_set(this->y, other.y);
    }

    ~Point() {
        mpz_clear(x);
        mpz_clear(y);
    }

    Point setPoint(const std::string& strX, const std::string& strY) { return Point(strX, strY); };
};

class KeyPair {
public:
    mpz_t privateKey;
    Point publicKey;

    KeyPair() { mpz_init(privateKey); }
    KeyPair(const mpz_t& gmpPriv, const Point& strPub) {
        mpz_init(privateKey);
        mpz_set(privateKey, gmpPriv);
        publicKey = strPub;
    }
    KeyPair(const std::string& strPriv, const Point& strPub) {
        mpz_init(privateKey);
        stringToGMP(strPriv, privateKey);
        publicKey = strPub;
    }
    KeyPair(const KeyPair& other) {
        mpz_init_set(privateKey, other.privateKey);
        publicKey = other.publicKey;
    }
    void operator =(const KeyPair& R) {
        mpz_set(this->privateKey, R.privateKey);
        this->publicKey = R.publicKey;
    } 

    ~KeyPair() { mpz_clear(privateKey); }
};

class Signature {
public:
    mpz_t r, s;

    Signature() { mpz_inits(r, s, NULL); }
    Signature(const std::string& strR, const std::string& strS) {
        mpz_inits(r, s, NULL);
        stringToGMP(strR, r);
        stringToGMP(strS, s);
    }
    Signature(const Signature& other) {
        mpz_init_set(r, other.r);
        mpz_init_set(s, other.s);
    }
    void operator =(const Signature& other) {
        mpz_set(this->r, other.r);
        mpz_set(this->s, other.s);
    }

    ~Signature() {
        mpz_clear(r);
        mpz_clear(s);
    }
};