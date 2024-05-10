/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecc.cpp
 *
 * This file contains the implementation of Elliptic Curve Cryptography (ECC) algorithms for Gestalt.
 * ECC is a powerful cryptographic technique based on the algebraic properties of elliptic curves
 * over finite fields.
 *
 * This implementation covers key operations in ECC, including point addition, point doubling,
 * scalar multiplication, and the ECC arithmetic required for cryptographic operations.
 *
 * References:
 * - "Guide to Elliptic Curve Cryptography" by Darrel Hankerson, Alfred Menezes, Scott Vanstone
 * - "Elliptic Curves: Number Theory and Cryptography" by Lawrence C. Washington
 * - "Understanding Cryptography" by Christof Paar and Jan Pelzl
 *
 */


#include <math.h>
#include <string>
#include <sstream>
#include <gmp.h>

#include "ecc.h"

// Function to add two points
Point ECC::addPoints(Point P, Point Q) {
    Point T;

    mpz_t s;
    mpz_init(s);

    /* s = (y1 - y2) / (x1 - x2) */
    mpz_sub(T.x, P.y, Q.y);
    mpz_sub(T.y, P.x, Q.x);
    mpz_invert(T.y, T.y, ellipticCurve.p);
    mpz_mul(s, T.x, T.y);
    mpz_mod(s, s, ellipticCurve.p);

    /* rx = s^2 - (x1 + x2) */
    mpz_mul(T.x, s, s);
    mpz_sub(T.x, T.x, P.x);
    mpz_sub(T.x, T.x, Q.x);

    /* ry = s(x1 - rx) - y1 */
    mpz_sub(T.y, P.x, T.x);
    mpz_mul(T.y, s, T.y);
    mpz_sub(T.y, T.y, P.y);

    mpz_clear(s);

    /* We assign the destination parameters in the end to allow them to
     be identical to the inputs. */
    Point R;
    mpz_mod(R.x, T.x, ellipticCurve.p);
    mpz_mod(R.y, T.y, ellipticCurve.p);

    return R;
}

// Function to double a point
Point ECC::doublePoint(Point P) {
    Point T;
    
    mpz_t s;
    mpz_init(s);

    /* s = (3x^2 + a) / 2y */
    mpz_mul(T.x, P.x, P.x);
    mpz_mod(T.x, T.x, ellipticCurve.p);
    mpz_mul_ui(T.x, T.x, 3);
    mpz_add(T.x, T.x, ellipticCurve.a);
    mpz_mod(T.x, T.x, ellipticCurve.p);

    mpz_mul_ui(T.y, P.y, 2);
    mpz_invert(T.y, T.y, ellipticCurve.p);

    mpz_mul(s, T.x, T.y);
    mpz_mod(s, s, ellipticCurve.p);

    /* rx = s^2 - 2x */
    mpz_mul(T.x, s, s);
    mpz_mul_ui(T.y, P.x, 2);
    mpz_sub(T.x, T.x, T.y);

    /* ry = s(x - rx) - y */
    mpz_sub(T.y, P.x, T.x);
    mpz_mul(T.y, s, T.y);
    mpz_sub(T.y, T.y, P.y);

    mpz_clear(s);

    /* We assign the destination parameters in the end to allow them to
        be identical to the inputs. */
    Point R;
    mpz_mod(R.x, T.x, ellipticCurve.p);
    mpz_mod(R.y, T.y, ellipticCurve.p);  

    return R;
}

// Implementation of the double-and-add algoirthm
Point ECC::scalarMultiplyPoints(const mpz_t& k, Point P) {
    Point T = P;

    // Perform scalar multiplication using the double-and-add algorithm
    for (int i = mpz_sizeinbase(k, 2) - 2; i >= 0; --i) {
        // Double the point
        T = doublePoint(T);

        // If the current bit of the scalar is 1, add the base point
        if (mpz_tstbit(k, i)) T = addPoints(T, P);
    }

    return T;
}

// Function to generate random numbers
void ECC::getRandomNumber(const mpz_t min, const mpz_t max, mpz_t& result) {
    // Initialize GMP random state
    gmp_randstate_t state;
    gmp_randinit_default(state);

    // Calculate the range
    mpz_t range;
    mpz_init(range);
    mpz_sub(range, max, min);

    // Generate a random number within the range
    mpz_urandomm(result, state, range);

    // Add the minimum value to the random number to shift it into the desired range
    mpz_add(result, result, min);

    // Clear temporary variables and random state
    mpz_clear(range);
    gmp_randclear(state);
}

KeyPair ECC::generateKeyPair() {
    // Initialize GMP random state
    mpz_t temp;
    mpz_init(temp);

    // Generate a random private key between 1 and curve order - 1
    mpz_t min;
    mpz_init(min);
    mpz_set_ui(min, 1);
    getRandomNumber(min, ellipticCurve.n - 1, temp);

    // Calculate the public key
    Point pubKeyPoint = scalarMultiplyPoints(temp, ellipticCurve.generator);
    KeyPair T(temp, pubKeyPoint);

    // Clean up
    mpz_clear(min);
    mpz_clear(temp);

    return T;
}

void ECC::setKeyPair(const std::string& strKey) {
    mpz_t n;
    mpz_init(n);
    stringToGMP(strKey, n);

    KeyPair T(n, scalarMultiplyPoints(n, ellipticCurve.generator));

    mpz_clear(n);

    keyPair = T;
}