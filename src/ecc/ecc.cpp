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

#include <gmp.h>

#include "ecc.h"

Point ECC::addPoints(Point P, Point Q) {
    if (isIdentityPoint(P)) return Q;
    if (isIdentityPoint(Q)) return P;

    if (mpz_cmp(P.x, Q.x) == 0 && mpz_cmp(P.y, Q.y) == 0) return doublePoint(P);
    if (mpz_cmp(P.x, Q.x) == 0 && mpz_cmp(P.y, Q.y) != 0) return Point("0", "0");

    Point R;
    mpz_t s;
    mpz_init(s);

    mpz_t temp1, temp2;
    mpz_init(temp1);
    mpz_init(temp2);

    // s = (y2 - y1) / (x2 - x1)
    mpz_sub(temp1, Q.y, P.y);
    mpz_sub(temp2, Q.x, P.x);
    mpz_invert(temp2, temp2, ellipticCurve.p);
    mpz_mul(s, temp1, temp2);
    mpz_mod(s, s, ellipticCurve.p);

    // rx = s^2 - x1 - x2
    mpz_mul(R.x, s, s);
    mpz_sub(R.x, R.x, P.x);
    mpz_sub(R.x, R.x, Q.x);
    mpz_mod(R.x, R.x, ellipticCurve.p);

    // ry = s(x1 - rx) - y1
    mpz_sub(temp1, P.x, R.x);
    mpz_mul(R.y, s, temp1);
    mpz_sub(R.y, R.y, P.y);
    mpz_mod(R.y, R.y, ellipticCurve.p);

    mpz_clear(s);
    mpz_clear(temp1);
    mpz_clear(temp2);

    return R;
}

Point ECC::doublePoint(Point P) {
    if (isIdentityPoint(P)) return P;

    Point R;
    mpz_t s;
    mpz_init(s);

    mpz_t temp1, temp2;
    mpz_init(temp1);
    mpz_init(temp2);

    // s = (3x^2 + a) / (2y)
    mpz_mul(temp1, P.x, P.x);
    mpz_mul_ui(temp1, temp1, 3);
    mpz_add(temp1, temp1, ellipticCurve.a);
    mpz_mul_ui(temp2, P.y, 2);
    mpz_invert(temp2, temp2, ellipticCurve.p);
    mpz_mul(s, temp1, temp2);
    mpz_mod(s, s, ellipticCurve.p);

    // rx = s^2 - 2x
    mpz_mul(R.x, s, s);
    mpz_mul_ui(temp1, P.x, 2);
    mpz_sub(R.x, R.x, temp1);
    mpz_mod(R.x, R.x, ellipticCurve.p);

    // ry = s(x - rx) - y
    mpz_sub(temp1, P.x, R.x);
    mpz_mul(R.y, s, temp1);
    mpz_sub(R.y, R.y, P.y);
    mpz_mod(R.y, R.y, ellipticCurve.p);

    mpz_clear(s);
    mpz_clear(temp1);
    mpz_clear(temp2);

    return R;
}

// Implementation of the double-and-add algoirthm
Point ECC::scalarMultiplyPoints(const mpz_t& k, Point P) {
    if(mpz_cmp(k, ellipticCurve.n) == 0) return Point("0", "0");

    Point result;
    Point temp = P;

    size_t n_bits = mpz_sizeinbase(k, 2);
    for (int i = n_bits - 1; i >= 0; --i) {
        result = doublePoint(result);
        
        // If the current bit of the scalar is 1, add the base point
        if (mpz_tstbit(k, i)) result = addPoints(result, temp);
    }

    return result;
}

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

    mpz_clear(range);
    gmp_randclear(state);
}

void ECC::fieldElementToInteger(const mpz_t& fieldElement, mpz_t result) {
    mpz_t temp, element;
    mpz_inits(temp, element, NULL);
    mpz_set(element, fieldElement);

    // If the modulus is an odd prime, no conversion is needed
    if (mpz_odd_p(ellipticCurve.n) && mpz_probab_prime_p(ellipticCurve.n, 25)) {
        mpz_set(result, element);
    } else {
        mpz_set_ui(result, 0);
        mpz_set_ui(temp, 1);
        // Convert the field element to an integer by evaluating the binary polynomial at x = 2
        while (mpz_cmp_ui(element, 0) > 0) {
            if (mpz_odd_p(element)) {
                mpz_add(result, result, temp);
            }
            mpz_mul_2exp(temp, temp, 1);
            mpz_fdiv_q_2exp(element, element, 1);
        }
    }

    mpz_clears(temp, element, NULL);
}

bool ECC::isInDomainRange(const mpz_t k) {
    // mpz_cmp returns a positive value if l > r, 0 if l = r, and a negative value if l < r
    return (mpz_cmp_ui(k, 0) >= 0 && mpz_cmp(k, ellipticCurve.p) < 0);
}

bool ECC::isIdentityPoint(Point P) {
    // mpz_cmp returns a positive value if l > r, 0 if l = r, and a negative value if l < r
    return (mpz_cmp_ui(P.x, 0) == 0 && mpz_cmp_ui(P.y, 0) == 0);
}

bool ECC::isPointOnCurve(Point P) {
    // mpz_cmp returns a positive value if l > r, 0 if l = r, and a negative value if l < r
    return (isInDomainRange(P.x)) && (isInDomainRange(P.y));
}

std::string ECC::isValidPublicKey(const ECDSAPublicKey P) {
    if (!isPointOnCurve(P.getPublicKey())) return "Error: Given Public Key is not on the curve.";
    if (isIdentityPoint(P.getPublicKey())) return "Error: Given Public Key is the Identity element.";

    // Check n*P = identity
    Point result = scalarMultiplyPoints(ellipticCurve.n, P.getPublicKey());
    if (!isIdentityPoint(result)) {
        return "Error: Given Public key multiplied by curve modulus is not Identity Element.";
    }

    return ""; // Return an empty string if the public key is valid
}

std::string ECC::isValidKeyPair(const KeyPair& K) {
    if (!isInDomainRange(K.privateKey)) return "Error: Given Private Key is not in range [1, n - 1].";
    std::string temp = isValidPublicKey(K.publicKey);
    if (temp != "") return temp;

    // Check d*G = pubKey
    Point result = scalarMultiplyPoints(K.privateKey, ellipticCurve.generator);
    if (mpz_cmp(result.x, K.publicKey.getPublicKey().x) != 0 || mpz_cmp(result.y, K.publicKey.getPublicKey().y) != 0) {
        return "Error: Pair-wise consistency check failed.";
    }

    return ""; // Return an empty string if the key pair is valid
}

KeyPair ECC::generateKeyPair() {
    mpz_t temp;
    mpz_init(temp);

    // Generate a random private key between 1 and curve order - 1
    mpz_t min;
    mpz_init(min);
    mpz_set_ui(min, 1);

    Point pubKeyPoint;
    do {
        getRandomNumber(min, ellipticCurve.n - 1, temp);
        pubKeyPoint = scalarMultiplyPoints(temp, ellipticCurve.generator);
    } while(isIdentityPoint(pubKeyPoint)); // ensure the public key is not the identity element

    KeyPair result(temp, pubKeyPoint);

    mpz_clear(min);
    mpz_clear(temp);

    return result;
}

void ECC::setKeyPair(const KeyPair& newKeyPair) {
    std::string validationError = isValidKeyPair(newKeyPair);
    if (!validationError.empty()) {
        throw std::invalid_argument(validationError);
    }
    keyPair = newKeyPair;
}

void ECC::setKeyPair(const std::string& givenKey) {
    mpz_t n;
    mpz_init(n);
    stringToGMP(givenKey, n);

    KeyPair result(n, scalarMultiplyPoints(n, ellipticCurve.generator));
    if(isIdentityPoint(result.publicKey.getPublicKey())) throw 
        std::invalid_argument("Error: Given Private Key derives identity public key.");

    mpz_clear(n);

    keyPair = result;
}