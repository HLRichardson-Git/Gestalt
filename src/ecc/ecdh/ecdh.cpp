/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdh.cpp
 *
 * This file contains the implementation of Elliptic Curve Diffie-Hellman Algorithm (ECDH) for Gestalt.
 * ECDH is a cryptographic algorithm used for computing a secret shared value on an insecure channel
 * based on elliptic curve cryptography (ECC). It offers efficient a shared secret computation
 * while providing a high level of security, making it suitable for a wide range of applications
 * such as secure Key Agreement/ Establishment.
 *
 * This class provides functionality for shared secret computation necessary for implementing ECDH.
 *
 * References:
 * - "Understanding Cryptography" by Christof Paar and Jan Pelzl
 * - "FIPS SP800-56Ar3 Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm 
 *    Cryptography" by NIST
 *
 */

#include <gmp.h>

#include <gestalt/ecdh.h>

Point ECDH::givePublicKey() const {
    return keyPair.publicKey;
}

void ECDH::getPublicKey(const Point& givenPublicKey) {
    std::string validationError = isValidPublicKey(givenPublicKey);
    if (!validationError.empty()) {
        throw std::invalid_argument(validationError);
    }
    peerPublicKey = givenPublicKey;
}

std::string ECDH::computeSharedSecret() {
    Point sharedPoint = scalarMultiplyPoints(keyPair.privateKey, peerPublicKey);
    if(isIdentityPoint(sharedPoint)) throw std::invalid_argument("Error: Computed shared value is Identity element.");
    fieldElementToInteger(sharedPoint.x, sharedPoint.x);
    return keyToString(sharedPoint);
}

std::string ECDH::computeSharedSecret(const Point& givenPeerPublicKey) {
    std::string validationError = isValidPublicKey(givenPeerPublicKey);
    if (!validationError.empty()) {
        throw std::invalid_argument(validationError);
    }

    Point sharedPoint = scalarMultiplyPoints(keyPair.privateKey, givenPeerPublicKey);
    if(isIdentityPoint(sharedPoint)) throw std::invalid_argument("Error: Computed shared value is Identity element.");
    fieldElementToInteger(sharedPoint.x, sharedPoint.x);
    return keyToString(sharedPoint);
}

std::string ECDH::keyToString(const Point& point) const {
    char *cStr = mpz_get_str(NULL, 16, point.x);
    std::string str = cStr;
    return str;
}