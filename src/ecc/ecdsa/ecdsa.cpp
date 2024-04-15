/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsa.cpp
 *
 * This file contains the implementation of Gestalts ECDSA security functions.
 */

#include <cmath>

#include <gestalt/ecdsa.h>
#include "infint/InfInt.h"
#include "utils.h"

KeyPair ECDSA::generateKeyPair() {
    InfInt privateKey = ecc.getRandomNumber(1, ecc.curve.n - 1);
    Point publicKey = ecc.scalarMultiplyPoints(privateKey, ecc.curve.basePoint);
    return {publicKey, privateKey};
}

KeyPair ECDSA::setKeyPair(const InfInt& privateKey) {
    InfInt priv = privateKey;
    Point publicKey = ecc.scalarMultiplyPoints(priv, ecc.curve.basePoint);
    return {publicKey, priv};
}

InfInt ECDSA::prepareMessage(const std::string& message) {
    InfInt hashByteLen = message.length() * 4;
    std::string E;

    if (hashByteLen >= ecc.curve.bitLength) {
        E = message.substr(0, ecc.curve.bitLength);
    } else {
        E = message;
    }

    return ecc.hexStringToInteger(E);
}

InfInt ECDSA::fieldElementToInteger(const InfInt& fieldElement, const InfInt& modulus) {
    // If the modulus is an odd prime, no conversion is needed
    if (modulus % 2 == 1) {
        return fieldElement;
    }
    // If the modulus is a power of 2, convert the field element to an integer
    // by evaluating the binary polynomial at x = 2
    else {
        InfInt result = 0;
        InfInt temp = 1;
        InfInt element = fieldElement;
        while (element > 0) {
            if (element % 2 == 1) {
                result += temp;
            }
            temp *= 2;
            element /= 2;
        }
        return result;
    }
}

Signature ECDSA::signMessage(const std::string& message, const KeyPair& keyPair) {
    InfInt e = prepareMessage(message);
    InfInt k = ecc.getRandomNumber(0, ecc.curve.n);
    return generateSignature(e, keyPair, k);
}

Signature ECDSA::signMessage(const std::string& message, const KeyPair& keyPair, const InfInt& k) {
    InfInt e = prepareMessage(message);
    return generateSignature(e, keyPair, k);
}

Signature ECDSA::generateSignature(const InfInt& e, const KeyPair& keyPair, const InfInt& k) {
    Signature S;
    Point R = ecc.scalarMultiplyPoints(k, ecc.curve.basePoint);
    S.r = ecc.mod(fieldElementToInteger(R.x, ecc.curve.n), ecc.curve.n);
    InfInt kInverse = ecc.modInverse(k, ecc.curve.n); 
    S.s = ecc.mod(((e + (keyPair.privateKey * S.r)) * kInverse), ecc.curve.n);
    return S;
}

bool ECDSA::verifySignature(const std::string& message, const Signature signature, const Point& publicKey) {
    InfInt e = prepareMessage(message);
    InfInt sInverse = ecc.modInverse(signature.s, ecc.curve.n);
    InfInt u1 = ecc.mod(sInverse * e, ecc.curve.n);
    InfInt u2 = ecc.mod(sInverse * signature.r, ecc.curve.n);
    Point P = ecc.addPoints(ecc.scalarMultiplyPoints(u1, ecc.curve.basePoint), ecc.scalarMultiplyPoints(u2, publicKey));
    return signature.r == ecc.mod(P.x, ecc.curve.n);
}