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

#include <gestalt/ecdsa.h>
#include "infint/InfInt.h"
#include "utils.h"

InfInt myint1 = "15432154865413186646848435184100510168404641560358";
InfInt myint2 = 156341300544608LL;

KeyPair ECDSA::generateKeyPair() {
    int privateKey = ecc.getRandomNumber(1, ecc.curve.n - 1);
    privateKey = 8;
    Point publicKey = ecc.scalarMultiplyPoints(privateKey, ecc.curve.basePoint);
    return {publicKey, privateKey};
}

Signature ECDSA::signMessage(const std::string& message, const KeyPair& keyPair) {
    Signature S;
    int k = ecc.getRandomNumber(0, ecc.curve.n);
    Point R = ecc.scalarMultiplyPoints(k, ecc.curve.basePoint);
    S.r = R.x % ecc.curve.n;
    int e = hexStringToInt(message);
    int kInverse = ecc.modInverse(k, ecc.curve.n); 
    S.s = ((e + keyPair.privateKey * S.r) * kInverse) % ecc.curve.n;
    return S;
}

bool ECDSA::verifySignature(const std::string& message, const Signature signature, const Point& publicKey) {
    int sInverse = ecc.modInverse(signature.s, ecc.curve.n);
    int w = sInverse % ecc.curve.n;
    int e = hexStringToInt(message);
    int u1 = w*e % ecc.curve.n;
    int u2 = w*signature.r % ecc.curve.n;
    Point P = ecc.addPoints(ecc.scalarMultiplyPoints(u1, ecc.curve.basePoint), ecc.scalarMultiplyPoints(u2, publicKey));
    return signature.r == P.x % ecc.curve.n;
}