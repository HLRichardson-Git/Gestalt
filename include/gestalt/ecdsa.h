/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsa.h
 *
 * This file contains the definitions of Gestalts AES security functions.
 */

#pragma once

#include <string>

#include "../../src/ecc/eccRecources.h"

struct Signature {
    int r;
    int s;
};

class ECDSA {
private:

     Point addPoints(Point P, Point Q);
     Point doublePoint(Point P);
     Point scalarMultiplyPoints(int k, Point P);

    int getRandomNumber(int min, int max);
public:

    ECDSA();
	~ECDSA() {}

    ECDSA_KeyPair keyPair;

    ECDSA_KeyPair generateKeyPair();
    Signature signMessage(const std::string& message, const ECDSA_KeyPair& keyPair);
    bool verifySignature(const std::string& message, const Signature signature, const Point& publicKey);
};

std::tuple<int, int, int> extendedEuclidean(int a, int b);
int modInverse(int a, int m);