/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsa.h
 *
 * This file contains the definitions of Gestalts ECDSA security functions.
 */

#pragma once

#include <string>

#include "../src/ecc/ecc.h"
#include "../../external/infint/InfInt.h"

struct Signature {
    InfInt r;
    InfInt s;
};

class ECDSA {
private:

    ECC ecc;

    InfInt prepareMessage(const std::string& message);
    InfInt fieldElementToInteger(const InfInt& fieldElement, const InfInt& modulus);

    Signature generateSignature(const InfInt& e, const KeyPair& keyPair, const InfInt& k);
public:

    ECDSA(StandardCurve curve = StandardCurve::secp256k1) : ecc(curve) {
        // Initialize ECDSA with the selected standard curve
    }
	~ECDSA() {}

    KeyPair generateKeyPair();
    KeyPair setKeyPair(const InfInt& privateKey);
    Signature signMessage(const std::string& message, const KeyPair& keyPair);
    Signature signMessage(const std::string& message, const KeyPair& keyPair, const InfInt& k);
    bool verifySignature(const std::string& message, const Signature signature, const Point& publicKey);
};