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
public:

    ECDSA(StandardCurve curve = StandardCurve::secp256k1) : ecc(curve) {
        // Initialize ECDSA with the selected standard curve
    }
	~ECDSA() {}

    KeyPair generateKeyPair();
    KeyPair setKeyPair(const InfInt& privateKey);
    Signature signMessage(const std::string& message, const KeyPair& keyPair);
    bool verifySignature(const std::string& message, const Signature signature, const Point& publicKey);
};