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

class ECDSA : public ECC {
private:

    void prepareMessage(const std::string& message, mpz_t& result);
    void fieldElementToInteger(const mpz_t& fieldElement, const mpz_t& modulus, mpz_t result);

    Signature generateSignature(const mpz_t& e, mpz_t& k);
public:

    ECDSA() : ECC(StandardCurve::secp256k1) { keyPair = generateKeyPair(); }
    ECDSA(StandardCurve curve) : ECC(curve) { keyPair = generateKeyPair(); }
    ECDSA(StandardCurve curve, const KeyPair& givenKeyPair) : ECC(curve) { setKeyPair(givenKeyPair); }
    ECDSA(StandardCurve curve, const std::string& strKeyPair) : ECC(curve) { setKeyPair(strKeyPair); }
    ECDSA(const std::string& strKeyPair) : ECC(StandardCurve::secp256k1) { setKeyPair(strKeyPair); }

	~ECDSA() {}

    Signature signMessage(const std::string& message);
    Signature signMessage(const std::string& message, mpz_t& k);
    bool verifySignature(const std::string& message, const Signature signature);
};