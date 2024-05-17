/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsa.h
 *
 * This file contains declarations for Elliptic Curve Digital Signature Algorithm (ECDSA) for Gestalt.
 * ECDSA is a cryptographic algorithm used for generating and verifying digital signatures based on
 * elliptic curve cryptography (ECC). It offers efficient signature generation and verification
 * while providing a high level of security, making it suitable for a wide range of applications
 * such as secure communication protocols and digital authentication systems.
 *
 * This class provides functionality for signature generation, signature verification, and other 
 * operations necessary for implementing ECDSA-based security protocols.
 *
 * References:
 * - "Understanding Cryptography" by Christof Paar and Jan Pelzl
 * - "Guide to Elliptic Curve Cryptography" by Darrel Hankerson, Alfred Menezes, Scott Vanstone
 * - "FIPS 186-5 Digital Signature Standard (DSS)" by NIST
 *
 */


#pragma once

#include <string>

#include "../src/ecc/ecc.h"

class ECDSA : public ECC {
private:

    void prepareMessage(const std::string& messageHash, mpz_t& result);
    void fieldElementToInteger(const mpz_t& fieldElement, mpz_t result);

    Signature generateSignature(const mpz_t& e, mpz_t& k);
public:

    ECDSA() : ECC(StandardCurve::secp256k1) { keyPair = generateKeyPair(); }
    ECDSA(StandardCurve curve) : ECC(curve) { keyPair = generateKeyPair(); }
    ECDSA(StandardCurve curve, const KeyPair& givenKeyPair) : ECC(curve) { setKeyPair(givenKeyPair); }
    ECDSA(StandardCurve curve, const std::string& strKeyPair) : ECC(curve) { setKeyPair(strKeyPair); }
    ECDSA(const std::string& strKeyPair) : ECC(StandardCurve::secp256k1) { setKeyPair(strKeyPair); }

	~ECDSA() {}

    Signature signMessage(const std::string& messageHash);
    Signature signMessage(const std::string& messageHash, BigInt& K);
    bool verifySignature(const std::string& messageHash, const Signature signature);
};