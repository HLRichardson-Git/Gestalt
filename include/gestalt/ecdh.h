/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdh.h
 *
 * This file contains declarations for Elliptic Curve Diffie-Hellman Algorithm (ECDH) for Gestalt.
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

#pragma once

#include "../src/ecc/ecc.h"

class ECDH : public ECC {
private:

    Point peerPublicKey;

    std::string keyToString(const Point& point) const;
public:

    ECDH() : ECC(StandardCurve::secp256k1) { keyPair = generateKeyPair(); }
    ECDH(StandardCurve curve) : ECC(curve) { keyPair = generateKeyPair(); }
    ECDH(StandardCurve curve, const KeyPair& givenKeyPair) : ECC(curve) { setKeyPair(givenKeyPair); }
    ECDH(StandardCurve curve, const std::string& strKeyPair) : ECC(curve) { setKeyPair(strKeyPair); }
    ECDH(const std::string& strKeyPair) : ECC(StandardCurve::secp256k1) { setKeyPair(strKeyPair); }

	~ECDH() {}

    Point givePublicKey() const;
    void getPublicKey(const Point& givenPublicKey);
    std::string computeSharedSecret();
    std::string computeSharedSecret(const Point& peerPublicKey);

    friend class TestECDH;
};