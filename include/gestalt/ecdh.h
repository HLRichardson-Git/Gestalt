/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
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
#include <gestalt/secure_bytes.h>

class ECDH : public ECC {
private:
    SecureBytes pointToSecureBytes(const Point& point) const;

    friend class ECDH_Test;
public:

    ECDH() : ECC(StandardCurve::secp256k1) { keyPair = generateKeyPair(); }
    ECDH(StandardCurve curve) : ECC(curve) { keyPair = generateKeyPair(); }
    ECDH(StandardCurve curve, const ECCKeyPair& givenKeyPair) : ECC(curve) { setKeyPair(givenKeyPair); }
    ECDH(StandardCurve curve, const BigInt& privKey) : ECC(curve) { setKeyPair(privKey); }
    ECDH(const BigInt& privKey) : ECC(StandardCurve::secp256k1) { setKeyPair(privKey); }

	~ECDH() {}

    ECDHPublicKey getPublicKey() const { return keyPair.getPublicKey(); };
    SecureBytes computeSharedSecret(const ECDHPublicKey& peerPublicKey);
};