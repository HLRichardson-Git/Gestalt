/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsa.cpp
 *
 * This file contains the implementation of the Elliptic Curve Digital ECDSASignature Algorithm (ECDSA) for Gestalt.
 * ECDSA is a widely used cryptographic algorithm for generating and verifying digital signatures
 * based on elliptic curve cryptography (ECC). It provides a secure and efficient method for
 * authentication and integrity verification in various applications such as secure messaging,
 * digital certificates, and blockchain technology.
 *
 * This class provides functionality for signature generation, signature verification, and other
 * operations necessary for implementing ECDSA-based security protocols.
 *
 * References:
 * - "Understanding Cryptography" by Christof Paar and Jan Pelzl
 * - "Guide to Elliptic Curve Cryptography" by Darrel Hankerson, Alfred Menezes, Scott Vanstone
 * - "FIPS 186-5 Digital ECDSASignature Standard (DSS)" by NIST
 *
 */

#include <gestalt/ecdsa.h>

BigInt ECDSA::prepareMessage(const SecureBytes& messageHash) {
    size_t maxBytes = (ellipticCurve.bitLength + 7) / 8;
    size_t useBytes = std::min(messageHash.size(), maxBytes);
    return BigInt::fromBytes(messageHash.data(), useBytes);
}

bool ECDSA::isInvalidSignature(const ECDSASignature& S) {
    return (S.r.isZero() || S.s.isZero());
}

ECDSASignature ECDSA::signMessage(const SecureBytes& message, HashAlgorithm hashAlg) {
    SecureBytes messageHash = hash(hashAlg)(message);
    BigInt e = prepareMessage(messageHash);

    ECDSASignature signature;
    BigInt randomNumber;
    do {
        randomNumber = BigInt::random(BigInt(1), ellipticCurve.n - 1);
        signature = generateSignature(e, randomNumber);
    } while (isInvalidSignature(signature)); // Check if r = 0 or s = 0

    return signature;
}

ECDSASignature ECDSA::signMessage(const SecureBytes& message, const BigInt& K, HashAlgorithm hashAlg) {
    SecureBytes messageHash = hash(hashAlg)(message);
    BigInt e = prepareMessage(messageHash);

    ECDSASignature signature = generateSignature(e, K);

    if (isInvalidSignature(signature)) throw std::invalid_argument("Error: Private key derives invalid signature.");

    return signature;
}

ECDSASignature ECDSA::generateSignature(const BigInt& e, const BigInt& k) {
    // Calculate R = k*G (where G is the generator point)
    Point R = scalarMultiplyPoints(k, ellipticCurve.generator);

    // Take the x-coordinate of R and make sure it is a valid integer
    BigInt xCoordinateOfR = fieldElementToInteger(R.x);

    // Calculate r = xCoordinateOfR mod n
    ECDSASignature signature;
    signature.r = xCoordinateOfR % ellipticCurve.n;

    BigInt kInverse = k.modInverse(ellipticCurve.n);

    // Calculate s = (e + d * r) * kInverse mod n
    signature.s = ((e + keyPair.privateKey * signature.r) * kInverse) % ellipticCurve.n;

    return signature;
}

bool ECDSA::verifySignature(const SecureBytes& message, const ECDSAPublicKey& peerPublicKey, const ECDSASignature& signature, HashAlgorithm hashAlg) {
    SecureBytes messageHash = hash(hashAlg)(message);
    BigInt e = prepareMessage(messageHash);

    Curve peerCurve = getCurveParams(peerPublicKey.getPublicKeyCurve());

    BigInt sInverse = signature.s.modInverse(peerCurve.n);

    // Calculate u1 = sInverse * e mod n
    BigInt u1 = (sInverse * e) % peerCurve.n;

    // Calculate u2 = sInverse * r mod n
    BigInt u2 = (sInverse * signature.r) % peerCurve.n;

    // Calculate P = u1*G + u2*publicKey
    Point P = addPoints(scalarMultiplyPoints(u1, peerCurve.generator),
                        scalarMultiplyPoints(u2, peerPublicKey.getPublicKey()));

    // Take the x-coordinate of P and make sure it is a valid integer
    BigInt xCoordinateOfP = fieldElementToInteger(P.x);

    // Compare r with P.x mod n
    BigInt P_mod_n = xCoordinateOfP % peerCurve.n;
    return (signature.r == P_mod_n);
}