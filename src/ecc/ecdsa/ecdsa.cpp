/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsa.cpp
 *
 * This file contains the implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA) for Gestalt.
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
 * - "FIPS 186-5 Digital Signature Standard (DSS)" by NIST
 *
 */

#include <gestalt/ecdsa.h>

void ECDSA::prepareMessage(const std::string& messageHash, mpz_t& result) {
    std::string hashWithoutPrefix = messageHash;
    if (messageHash.compare(0, 2, "0x") == 0) {
        hashWithoutPrefix = messageHash.substr(2);
    }

    size_t hashBitLength = hashWithoutPrefix.length() * 4;

    if (hashBitLength >= ellipticCurve.bitLength) {
        std::string truncatedHash = hashWithoutPrefix.substr(0, ellipticCurve.bitLength / 4);
        mpz_set_str(result, truncatedHash.c_str(), 16);
    } else {
        mpz_set_str(result, hashWithoutPrefix.c_str(), 16);
    }
}

bool ECDSA::isInvalidSignature(Signature S) {
    // mpz_cmp returns a positive value if l > r, 0 if l = r, and a negative value if l < r
    return (mpz_cmp_ui(S.r, 0) == 0 || mpz_cmp_ui(S.s, 0) == 0);
}

Signature ECDSA::signMessage(const std::string& message, HashAlgorithm hashAlg) {
    std::string messageHash = hash(hashAlg)(message);

    mpz_t e;
    mpz_init(e);
    prepareMessage(messageHash, e);

    mpz_t randomNumber, minBound;
    mpz_init(randomNumber);
    mpz_init_set_ui(minBound, 1); // Its easier to set minBound here as mpz_t rather than in getRandomNumber

    Signature signature;
    do {
        getRandomNumber(minBound, ellipticCurve.n - 1, randomNumber);
        signature = generateSignature(e, randomNumber);
    } while(isInvalidSignature(signature)); // Check if r = 0 or s = 0

    mpz_clears(randomNumber, e, minBound, NULL);

    return signature;
}

Signature ECDSA::signMessage(const std::string& message, BigInt& K, HashAlgorithm hashAlg) {
    std::string messageHash = hash(hashAlg)(message);

    mpz_t e;
    mpz_init(e);
    prepareMessage(messageHash, e);

    Signature signature = generateSignature(e, K.n);

    if(isInvalidSignature(signature)) throw std::invalid_argument("Error: Private key derives invalid signature.");

    mpz_clear(e);

    return signature;
}

Signature ECDSA::generateSignature(const mpz_t& e, mpz_t& k) {
    // Calculate R = k*A (where A is the generator point)
    Point R = scalarMultiplyPoints(k, ellipticCurve.generator);

    // Take the x-coordiante of R and make sure it is a valid integer.
    mpz_t xCoordinateOfR;
    mpz_init(xCoordinateOfR);
    fieldElementToInteger(R.x, xCoordinateOfR);

    // Calculate r = xCoordinateOfR mod n
    Signature signature;
    mpz_mod(signature.r, xCoordinateOfR, ellipticCurve.n);

    mpz_t kInverse;
    mpz_init(kInverse);
    mpz_invert(kInverse, k, ellipticCurve.n);

    // Calculate s = (e + d * r) kInverse mod n
    mpz_t temp;
    mpz_init(temp);
    mpz_mul(temp, keyPair.privateKey, signature.r); // temp = privateKey * r
    mpz_add(temp, e, temp); // temp = e + privateKey * r
    mpz_mul(temp, temp, kInverse); // temp = (e + privateKey * r) * kInverse
    mpz_mod(signature.s, temp, ellipticCurve.n); // s = (e + privateKey * r) * kInverse mod n

    mpz_clears(xCoordinateOfR, kInverse, temp, NULL);

    return signature;
}

bool ECDSA::verifySignature(const std::string& message, const ECDSAPublicKey& peerPublicKey, const Signature& signature, HashAlgorithm hashAlg) {
    std::string messageHash = hash(hashAlg)(message);

    mpz_t e;
    mpz_init(e);
    prepareMessage(messageHash, e);

    Curve peerCurve = getCurveParams(peerPublicKey.getPublicKeyCurve());

    mpz_t sInverse;
    mpz_init(sInverse);
    mpz_invert(sInverse, signature.s, peerCurve.n);

    // Calculate u1 = sInverse * e mod n
    mpz_t u1;
    mpz_init(u1);
    mpz_mul(u1, sInverse, e);
    mpz_mod(u1, u1, peerCurve.n);

    // Calculate u2 = sInverse * r mod n
    mpz_t u2;
    mpz_init(u2);
    mpz_mul(u2, sInverse, signature.r);
    mpz_mod(u2, u2, peerCurve.n);

    // Calculate P = u1*G + u2*publicKey
    Point P = addPoints(scalarMultiplyPoints(u1, peerCurve.generator), 
                        scalarMultiplyPoints(u2, peerPublicKey.getPublicKey()));

    // Take the x-coordiante of R and make sure it is a valid integer.
    mpz_t xCoordinateOfP;
    mpz_init(xCoordinateOfP);
    fieldElementToInteger(P.x, xCoordinateOfP);

    // Calculate P.x mod n
    mpz_t P_mod_n;
    mpz_init(P_mod_n);
    mpz_mod(P_mod_n, xCoordinateOfP, peerCurve.n);

    // Compare r with P.x mod n
    bool verified = (mpz_cmp(signature.r, P_mod_n) == 0);

    mpz_clears(e, sInverse, u1, u2, xCoordinateOfP, P_mod_n, NULL);

    return verified;
}