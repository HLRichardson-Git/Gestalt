/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecc.cpp
 *
 * This file contains the implementation of Elliptic Curve Cryptography (ECC) algorithms for Gestalt.
 * ECC is a powerful cryptographic technique based on the algebraic properties of elliptic curves
 * over finite fields.
 *
 * This implementation covers key operations in ECC, including point addition, point doubling,
 * scalar multiplication, and the ECC arithmetic required for cryptographic operations.
 *
 * References:
 * - "Guide to Elliptic Curve Cryptography" by Darrel Hankerson, Alfred Menezes, Scott Vanstone
 * - "Elliptic Curves: Number Theory and Cryptography" by Lawrence C. Washington
 * - "Understanding Cryptography" by Christof Paar and Jan Pelzl
 *
 */

#include "ecc.h"
#include "asn1/der/der.h"
#include "asn1/pem/pem.h"

Point ECC::addPoints(Point P, Point Q) {
    if (isIdentityPoint(P)) return Q;
    if (isIdentityPoint(Q)) return P;

    if (P.x == Q.x && P.y == Q.y) return doublePoint(P);
    if (P.x == Q.x && P.y != Q.y) return Point();

    const BigInt& p = ellipticCurve.p;

    // s = (y2 - y1) / (x2 - x1) mod p
    BigInt s = ((Q.y - P.y) * (Q.x - P.x).modInverse(p)) % p;

    // rx = s^2 - x1 - x2 mod p
    BigInt rx = (s * s - P.x - Q.x) % p;

    // ry = s(x1 - rx) - y1 mod p
    BigInt ry = (s * (P.x - rx) - P.y) % p;

    return Point(rx, ry);
}

Point ECC::doublePoint(Point P) {
    if (isIdentityPoint(P)) return P;

    const BigInt& p = ellipticCurve.p;

    // s = (3x^2 + a) / (2y) mod p
    BigInt s = ((P.x * P.x * BigInt(3) + ellipticCurve.a) * (P.y * BigInt(2)).modInverse(p)) % p;

    // rx = s^2 - 2x mod p
    BigInt rx = (s * s - P.x * BigInt(2)) % p;

    // ry = s(x - rx) - y mod p
    BigInt ry = (s * (P.x - rx) - P.y) % p;

    return Point(rx, ry);
}

// Implementation of the double-and-add algorithm
Point ECC::scalarMultiplyPoints(const BigInt& k, Point P) {
    if (k == ellipticCurve.n) return Point();

    Point result;
    size_t nBits = k.bitLength();
    for (int i = nBits - 1; i >= 0; --i) {
        result = doublePoint(result);

        // If the current bit of the scalar is 1, add the base point
        if (k.testBit(i)) result = addPoints(result, P);
    }

    return result;
}

BigInt ECC::fieldElementToInteger(const BigInt& fieldElement) {
    if (ellipticCurve.n.isOdd() && ellipticCurve.n.isProbablyPrime()) {
        return fieldElement;
    }

    // Convert a binary field element to an integer by evaluating the polynomial at x = 2
    BigInt result(0), temp(1), element = fieldElement;
    while (element > 0) {
        if (element.isOdd()) result = result + temp;
        temp = temp * BigInt(2);
        element = element.shiftRight(1);
    }
    return result;
}

bool ECC::isInDomainRange(const BigInt& k) {
    return (k >= 0 && k < ellipticCurve.p);
}

bool ECC::isIdentityPoint(Point P) {
    return (P.x.isZero() && P.y.isZero());
}

bool ECC::isPointOnCurve(Point P) {
    return (isInDomainRange(P.x)) && (isInDomainRange(P.y));
}

std::string ECC::isValidPublicKey(const ECDSAPublicKey P) {
    if (!isPointOnCurve(P.getPublicKey())) return "Error: Given Public Key is not on the curve.";
    if (isIdentityPoint(P.getPublicKey())) return "Error: Given Public Key is the Identity element.";

    // Check n*P = identity
    Point result = scalarMultiplyPoints(ellipticCurve.n, P.getPublicKey());
    if (!isIdentityPoint(result)) {
        return "Error: Given Public key multiplied by curve modulus is not Identity Element.";
    }

    return ""; // Return an empty string if the public key is valid
}

std::string ECC::isValidKeyPair(const ECCKeyPair& K) {
    if (!isInDomainRange(K.privateKey)) return "Error: Given Private Key is not in range [1, n - 1].";
    std::string temp = isValidPublicKey(K.publicKey);
    if (temp != "") return temp;

    // Check d*G = pubKey
    Point result = scalarMultiplyPoints(K.privateKey, ellipticCurve.generator);
    if (result.x != K.publicKey.getPublicKey().x || result.y != K.publicKey.getPublicKey().y) {
        return "Error: Pair-wise consistency check failed.";
    }

    return ""; // Return an empty string if the key pair is valid
}

ECCKeyPair ECC::generateKeyPair() {
    BigInt privKey;
    Point pubKeyPoint;
    do {
        privKey = BigInt::random(BigInt(1), ellipticCurve.n - 1);
        pubKeyPoint = scalarMultiplyPoints(privKey, ellipticCurve.generator);
    } while (isIdentityPoint(pubKeyPoint)); // ensure the public key is not the identity element

    return ECCKeyPair(privKey, ECDSAPublicKey(pubKeyPoint));
}

void ECC::setKeyPair(const ECCKeyPair& newKeyPair) {
    std::string validationError = isValidKeyPair(newKeyPair);
    if (!validationError.empty()) {
        throw std::invalid_argument(validationError);
    }
    keyPair = newKeyPair;
}

void ECC::setKeyPair(const BigInt& key) {
    ECCKeyPair result(key, scalarMultiplyPoints(key, ellipticCurve.generator));
    if (isIdentityPoint(result.publicKey.getPublicKey())) throw
        std::invalid_argument("Error: Given Private Key derives identity public key.");

    keyPair = result;
}

// ECCPublicKey DER/PEM encoding

std::vector<uint8_t> ECCPublicKey::toDER(EccKeyFormat format) const {
    DEREncoder encoder;
    switch (format) {
        case EccKeyFormat::SEC1: return encoder.encodeECPublicKeyToSEC1(*this);
        case EccKeyFormat::PKCS8:
        default: return encoder.encodeECPublicKeyToPKCS8(*this);
    }
}

void ECCPublicKey::fromDER(const std::vector<uint8_t>& der, EccKeyFormat format) {
    DERDecoder decoder(der);
    ECDSAPublicKey decoded;
    switch (format) {
        case EccKeyFormat::SEC1:
            decoded = decoder.decodeECPublicKeyFromSEC1();
            break;
        case EccKeyFormat::PKCS8:
        default:
            decoded = decoder.decodeECPublicKeyFromPKCS8();
            break;
    }
    *this = ECCPublicKey(decoded.getPublicKey(), decoded.getPublicKeyCurve());
}

std::string ECCPublicKey::toPEM(EccKeyFormat format) const {
    switch (format) {
        case EccKeyFormat::SEC1: return PEMEncoder::encodeECPublicKeyToSEC1(*this);
        case EccKeyFormat::PKCS8:
        default: return PEMEncoder::encodeECPublicKeyToPKCS8(*this);
    }
}

void ECCPublicKey::fromPEM(const std::string& pem, EccKeyFormat format) {
    ECDSAPublicKey decoded;
    switch (format) {
        case EccKeyFormat::SEC1:
            decoded = PEMDecoder::decodeECPublicKeyFromSEC1(pem);
            break;
        case EccKeyFormat::PKCS8:
        default:
            decoded = PEMDecoder::decodeECPublicKeyFromPKCS8(pem);
            break;
    }
    *this = ECCPublicKey(decoded.getPublicKey(), decoded.getPublicKeyCurve());
}

// ECCKeyPair DER/PEM encoding

std::vector<uint8_t> ECCKeyPair::toDER(EccKeyFormat format) const {
    DEREncoder encoder;
    switch (format) {
        case EccKeyFormat::SEC1: return encoder.encodeECPrivateKeyToSEC1(*this);
        case EccKeyFormat::PKCS8:
        default: return encoder.encodeECPrivateKeyToPKCS8(*this);
    }
}

void ECCKeyPair::fromDER(const std::vector<uint8_t>& der, EccKeyFormat format) {
    DERDecoder decoder(der);
    ECCKeyPair decoded;
    switch (format) {
        case EccKeyFormat::SEC1:
            decoded = decoder.decodeECPrivateKeyFromSEC1();
            break;
        case EccKeyFormat::PKCS8:
        default:
            decoded = decoder.decodeECPrivateKeyFromPKCS8();
            break;
    }
    privateKey = decoded.privateKey;
    publicKey = decoded.publicKey;
}

std::string ECCKeyPair::toPEM(EccKeyFormat format) const {
    switch (format) {
        case EccKeyFormat::SEC1: return PEMEncoder::encodeECPrivateKeyToSEC1(*this);
        case EccKeyFormat::PKCS8:
        default: return PEMEncoder::encodeECPrivateKeyToPKCS8(*this);
    }
}

void ECCKeyPair::fromPEM(const std::string& pem, EccKeyFormat format) {
    ECCKeyPair decoded;
    switch (format) {
        case EccKeyFormat::SEC1:
            decoded = PEMDecoder::decodeECPrivateKeyFromSEC1(pem);
            break;
        case EccKeyFormat::PKCS8:
        default:
            decoded = PEMDecoder::decodeECPrivateKeyFromPKCS8(pem);
            break;
    }
    privateKey = decoded.privateKey;
    publicKey = decoded.publicKey;
}