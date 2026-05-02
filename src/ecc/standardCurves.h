/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * standardCurves.h
 *
 * This file contains definitions of standard elliptic curves commonly used.
 *
 * The curves defined in this file are selected from standardized sets recommended by organizations
 * such as the National Institute of Standards and Technology (NIST) and the International
 * Organization for Standardization (ISO). Each curve is specified by its parameters, including
 * the prime modulus, coefficients, generator, and order.
 *
 * The file provides functions to retrieve instances of these standard curves, allowing applications
 * to easily access predefined curve parameters for cryptographic operations.
 *
 * References:
 * - "FIPS 186-5 Digital Signature Standard (DSS)" by NIST
 * - Standard Curve Database [https://neuromancer.sk/std/] by Jan Jancar
 * 
 */

#include <iostream>
#include "bigInt/bigInt.h"

class Point;

// Enumerate the available standard curves
enum class StandardCurve {
    P192,
    P224,
    P256,
    P384,
    P521,
    secp256k1,
    // Add more standard curves as needed
};

struct Curve {
    BigInt a;
    BigInt b;
    BigInt p;
    Point generator;
    BigInt n;
    size_t bitLength;
};

inline Curve init_p192() {
    Curve P192;
    P192.a = BigInt("0xfffffffffffffffffffffffffffffffefffffffffffffffc");
    P192.b = BigInt("0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");
    P192.p = BigInt("0xfffffffffffffffffffffffffffffffeffffffffffffffff");
    P192.generator.x = BigInt("0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");
    P192.generator.y = BigInt("0x7192b95ffc8da78631011ed6b24cdd573f977a11e794811");
    P192.n = BigInt("0xffffffffffffffffffffffff99def836146bc9b1b4d22831");
    P192.bitLength = 192;
    return P192;
}

inline Curve init_p224() {
    Curve P224;
    P224.a = BigInt("0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe");
    P224.b = BigInt("0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4");
    P224.p = BigInt("0xffffffffffffffffffffffffffffffff000000000000000000000001");
    P224.generator.x = BigInt("0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21");
    P224.generator.y = BigInt("0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34");
    P224.n = BigInt("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d");
    P224.bitLength = 224;
    return P224;
}

inline Curve init_p256() {
    Curve P256;
    P256.a = BigInt("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
    P256.b = BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
    P256.p = BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    P256.generator.x = BigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    P256.generator.y = BigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    P256.n = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    P256.bitLength = 256;
    return P256;
}

inline Curve init_p384() {
    Curve P384;
    P384.a = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc");
    P384.b = BigInt("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef");
    P384.p = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff");
    P384.generator.x = BigInt("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7");
    P384.generator.y = BigInt("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");
    P384.n = BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
    P384.bitLength = 384;
    return P384;
}

inline Curve init_p521() {
    Curve P521;
    P521.a = BigInt("0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc");
    P521.b = BigInt("0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00");
    P521.p = BigInt("0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    P521.generator.x = BigInt("0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66");
    P521.generator.y = BigInt("0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650");
    P521.n = BigInt("0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409");
    P521.bitLength = 521;
    return P521;
}

inline Curve init_secp256k1() {
    Curve secp256k1;
    secp256k1.a = BigInt("0x0");
    secp256k1.b = BigInt("0x7");
    secp256k1.p = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    secp256k1.generator.x = BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    secp256k1.generator.y = BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    secp256k1.n = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    secp256k1.bitLength = 256;
    return secp256k1;
}

inline Curve getCurveParams(StandardCurve curve) {
    switch (curve) {
        case StandardCurve::P192:
            return init_p192();
        case StandardCurve::P224:
            return init_p224();
        case StandardCurve::P256:
            return init_p256();
        case StandardCurve::P384:
            return init_p384();
        case StandardCurve::P521:
            return init_p521();
        case StandardCurve::secp256k1:
            return init_secp256k1();
        // Add more cases for additional standard curves
        default:
            throw std::invalid_argument("Invalid standard curve");
    }
}