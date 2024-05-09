/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * standardCurves.h
 *
 * This file contains the implementation of Gestalts ECC security functions.
 */

#include <iostream>
#include <gmp.h>

class Point;

// Enumerate the available standard curves
enum class StandardCurve {
    test,
    //Curve25519,
    //Curve383187,
    //Curve41417,
    P256,
    secp256k1,
    // Add more standard curves as needed
};

struct Curve {
    mpz_t a;
    mpz_t b;
    mpz_t p;
    Point basePoint;
    mpz_t n;
    size_t bitLength;
};

inline Curve init_test() {
    Curve test;
    mpz_inits(test.a, test.b, test.p, test.basePoint.x, test.basePoint.y, test.n, NULL);
    mpz_set_str(test.a, "2", 16);
    mpz_set_str(test.b, "2", 16);
    mpz_set_str(test.p, "11", 16);
    mpz_set_str(test.basePoint.x, "5", 16);
    mpz_set_str(test.basePoint.y, "1", 16);
    mpz_set_str(test.n, "13", 16);
    test.bitLength = 1;
    return test;
}

inline Curve init_p256() {
    Curve P256;
    mpz_inits(P256.a, P256.b, P256.p, P256.basePoint.x, P256.basePoint.y, P256.n, NULL);
    mpz_set_str(P256.a, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
    mpz_set_str(P256.b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    mpz_set_str(P256.p, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    mpz_set_str(P256.basePoint.x, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    mpz_set_str(P256.basePoint.y, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    mpz_set_str(P256.n, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    P256.bitLength = 256;
    return P256;
}

inline Curve init_secp256k1() {
    Curve secp256k1;
    mpz_inits(secp256k1.a, secp256k1.b, secp256k1.p, secp256k1.basePoint.x, secp256k1.basePoint.y, secp256k1.n, NULL);
    mpz_set_str(secp256k1.a, "0", 16);
    mpz_set_str(secp256k1.b, "7", 16);
    mpz_set_str(secp256k1.p, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    mpz_set_str(secp256k1.basePoint.x, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    mpz_set_str(secp256k1.basePoint.y, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
    mpz_set_str(secp256k1.n, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    secp256k1.bitLength = 256;
    return secp256k1;
}

inline Curve getCurveParams(StandardCurve curve) {
    switch (curve) {
        case StandardCurve::test:
            return init_test();
            //case StandardCurve::Curve25519:
            //    return Curve25519;
            //case StandardCurve::Curve383187:
            //    return Curve383187;
            //case StandardCurve::Curve41417:
            //    return Curve41417;
            case StandardCurve::P256:
                return init_p256();
            case StandardCurve::secp256k1:
                return init_secp256k1();
            // Add more cases for additional standard curves
            default:
                throw std::invalid_argument("Invalid standard curve");
    }
}