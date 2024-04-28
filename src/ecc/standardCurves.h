/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * standardCurves.h
 *
 * This file contains popular standard curves uses in Elliptic Curve Cryptography.
 *
 * References:
 * - 
 */
#pragma once

//#include "../../external/infint/InfInt.h"
#include <gmp.h>

/*struct Point {
    InfInt x;
    InfInt y;
};

struct Curve {
    InfInt a;
    InfInt b;
    InfInt p;
    Point basePoint;
    InfInt n;
    size_t bitLength;
};*/

typedef struct {
    mpz_t x;
    mpz_t y;
} Point;

typedef struct {
    mpz_t a;
    mpz_t b;
    mpz_t p;
    Point basePoint;
    mpz_t n;
    size_t bitLength;
} Curve;

/*const Curve test = {
    2,
    2,
    17,
    {5, 1},
    19,
    1
};

const Curve Curve25519 = {
    2,
    2,
    17,
    {5, 1},
    19,
    1
};

const Curve Curve383187 = {
    3,
    4,
    23,
    {7, 2},
    29,
    1
};

const Curve Curve41417 = {
    5,
    6,
    31,
    {11, 3},
    41,
    1
};

const Curve P256 = {
    "115792089210356248762697446949407573530086143415290314195533631308867097853948",
    "41058363725152142129326129780047268409114441015993725554835256314039467401291",
    "115792089210356248762697446949407573530086143415290314195533631308867097853951",
    {"48439561293906451759052585252797914202762949526041747995844080717082404635286",
     "36134250956749795798585127919587881956611106672985015071877198253568414405109"},
    "115792089210356248762697446949407573529996955224135760342422259061068512044369",
    256
};

const Curve secp256k1 = {
    "0",
    "7",
    "115792089237316195423570985008687907853269984665640564039457584007908834671663",
    {"55066263022277343669578718895168534326250603453777594175500187360389116729240",
     "32670510020758816978083085130507043184471273380659243275938904335757337482424"},
    "115792089237316195423570985008687907852837564279074904382605163141518161494337",
    256
};*/

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