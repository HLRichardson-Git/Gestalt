/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * ecdsa.cpp
 *
 * This file contains the implementation of Gestalts ECDSA security functions.
 */

#include <cmath>
#include <gmp.h>

#include <gestalt/ecdsa.h>

KeyPair ECDSA::generateKeyPair() {
    // Initialize GMP random state
    mpz_t temp;
    mpz_init(temp);

    // Generate a random private key between 1 and curve order - 1
    mpz_t min;
    mpz_init(min);
    mpz_set_ui(min, 1);
    ecc.getRandomNumber(min, ecc.curve.n - 1, temp);

    // Calculate the public key
    Point pubKeyPoint = ecc.scalarMultiplyPoints(temp, ecc.curve.basePoint);
    KeyPair T(temp, pubKeyPoint);

    // Clean up
    mpz_clear(min);
    mpz_clear(temp);

    return T;
}

KeyPair ECDSA::setKeyPair(const std::string& strKey) {
    mpz_t n;
    mpz_init(n);
    stringToGMP(strKey, n);

    KeyPair T(n, ecc.scalarMultiplyPoints(n, ecc.curve.basePoint));

    mpz_clear(n);
    return T;
}

void ECDSA::prepareMessage(const std::string& message, mpz_t& result) {
    // Calculate the length of the hash in bits
    size_t hashBitLen = message.length() * 4;

    // Check if the hash length exceeds the curve's bit length
    if (hashBitLen >= ecc.curve.bitLength) {
        // Truncate the hash to fit the curve's bit length
        std::string truncatedHash = message.substr(0, ecc.curve.bitLength / 4); // Divide by 4 to get byte length
        // Convert the truncated hash from hexadecimal string to mpz_t integer
        mpz_init_set_str(result, truncatedHash.c_str(), 16);
    } else {
        // Convert the entire hash from hexadecimal string to mpz_t integer
        mpz_init_set_str(result, message.c_str(), 16);
    }
}

void ECDSA::fieldElementToInteger(const mpz_t& fieldElement, const mpz_t& modulus, mpz_t result) {
    // Initialize GMP variables
    mpz_t temp, element;
    mpz_inits(temp, element, NULL);

    // Copy fieldElement to element
    mpz_set(element, fieldElement);

    // If the modulus is an odd prime, no conversion is needed
    if (mpz_odd_p(modulus) && mpz_probab_prime_p(modulus, 25)) {
        mpz_set(result, element); // Copy fieldElement to result
    } else {
        mpz_set_ui(result, 0); // Initialize result to 0
        mpz_set_ui(temp, 1);   // Initialize temp to 1
        // Convert the field element to an integer by evaluating the binary polynomial at x = 2
        while (mpz_cmp_ui(element, 0) > 0) {
            if (mpz_odd_p(element)) {
                mpz_add(result, result, temp);
            }
            mpz_mul_2exp(temp, temp, 1); // Multiply temp by 2
            mpz_fdiv_q_2exp(element, element, 1); // Divide element by 2
        }
    }

    // Clear GMP variables
    mpz_clears(temp, element, NULL);
}

Signature ECDSA::signMessage(const std::string& message, const KeyPair& keyPair) {
    // Prepare the message
    mpz_t e;
    mpz_init(e);
    prepareMessage(message, e);

    // Generate a random number k
    mpz_t k, min;
    mpz_init(k);
    mpz_init_set_ui(min, 1);
    ecc.getRandomNumber(min, ecc.curve.n - 1, k);

    // Generate the signature
    Signature signature = generateSignature(e, keyPair, k);

    // Clear temporary variables
    mpz_clear(k);
    mpz_clear(e);
    mpz_clear(min);

    return signature;
}

Signature ECDSA::signMessage(const std::string& message, const KeyPair& keyPair, mpz_t& k) {
    // Prepare the message
    mpz_t e;
    mpz_init(e);
    prepareMessage(message, e);

    // Generate the signature
    Signature signature = generateSignature(e, keyPair, k);

    // Clear temporary variables
    mpz_clear(e);

    return signature;
}

Signature ECDSA::generateSignature(const mpz_t& e, const KeyPair& keyPair, mpz_t& k) {
    // Generate the point R
    Point R = ecc.scalarMultiplyPoints(k, ecc.curve.basePoint);

    // Convert x-coordinate of R to integer
    mpz_t R_integer;
    mpz_init(R_integer);
    fieldElementToInteger(R.x, ecc.curve.n, R_integer);

    Signature signature;
    mpz_mod(signature.r, R_integer, ecc.curve.n);

    // Calculate kInverse
    mpz_t kInverse;
    mpz_init(kInverse);
    mpz_invert(kInverse, k, ecc.curve.n);

    // Calculate s
    mpz_t temp;
    mpz_init(temp);
    mpz_mul(temp, keyPair.privateKey, signature.r); // temp = privateKey * r
    mpz_add(temp, e, temp); // temp = e + privateKey * r
    mpz_mul(temp, temp, kInverse); // temp = (e + privateKey * r) * kInverse
    mpz_mod(signature.s, temp, ecc.curve.n); // s = (e + privateKey * r) * kInverse mod n

    // Clear temporary variables
    mpz_clear(R_integer);
    mpz_clear(kInverse);
    mpz_clear(temp);

    return signature;
}

bool ECDSA::verifySignature(const std::string& message, const Signature signature, const Point& publicKey) {
        // Prepare the message
    mpz_t e;
    mpz_init(e);
    prepareMessage(message, e);

    // Calculate sInverse using GMP's modular inverse function
    mpz_t sInverse;
    mpz_init(sInverse);
    mpz_invert(sInverse, signature.s, ecc.curve.n);

    // Calculate u1 = sInverse * e mod n
    mpz_t u1;
    mpz_init(u1);
    mpz_mul(u1, sInverse, e);
    mpz_mod(u1, u1, ecc.curve.n);

    // Calculate u2 = sInverse * r mod n
    mpz_t u2;
    mpz_init(u2);
    mpz_mul(u2, sInverse, signature.r);
    mpz_mod(u2, u2, ecc.curve.n);

    // Calculate P = u1*G + u2*publicKey
    Point P;
    P = ecc.addPoints(ecc.scalarMultiplyPoints(u1, ecc.curve.basePoint), ecc.scalarMultiplyPoints(u2, publicKey));

    // Convert x-coordinate of P to integer
    mpz_t P_integer;
    mpz_init(P_integer);
    fieldElementToInteger(P.x, ecc.curve.n, P_integer);

    // Calculate P.x mod n
    mpz_t P_mod_n;
    mpz_init(P_mod_n);
    mpz_mod(P_mod_n, P_integer, ecc.curve.n);

    // Compare r with P.x mod n
    bool verified = (mpz_cmp(signature.r, P_mod_n) == 0);

    // Clear temporary variables
    mpz_clear(e);
    mpz_clear(sInverse);
    mpz_clear(u1);
    mpz_clear(u2);
    mpz_clear(P_integer);
    mpz_clear(P_mod_n);

    return verified;
}