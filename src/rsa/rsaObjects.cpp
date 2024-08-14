/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsaObjects.cpp
 *
 */

#include <iostream>

#include "rsaObjects.h"

bool RSAKeyPair::validatePrivateKey(RSAPrivateKey privateKeyCandidate) {
    // TODO: do the thing
    return true;
}

bool RSAKeyPair::validatePublicKey(RSAPublicKey publicKeyCandidate) {
    // TODO: do the thing
    return true;
}

void RSAKeyPair::computePrivateExponent(mpz_t d, const mpz_t e, const mpz_t phi_n) {
    if (mpz_invert(d, e, phi_n) == 0) {
        std::cerr << "Error: e has no modular inverse with respect to phi(n)" << std::endl;
        exit(1);
    }
}

void RSAKeyPair::generateKeyPair(RSAKeyGenOptions options) {
    mpz_t p, q, n;
    mpz_inits(p, q, n, NULL);

    generateLargePrime(p, static_cast<unsigned int>(options.securityStrength) / 2, options.primeMethod);
    generateLargePrime(q, static_cast<unsigned int>(options.securityStrength) / 2, options.primeMethod);

    mpz_mul(n, p, q);

    // Calculate phi(n) = (p-1) * (q-1)
    mpz_t p_minus_1, q_minus_1, phi_n;
    mpz_inits(p_minus_1, q_minus_1, phi_n, NULL);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(phi_n, p_minus_1, q_minus_1);

    computePrivateExponent(privateKey.d.n, publicKey.e.n, phi_n);
    publicKey.n = n;

    mpz_clears(p, q, n, phi_n, p_minus_1, q_minus_1, NULL);
}