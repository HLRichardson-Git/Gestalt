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
#include <cmath>

#include "rsaObjects.h"

bool RSAKeyPair::validatePrivateKey(RSAPrivateKey privateKeyCandidate) {
    unsigned int dBitLength = mpz_sizeinbase(privateKeyCandidate.d.n, 2);
    
    if (abs(int (dBitLength - static_cast<int>(keyGenOptions.securityStrength))) > 10) { // within security range +-10
        return false;  // Private key 'd' is too small
    }

    return true;
}

bool RSAKeyPair::validatePublicKey(RSAPublicKey publicKeyCandidate) {
    unsigned int nBitLength = mpz_sizeinbase(publicKeyCandidate.n.n, 2);

    if (abs(int (nBitLength - static_cast<int>(keyGenOptions.securityStrength))) > 10) { // within security range +-10
        return false;  // Public key modulus 'n' is too small
    }

    BigInt twoPow256 = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    if (mpz_cmp_ui(publicKeyCandidate.e.n, 65536) < 0 || mpz_cmp(publicKeyCandidate.e.n, twoPow256.n) > 0) {
        return false;  // Public exponent 'e' is out of range
    }

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

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    generateLargePrime(p, static_cast<unsigned int>(options.securityStrength) / 2, options.primeMethod, state);
    generateLargePrime(q, static_cast<unsigned int>(options.securityStrength) / 2, options.primeMethod, state);

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

bool RSAKeyPair::validateKeyPair() {
    return validatePrivateKey(this->privateKey) && validatePublicKey(this->publicKey);
}

void RSAKeyPair::regenerateKeyPair(const RSAKeyGenOptions& options) {
    generateKeyPair(options);
}

unsigned int RSAKeyPair::getModulusBitLength() const {
    return mpz_sizeinbase(publicKey.n.n, 2);
}

unsigned int RSAKeyPair::getPrivateExponentBitLength() const {
    return mpz_sizeinbase(privateKey.d.n, 2);
}