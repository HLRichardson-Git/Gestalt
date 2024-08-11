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

bool RSAKeyPair::isValidThreshold(const BigInt& value, const BigInt& minThreshold, const BigInt& maxThreshold) {
    return (mpz_cmp(value.n, minThreshold.n) <= 0) || (mpz_cmp(value.n, maxThreshold.n) >= 0);
}

void RSAKeyPair::getSeed(RSA_SECURITY_STRENGTH securityStrength, mpz_t& result) {
    int seedLength = static_cast<int>(securityStrength) * 2;
    mpz_t n;
    mpz_init_set_si(n, seedLength);

    gmp_randstate_t state;
    gmp_randinit_default(state);

    mpz_rrandomb(result, state, seedLength);

    gmp_randclear(state);
}

void RSAKeyPair::generatePrimes(RSAKeyGenOptions keyGenOptions, const BigInt& e, const mpz_t& seed, mpz_t& pResult, mpz_t& qResult) {
    BigInt minThreshold = "65536";  // 2^16
    BigInt maxThreshold = "1152921504606846976"; // 2^256
    if (!isValidThreshold(e, minThreshold, maxThreshold)) {
        mpz_set_ui(pResult, 0);
        mpz_set_ui(qResult, 0);
        throw std::invalid_argument("Error: Public exponent is out of valid range.");
    }

    minThreshold = "0";
    maxThreshold = static_cast<int>(keyGenOptions.securityStrenght) * 2;

    if (isValidThreshold(mpz_sizeinbase(seed, 2), minThreshold, maxThreshold)) {
        mpz_set_ui(pResult, 0);
        mpz_set_ui(qResult, 0);
        throw std::invalid_argument("Error: Seed for generating primes is to small.");
    }

    unsigned int L = 3072/2; // Need to figure out how to get this from RSAKeyGenOtions
    unsigned int N1 = 0, N2 = 1;
    BigInt workingSeed = seed;
    ProvablePrimeConstructionResult results = provablePrimeConstruction(L, N1, N2, workingSeed, e);
}