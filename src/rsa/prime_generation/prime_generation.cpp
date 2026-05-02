/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * prime_generation.cpp
 *
 * This file provides functionality to generate large prime numbers for RSA key generation. It supports both provable 
 * and probable primality tests, allowing for trade-offs between performance and certainty.The `generateLargePrime` 
 * function generates a prime number of specified bit length using the chosen primality test method.
 * 
 */

#include "prime_generation.h"

BigInt generateLargePrime(unsigned int bits, RandomPrimeMethod method) {
    BigInt lower, upper;
    mpz_ui_pow_ui(lower.n, 2, bits - 1); // 2^(bits-1)
    mpz_ui_pow_ui(upper.n, 2, bits);     // 2^bits

    BigInt candidate;
    do {
        candidate = BigInt::random(lower, upper);
        /*
         * mpz_probab_prime_p returns:
         *   2 if definitely prime (takes longer)
         *   1 if probably prime (faster)
         *   0 if definitely not prime
         */
        int is_prime = mpz_probab_prime_p(candidate.n, 25);
        if ((method == RandomPrimeMethod::provable  && is_prime == 2) ||
            (method == RandomPrimeMethod::probable  && is_prime  > 0)) {
            break;
        }
    } while (true);

    return candidate;
}