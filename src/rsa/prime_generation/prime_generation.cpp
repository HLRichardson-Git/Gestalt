/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * prime_generation.cpp
 *
 */

#include "prime_generation.h"

void generateLargePrime(mpz_t prime, unsigned int bits, RANDOM_PRIME_METHOD method) {
    mpz_t lower_bound, upper_bound;
    mpz_inits(lower_bound, upper_bound, NULL);

    mpz_ui_pow_ui(upper_bound, 2, bits); // 2^bits
    mpz_ui_pow_ui(lower_bound, 2, bits - 1); // 2^(bits - 1)

    gmp_randstate_t state;
    gmp_randinit_default(state);
    
    mpz_urandomb(prime, state, bits);
    mpz_setbit(prime, bits - 1); // Ensure the number has the correct bit length

    while (true) {
        if (mpz_cmp(prime, lower_bound) >= 0 && mpz_cmp(prime, upper_bound) < 0) {
            /*
             * returns 2 if prime is definitely prime, but takes significantly longer
             * returns 1 if prime is probably prime and is a lot faster
             * returns 0 if prime is definitely not prime
             */
            unsigned int is_prime = mpz_probab_prime_p(prime, 25); 

            if ((method == RANDOM_PRIME_METHOD::provable && is_prime == 2) ||
                (method == RANDOM_PRIME_METHOD::probable && (is_prime == 1 || is_prime == 2))) {
                break; // Prime number found
            }
        }
        mpz_urandomb(prime, state, bits);
        mpz_setbit(prime, bits - 1);
    }

    mpz_clears(lower_bound, upper_bound, NULL);
}