/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * prime_generation.h
 *
 */

#pragma once

#include <vector>

#include "bigInt/bigInt.h"

enum class RandomPrimeMethod {
    provable,
    probable
    //provableWithProvableAux,
    //probableWithProvableAux,
    //probableWithProbableAux
};

void generateLargePrime(mpz_t prime, unsigned int bits, RandomPrimeMethod method, gmp_randstate_t& state);