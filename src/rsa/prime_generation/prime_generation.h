/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * prime_generation.h
 *
 * This file provides functionality to generate large prime numbers for RSA key generation. It supports both provable 
 * and probable primality tests, allowing for trade-offs between performance and certainty.The `generateLargePrime` 
 * function generates a prime number of specified bit length using the chosen primality test method.
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

BigInt generateLargePrime(unsigned int bits, RandomPrimeMethod method);