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

#include "bigInt/bigInt.h"

enum Status {
    SUCCESS,
    FAILURE
};

struct ProvablePrimeConstructionResult {
    Status status;
    BigInt p; // The required prime p
    BigInt p1; // p1 having the property that p1 divides p - 1
    BigInt p2; // p2 having the property that p2 divides p + 1
    BigInt pSeed;
};

struct ShaweTaylorRandomPrimeRoutineResult {
    Status status;
    BigInt prime;
    BigInt primeSeed;
    BigInt PrimeGenCounter;
};

ShaweTaylorRandomPrimeRoutineResult shawneTaylorRandomPrime (unsigned int length, const BigInt& inputSeed);

ProvablePrimeConstructionResult provablePrimeConstruction (
    unsigned int L, 
    unsigned int N1,
    unsigned int N2,
    const BigInt& firstSeed,
    const BigInt& e
);