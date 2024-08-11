/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * provable_prime_construction.cpp
 *
 */

#include "prime_generation.h"

ShaweTaylorRandomPrimeRoutineResult shawneTaylorRandomPrime (unsigned int length, const BigInt& inputSeed) {
    ShaweTaylorRandomPrimeRoutineResult result = {Status::FAILURE, 0, 0, 0};

    // Obviously need this logic

    return result;
}

ProvablePrimeConstructionResult provablePrimeConstruction (
    unsigned int L, 
    unsigned int N1,
    unsigned int N2,
    const BigInt& firstSeed,
    const BigInt& e
) {
    ProvablePrimeConstructionResult result = { Status::FAILURE, 0, 0, 0, 0 };
    if (L != 1536) { // Need to figure out to generalize this, maybe another struct?
        return result;
    }
    
    BigInt p2Seed = 0;
    if (N1 == 1) {
        result.p1 = 1;
        p2Seed = firstSeed;
    }

    ShaweTaylorRandomPrimeRoutineResult stResult;
    if (N2 >= 2) {
        stResult = shawneTaylorRandomPrime(N1, firstSeed);
        if (stResult.status == Status::FAILURE) return { Status::FAILURE, 0, 0, 0, 0 };
    }
    result.p1 = stResult.prime;
    p2Seed = stResult.primeSeed;

    BigInt p0Seed = 0;
    if (N2 == 1) {
        result.p2 = 1;
        p0Seed = p2Seed;
    }

    if (N2 >= 2) {
        stResult = shawneTaylorRandomPrime(N2, p2Seed);
        if (stResult.status == Status::FAILURE) return { Status::FAILURE, 0, 0, 0, 0 };
    }
    result.p2 = stResult.prime;
    p0Seed = stResult.primeSeed;

    stResult = shawneTaylorRandomPrime(ceil(L / 2) + 1, p0Seed);
    if (stResult.status == Status::FAILURE) return { Status::FAILURE, 0, 0, 0, 0 };
    result.p = stResult.prime;
    result.pSeed = stResult.primeSeed;

    // There is so much more to add wtf... and I have to use a hash wtf

    return result;
}