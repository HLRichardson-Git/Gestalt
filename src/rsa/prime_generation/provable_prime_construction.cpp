/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * provable_prime_construction.cpp
 *
 */

#include <iostream> // for fun
#include <cmath>
#include <gestalt/sha2.h>

#include "prime_generation.h"
#include "utils.h"

std::vector<int> sieveProcedure(int limit) {
    std::vector<int> primes;
    std::vector<bool> isPrime(limit + 1, true);

    // Initialize sieve array: true means it's still a candidate for being prime
    isPrime[0] = isPrime[1] = false;

    for (int pj = 2; pj <= limit; ++pj) {
        if (isPrime[pj]) {
            primes.push_back(pj);
            // Mark multiples of pj as not prime
            for (int multiple = pj * 2; multiple <= limit; multiple += pj) {
                isPrime[multiple] = false;
            }
        }
    }
    return primes;
}

bool isPrimeTrialDivision(unsigned int c) {
    if (c <= 1) return false; // 1 and below are not prime numbers
    if (c <= 3) return true;  // 2 and 3 are prime numbers

    // Step 1: Generate primes up to sqrt(c) using the sieve procedure
    int limit = static_cast<int>(std::sqrt(c));
    std::vector<int> primes = sieveProcedure(limit);

    // Step 2: Trial division
    for (int prime : primes) {
        if (c % prime == 0) {
            return false; // c is divisible by a prime, hence composite
        }
    }

    // Step 3: If no divisors found, c is prime
    return true;
}

ShaweTaylorRandomPrimeRoutineResult shawneTaylorRandomPrime (unsigned int length, const BigInt& inputSeed) {
    ShaweTaylorRandomPrimeRoutineResult result = {Status::FAILURE, 0, 0, 0};
    if (length < 2) return {Status::FAILURE, 0, 0, 0}; // Step 1
    if (length < 33) return shawneTaylorRandomPrime(ceil(length / 2) + 1, inputSeed); // Step 2
    // TODO: I highly doubt this works like I wish it does and goes to step 14... 
    result.primeSeed = inputSeed; // Step 3
    result.primeGenCounter = 0; // Step 4

    // Step 5
    std::string t = hashSHA256(result.primeSeed.toHexString()); // TODO: SHA2 doesnt properly handle these hex inputs
    result.primeSeed = result.primeSeed + 1;
    unsigned int c = xorHexStrings(t, hashSHA256(result.primeSeed.toHexString()));
    
    c = pow(2, length - 1) + (c % static_cast<int>(pow(2, length - 1))); // Step 6
    c = (2 * floor(c / 2)) + 1; // Step 7

    result.primeGenCounter += 1; // Step 8
    result.primeSeed += 2; // Step 9

    // Step 10 & 11
    if (isPrimeTrialDivision(c)) {
        result.prime = c;
        result.status = Status::SUCCESS;
        return result;
    }
    // Step 12
    if (result.primeGenCounter > (4 * length)) return {Status::FAILURE, 0, 0, 0};
    // TODO: Add logic to go back to step 5

    // TODO: Do the rest :)

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