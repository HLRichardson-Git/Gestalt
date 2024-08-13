/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * test_rsa_prime_generation.cpp
 *
 */

#include "gtest/gtest.h"

#include "rsa/prime_generation/prime_generation.h"

bool isPrime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

TEST(RSA_Prime_Generation, sieveProcedure) {
    int limit = 7919;
    std::vector<int> expected_primes;
    
    for (int i = 2; i <= limit; ++i) {
        if (isPrime(i)) {
            expected_primes.push_back(i);
        }
    }

    std::vector<int> generated_primes = sieveProcedure(limit);

    EXPECT_EQ(generated_primes, expected_primes);
}

TEST(RSA_Prime_Generation, trialDivision) {
    EXPECT_TRUE(isPrimeTrialDivision(7919));
    EXPECT_FALSE(isPrimeTrialDivision(4));
}