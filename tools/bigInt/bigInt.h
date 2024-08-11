/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * bigInt.h
 *
 */

# pragma once

#include <string>
#include <gmp.h>

inline void stringToGMP(const std::string& str, mpz_t& result) {
    if (str.substr(0, 2) == "0x") {
        std::string truncatedStr = str.substr(2, str.length());
        mpz_set_str(result, truncatedStr.c_str(), 16);
    } else {
        mpz_set_str(result, str.c_str(), 10);
    }
}

class BigInt {
public:
    mpz_t n;

    BigInt() { mpz_init(n); }
    
    BigInt(const std::string& strN) {
        mpz_init(n);
        stringToGMP(strN, n);
    }

    BigInt(int intN) {
        mpz_init(n);
        mpz_set_si(n, intN);
    }
    
    BigInt(const BigInt& other) {
        mpz_init_set(n, other.n);
    }

    BigInt(const char* strN) {
        mpz_init(n);
        stringToGMP(strN, n);
    }

    BigInt(const mpz_t& mpzN) {
        mpz_init_set(n, mpzN);
    }

    BigInt& operator=(const BigInt& other) {
        if (this != &other) {
            mpz_set(n, other.n);
        }
        return *this;
    }

    BigInt& operator=(const std::string& strN) {
        stringToGMP(strN, n);
        return *this;
    }

    BigInt& operator=(int intN) {
        mpz_set_si(n, intN);
        return *this;
    }

    BigInt& operator=(const char* strN) {
        stringToGMP(strN, n);
        return *this;
    }

    BigInt& operator=(const mpz_t& mpzN) {
        mpz_set(n, mpzN);
        return *this;
    }

    ~BigInt() {
        mpz_clear(n);
    }
};