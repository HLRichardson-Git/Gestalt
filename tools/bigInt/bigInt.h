/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * bigInt.h
 *
 * This file defines a wrapper class `BigInt` for GMP (GNU Multi-Precision) integers. The `BigInt` class provides 
 * convenient constructors, operators, and utility functions for working with large integers, including conversions 
 * from string representations (hexadecimal and decimal), arithmetic operations, and memory management.
 *
 * Key features:
 * - Supports both hexadecimal and decimal string-to-GMP conversions.
 * - Implements common arithmetic operators: +, -, *, and %.
 * - Comparison operators for BigInt and int types.
 * - Memory management functions for GMP integers.
 * - Methods for converting GMP values to hexadecimal and decimal strings.
 * - Validation methods for DER/cryptographic key parsing.
 * 
 */

#pragma once

#include <string>
#include <cstring>
#include <vector>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <gmp.h>

inline void stringToGMP(const std::string& str, mpz_t& result) {
    if (str.substr(0, 2) == "0x") {
        mpz_set_str(result, str.c_str() + 2, 16);
    } else {
        mpz_set_str(result, str.c_str(), 10);
    }
}

class BigInt {
public:
    mpz_t n;

    // Constructors
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

    BigInt(const std::vector<uint8_t>& bytes) {
        mpz_init(n);
        mpz_import(n, bytes.size(), 1, sizeof(uint8_t), 1, 0, bytes.data());
    }

    // Assignment operators
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

    // Arithmetic operators
    BigInt operator+(int intN) const {
        BigInt result;
        mpz_add_ui(result.n, this->n, intN);
        return result;
    }

    BigInt operator+(const BigInt& other) const {
        BigInt result;
        mpz_add(result.n, this->n, other.n);
        return result;
    }

    BigInt operator-(int intN) const {
        BigInt result;
        mpz_sub_ui(result.n, this->n, intN);
        return result;
    }

    BigInt operator-(const BigInt& other) const {
        BigInt result;
        mpz_sub(result.n, this->n, other.n);
        return result;
    }

    BigInt operator*(const BigInt& other) const {
        BigInt result;
        mpz_mul(result.n, this->n, other.n);
        return result;
    }

    BigInt operator%(const BigInt& other) const {
        BigInt result;
        mpz_mod(result.n, this->n, other.n);
        return result;
    }

    // Comparison operators - BigInt vs BigInt
    bool operator==(const BigInt& other) const {
        return mpz_cmp(n, other.n) == 0;
    }

    bool operator!=(const BigInt& other) const {
        return mpz_cmp(n, other.n) != 0;
    }

    bool operator<(const BigInt& other) const {
        return mpz_cmp(n, other.n) < 0;
    }

    bool operator>(const BigInt& other) const {
        return mpz_cmp(n, other.n) > 0;
    }

    bool operator<=(const BigInt& other) const {
        return mpz_cmp(n, other.n) <= 0;
    }

    bool operator>=(const BigInt& other) const {
        return mpz_cmp(n, other.n) >= 0;
    }

    // Comparison operators - BigInt vs int
    bool operator==(int value) const {
        return mpz_cmp_si(n, value) == 0;
    }

    bool operator!=(int value) const {
        return mpz_cmp_si(n, value) != 0;
    }

    bool operator<(int value) const {
        return mpz_cmp_si(n, value) < 0;
    }

    bool operator>(int value) const {
        return mpz_cmp_si(n, value) > 0;
    }

    bool operator<=(int value) const {
        return mpz_cmp_si(n, value) <= 0;
    }

    bool operator>=(int value) const {
        return mpz_cmp_si(n, value) >= 0;
    }

    // Destructor
    ~BigInt() {
        mpz_clear(n);
    }

    // Conversion methods
    std::string toHexString() const {
        char* hexStr = mpz_get_str(nullptr, 16, n);
        std::string result(hexStr);

        void (*freeFunc)(void*, size_t);
        mp_get_memory_functions(nullptr, nullptr, &freeFunc);
        freeFunc(hexStr, strlen(hexStr) + 1);

        return result;
    }

    std::string toDecimalString() const {
        char* decimalStr = mpz_get_str(nullptr, 10, n);
        std::string result(decimalStr);

        void (*freeFunc)(void*, size_t);
        mp_get_memory_functions(nullptr, nullptr, &freeFunc);
        freeFunc(decimalStr, strlen(decimalStr) + 1);

        return result;
    }

    // Validation and property methods
    bool isEven() const {
        return mpz_even_p(n) != 0;
    }

    bool isOdd() const {
        return mpz_odd_p(n) != 0;
    }

    size_t bitLength() const {
        return mpz_sizeinbase(n, 2);
    }

    size_t byteLength() const {
        size_t bits = bitLength();
        return (bits + 7) / 8;  // Round up to nearest byte
    }

    bool isZero() const {
        return mpz_cmp_ui(n, 0) == 0;
    }

    bool isPositive() const {
        return mpz_cmp_ui(n, 0) > 0;
    }

    bool isNegative() const {
        return mpz_cmp_ui(n, 0) < 0;
    }

    int sign() const {
        return mpz_sgn(n);
    }

    BigInt modInverse(const BigInt& mod) const {
        BigInt result;
        if (mpz_invert(result.n, n, mod.n) == 0)
            throw std::runtime_error("No modular inverse exists");
        return result;
    }

    BigInt modPow(const BigInt& exp, const BigInt& mod) const {
        BigInt result;
        mpz_powm(result.n, n, exp.n, mod.n);
        return result;
    }

    BigInt modPow(unsigned long exp, const BigInt& mod) const {
        BigInt result;
        mpz_powm_ui(result.n, n, exp, mod.n);
        return result;
    }

    bool testBit(size_t i) const {
        return mpz_tstbit(n, i) != 0;
    }

    bool isProbablyPrime(int rounds = 25) const {
        return mpz_probab_prime_p(n, rounds) != 0;
    }

    bool isCongruent(unsigned long remainder, unsigned long modulus) const {
        return mpz_congruent_ui_p(n, remainder, modulus) != 0;
    }

    BigInt floorDiv(unsigned long d) const {
        BigInt result;
        mpz_fdiv_q_ui(result.n, n, d);
        return result;
    }

    BigInt shiftRight(size_t bits) const {
        BigInt result;
        mpz_fdiv_q_2exp(result.n, n, bits);
        return result;
    }

    static BigInt fromBytes(const uint8_t* data, size_t count) {
        BigInt result;
        mpz_import(result.n, count, 1, 1, 1, 0, data);
        return result;
    }

    std::vector<uint8_t> toBytes() const {
        size_t count = byteLength();
        std::vector<uint8_t> result(count, 0);
        size_t exportCount = 0;
        mpz_export(result.data(), &exportCount, 1, 1, 1, 0, n);
        result.resize(exportCount);
        return result;
    }

    // Returns a cryptographically random BigInt in [min, max) using std::random_device as entropy.
    static BigInt random(const BigInt& min, const BigInt& max) {
        BigInt range = max - min;
        size_t bytes = range.byteLength();

        std::random_device rd;
        BigInt result;
        do {
            std::vector<uint8_t> buf(bytes);
            for (size_t i = 0; i < bytes; ) {
                unsigned int rval = rd();
                for (size_t j = 0; j < sizeof(rval) && i < bytes; ++j, ++i) {
                    buf[i] = static_cast<uint8_t>(rval & 0xFF);
                    rval >>= 8;
                }
            }
            mpz_import(result.n, bytes, 1, 1, 0, 0, buf.data());
        } while (result >= range);

        return result + min;
    }
};