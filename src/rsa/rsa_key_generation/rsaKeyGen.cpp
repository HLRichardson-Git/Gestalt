/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsaKeyGen.cpp
 *
 */

#include "rsaKeyGen.h"

unsigned int RSAPublicKey::getPublicModulusBitLength() const {
    return mpz_sizeinbase(n.n, 2);
}

bool RSAKeyPair::isPrime(const BigInt& number) {
    if (mpz_cmp_ui(number.n, 0) == 0) {
        return false;  // Handle the case where number is 0
    }
    return mpz_probab_prime_p(number.n, 5) != 0;  // Returns non-zero if the number is probably prime
}

bool RSAKeyPair::validatePrivateKey(RSAPrivateKey privateKeyCandidate) {
    // Check that p is prime if provided
    if (mpz_cmp_ui(privateKeyCandidate.p.n, 0) != 0) {
        if (!isPrime(privateKeyCandidate.p)) {
            throw std::invalid_argument("'p' is not prime.");
        }
    }

    // Check that q is prime if provided
    if (mpz_cmp_ui(privateKeyCandidate.q.n, 0) != 0) {
        if (!isPrime(privateKeyCandidate.q)) {
            throw std::invalid_argument("'q' is not prime.");
        }
    }

    // Check if p and q are coprime if both are provided
    if (mpz_cmp_ui(privateKeyCandidate.p.n, 0) != 0 && mpz_cmp_ui(privateKeyCandidate.q.n, 0) != 0) {
        BigInt gcdPQ;
        mpz_gcd(gcdPQ.n, privateKeyCandidate.p.n, privateKeyCandidate.q.n);
        if (mpz_cmp_ui(gcdPQ.n, 1) != 0) {
            throw std::invalid_argument("'p' and 'q' are not coprime.");
        }
    }

    unsigned int specifiedStrengthValue = static_cast<unsigned int>(specifiedStrength);
    unsigned int dBitLength = mpz_sizeinbase(privateKeyCandidate.d.n, 2);
    if (abs(int (dBitLength - specifiedStrengthValue)) > 10) { // within specified size +-10
        throw std::invalid_argument("Private key 'd' bit length (" + std::to_string(dBitLength) + 
                                " bits) is too far from the specified strength (" + 
                                std::to_string(specifiedStrengthValue) + " bits).");
    }

    return true;
}

bool RSAKeyPair::validatePublicKey(RSAPublicKey publicKeyCandidate) {
    unsigned int nBitLength = mpz_sizeinbase(publicKeyCandidate.n.n, 2);
    if (abs(int (nBitLength - static_cast<int>(specifiedStrength))) > 10) { // within specified size +-10
        throw std::invalid_argument("Public key modulus 'n' bit length is too far from the specified strength.");
    }

    BigInt twoPow256 = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    if (mpz_cmp_ui(publicKeyCandidate.e.n, 65536) < 0 || mpz_cmp(publicKeyCandidate.e.n, twoPow256.n) > 0) {
        throw std::invalid_argument("Public exponent 'e' is out of the allowed range.");
    }

    return true;
}

void RSAKeyPair::computePrivateExponent(mpz_t d, const mpz_t e, const mpz_t phi_n) {
    if (mpz_invert(d, e, phi_n) == 0) {
        std::cerr << "Error: e has no modular inverse with respect to phi(n)" << std::endl;
        exit(1);
    }
}

void RSAKeyPair::generateKeyPair(RSAKeyGenOptions options) {
    mpz_t p, q, n;
    mpz_inits(p, q, n, NULL);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    generateLargePrime(p, static_cast<unsigned int>(options.securityStrength) / 2, options.primeMethod, state);
    generateLargePrime(q, static_cast<unsigned int>(options.securityStrength) / 2, options.primeMethod, state);

    mpz_mul(n, p, q);

    // Calculate phi(n) = (p-1) * (q-1)
    mpz_t p_minus_1, q_minus_1, phi_n;
    mpz_inits(p_minus_1, q_minus_1, phi_n, NULL);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(phi_n, p_minus_1, q_minus_1);

    computePrivateExponent(privateKey.d.n, publicKey.e.n, phi_n);
    mpz_set(privateKey.p.n, p);
    mpz_set(privateKey.q.n, q);
    privateKey.calculateCRTComponents();
    
    publicKey.n = n;

    mpz_clears(p, q, n, phi_n, p_minus_1, q_minus_1, NULL);
}

bool RSAKeyPair::validateKeyPair() {
    try {
        return validatePrivateKey(this->privateKey) && validatePublicKey(this->publicKey);
    } catch (const std::invalid_argument& e) {
        std::cerr << "Key validation error: " << e.what() << std::endl;
        return false;
    }
}

void RSAKeyPair::regenerateKeyPair(const RSAKeyGenOptions& options) {
    generateKeyPair(options);
}

unsigned int RSAKeyPair::getModulusBitLength() const {
    return mpz_sizeinbase(publicKey.n.n, 2);
}

unsigned int RSAKeyPair::getPrivateExponentBitLength() const {
    return mpz_sizeinbase(privateKey.d.n, 2);
}