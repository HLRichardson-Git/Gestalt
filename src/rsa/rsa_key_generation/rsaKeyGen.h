/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsaKeyGen.h
 *
 */

# pragma once

#include "rsa/rsaObjects.h"
#include "rsa/prime_generation/prime_generation.h"

struct RSAKeyGenOptions {
    RSA_SECURITY_STRENGTH securityStrength = RSA_SECURITY_STRENGTH::RSA_2048;
    RANDOM_PRIME_METHOD primeMethod = RANDOM_PRIME_METHOD::probable;
};

struct RSAPrivateKey {
    BigInt d;      // Private exponent
    BigInt p;      // First prime factor
    BigInt q;      // Second prime factor
    BigInt dP;     // d mod (p-1)
    BigInt dQ;     // d mod (q-1)
    BigInt qInv;   // q^(-1) mod p

    RSAPrivateKey() = default;
    RSAPrivateKey(const BigInt& d) : d(d) {}
    RSAPrivateKey(const BigInt& d, const BigInt& p, const BigInt& q)
        : d(d), p(p), q(q) {
        calculateCRTComponents();
    }
    RSAPrivateKey(const BigInt& d, const BigInt& p, const BigInt& q, 
              const BigInt& dP, const BigInt& dQ, const BigInt& qInv)
    : d(d), p(p), q(q), dP(dP), dQ(dQ), qInv(qInv) {}

    void calculateCRTComponents() {
        BigInt pMinus1 = p - 1;
        BigInt qMinus1 = q - 1;
        dP = d % pMinus1;
        dQ = d % qMinus1;
        if (mpz_invert(qInv.n, q.n, p.n) == 0) {
            // If the return value is 0, it means the inverse doesn't exist (q and p are not coprime)
            throw std::runtime_error("q and p are not coprime, modular inverse does not exist.");
        }
    }

    void debugCRTComponents() const {
        std::cout << "d: " << d.toHexString() << std::endl;
        std::cout << "p: " << p.toHexString() << std::endl;
        std::cout << "q: " << q.toHexString() << std::endl;
        std::cout << "dP: " << dP.toHexString() << std::endl;
        std::cout << "dQ: " << dQ.toHexString() << std::endl;
        std::cout << "qInv: " << qInv.toHexString() << std::endl;
    }
};

struct RSAPublicKey {
    BigInt n;
    BigInt e = 65537;

    RSAPublicKey() = default;
    RSAPublicKey(const BigInt& n, const BigInt& e)
    : n(n), e(e) {}

    unsigned int getPublicModulusBitLength() const;
};

class RSAKeyPair {
private:
    RSAPrivateKey privateKey;
    RSAPublicKey publicKey;
    RSA_SECURITY_STRENGTH specifiedStrength;

    bool isPrime(const BigInt& number);
    bool validatePrivateKey(RSAPrivateKey privateKeyCandidate);
    bool validatePublicKey(RSAPublicKey publicKeyCandidate);
    void computePrivateExponent(mpz_t d, const mpz_t e, const mpz_t phi_n);
    void generateKeyPair(RSAKeyGenOptions options);

    friend class RSA;
    friend class RSA_KeyPair_Test;
public:

    RSAKeyPair() { 
        generateKeyPair({RSA_SECURITY_STRENGTH::RSA_2048, RANDOM_PRIME_METHOD::probable}); 
    };
    RSAKeyPair(RSAKeyGenOptions options) { 
        generateKeyPair(options);
    };
    
    RSAKeyPair(RSA_SECURITY_STRENGTH specifiedStrength, 
               const RSAPrivateKey& privateKeyCandidate, 
               const RSAPublicKey& publicKeyCandidate)   
        : specifiedStrength(specifiedStrength) {
        try {
            validatePrivateKey(privateKeyCandidate);  // Throws if invalid
            validatePublicKey(publicKeyCandidate);    // Throws if invalid
            privateKey = privateKeyCandidate;
            publicKey = publicKeyCandidate;
        } catch (const std::invalid_argument& e) {
            std::cerr << "Key validation error: " << e.what() << std::endl;
            throw; // Re-throw the exception to signal the error to the caller
        }
    };

    void setPrivateKey(RSAPrivateKey privateKeyCandidate) { 
        if (validatePrivateKey(privateKeyCandidate)) {
            privateKey.d = privateKeyCandidate.d;
        }
    };
    void setPublicKey(RSAPublicKey publicKeyCandidate) { 
        if (validatePublicKey(publicKeyCandidate)) {
            publicKey.n = publicKeyCandidate.n;
            publicKey.e = publicKeyCandidate.e;
        }
    };
    RSAPrivateKey getPrivateKey() const { return privateKey; };
    RSAPublicKey getPublicKey() const { return publicKey; };

    bool validateKeyPair();
    void regenerateKeyPair(const RSAKeyGenOptions& options);
    unsigned int getModulusBitLength() const;
    unsigned int getPrivateExponentBitLength() const;
};