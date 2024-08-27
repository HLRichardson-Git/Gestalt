/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsaObjects.h
 *
 */

# pragma once

#include <iostream>

#include "bigInt/bigInt.h"
#include "prime_generation/prime_generation.h"

enum class RSA_SECURITY_STRENGTH : unsigned int{
   RSA_1024 = 1024, // 80
   RSA_2048 = 2048, // 112
   RSA_3072 = 3072, // 128
   RSA_7680 = 7960, // 192
   RSA_15360 = 15360 // 256 
};

enum class ENCRYPTION_PADDING_SCHEME {
    NO_PADDING,
    PKCS1v15,
    OAEP
};

enum class SIGNATURE_PADDING_SCHEME {
    NO_PADDING,
    PKCS1v15,
    PSS
};

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
};

class RSAKeyPair {
private:
    RSAPrivateKey privateKey;
    RSAPublicKey publicKey;
    RSAKeyGenOptions keyGenOptions;

    bool validatePrivateKey(RSAPrivateKey privateKeyCandidate);
    bool validatePublicKey(RSAPublicKey publicKeyCandidate);
    void computePrivateExponent(mpz_t d, const mpz_t e, const mpz_t phi_n);
    void generateKeyPair(RSAKeyGenOptions options);

    friend class RSA;
    friend class RSA_KeyPair_Test;
public:

    RSAKeyPair() : keyGenOptions() { 
        generateKeyPair(keyGenOptions); 
    };
    RSAKeyPair(RSAKeyGenOptions options) : keyGenOptions(options) { 
        generateKeyPair(options);
    };
    
    RSAKeyPair(const RSAPrivateKey& privateKeyCandidate, const RSAPublicKey& publicKeyCandidate) {
        if (validatePrivateKey(privateKeyCandidate) && validatePublicKey(publicKeyCandidate)) {
            privateKey = privateKeyCandidate;
            publicKey = publicKeyCandidate;
        } else {
            throw std::invalid_argument("Invalid private or public key provided.");
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
    unsigned int getModulusSize() const { return static_cast<unsigned int>(keyGenOptions.securityStrength); }

    bool validateKeyPair();
    void regenerateKeyPair(const RSAKeyGenOptions& options);
    unsigned int getModulusBitLength() const;
    unsigned int getPrivateExponentBitLength() const;
};