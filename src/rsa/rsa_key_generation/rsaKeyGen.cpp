/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsaKeyGen.cpp
 *
 * This file provides functionality for generating RSA key pairs of various strengths (1024, 2048, 3072, 7680, 
 * 15360 bits). It includes structures for RSA public and private keys, as well as methods for validating and managing 
 * RSA keys. The key generation process uses prime number generation and modular arithmetic to compute the necessary 
 * key components.
 * 
 */

#include <algorithm>
#include <sstream>

#include "rsaKeyGen.h"
#include "asn1/der/der.h"
#include "asn1/pem/pem.h"
#include "utils.h"

unsigned int RSAPublicKey::getPublicModulusBitLength() const {
    return mpz_sizeinbase(n.n, 2);
}

std::vector<uint8_t> RSAPublicKey::toDER(RsaKeyFormat format) const {
    DEREncoder encoder;
    switch (format) {
        case RsaKeyFormat::PKCS1: return encoder.encodeRSAPublicKeyToPKCS1(*this);
        case RsaKeyFormat::PKCS8: 
        default: return encoder.encodeRSAPublicKeyToPKCS8(*this);
    }
}

void RSAPublicKey::fromDER(const std::vector<uint8_t>& der, RsaKeyFormat format) {
    DERDecoder decoder(der);
    switch (format) {
        case RsaKeyFormat::PKCS1: {
            RSAPublicKey decoded = decoder.decodeRSAPublicKeyFromPKCS1();
            n = decoded.n;
            e = decoded.e;
            break;
        }
        case RsaKeyFormat::PKCS8:
        default: {
            RSAPublicKey decoded = decoder.decodeRSAPublicKeyFromPKCS8();
            n = decoded.n;
            e = decoded.e;
            break;
        }
    }
}

std::string RSAPublicKey::toPEM(RsaKeyFormat format) const {
    PEMEncoder encoder;
    switch (format) {
        case RsaKeyFormat::PKCS1: return encoder.encodeRSAPublicKeyToPKCS1(*this);
        case RsaKeyFormat::PKCS8: 
        default: return encoder.encodeRSAPublicKeyToPKCS8(*this);
    }
}

void RSAPublicKey::fromPEM(const std::string& pem, RsaKeyFormat format) {
    PEMDecoder decoder;
    
    switch (format) {
        case RsaKeyFormat::PKCS1: {
            RSAPublicKey decoded = decoder.decodeRSAPublicKeyFromPKCS1(pem);
            n = decoded.n;
            e = decoded.e;
            break;
        }
        case RsaKeyFormat::PKCS8:
        default: {
            RSAPublicKey decoded = decoder.decodeRSAPublicKeyFromPKCS8(pem);
            n = decoded.n;
            e = decoded.e;
            break;
        }
    }
}

std::vector<uint8_t> RSAPrivateKey::toDER(RsaKeyFormat format, const RSAPublicKey* pubKey) const {
    if (!pubKey) {
        throw std::runtime_error("RSAPrivateKey::toDER requires a public key for encoding");
    }
    DEREncoder encoder;
    switch (format) {
        case RsaKeyFormat::PKCS1: return encoder.encodeRSAPrivateKeyToPKCS1({*this, *pubKey});
        case RsaKeyFormat::PKCS8: 
        default: return encoder.encodeRSAPrivateKeyToPKCS8({*this, *pubKey});
    }
}

void RSAPrivateKey::fromDER(const std::vector<uint8_t>& der, RsaKeyFormat format) {
    DERDecoder decoder(der);
    RSAKeyPair decoded = (format == RsaKeyFormat::PKCS1)
        ? decoder.decodeRSAPrivateKeyFromPKCS1()
        : decoder.decodeRSAPrivateKeyFromPKCS8();
    *this = decoded.getPrivateKey();
}

std::string RSAPrivateKey::toPEM(RsaKeyFormat format, const RSAPublicKey* pubKey) const {
    if (!pubKey) {
        throw std::runtime_error("RSAPrivateKey::toPem requires a public key for encoding");
    }
    PEMEncoder encoder;
    switch (format) {
        case RsaKeyFormat::PKCS1: return encoder.encodeRSAPrivateKeyToPKCS1({*this, *pubKey});
        case RsaKeyFormat::PKCS8: 
        default: return encoder.encodeRSAPrivateKeyToPKCS8({*this, *pubKey});
    }
}

void RSAPrivateKey::fromPEM(const std::string& pem, RsaKeyFormat format) {
    PEMDecoder decoder;
    RSAKeyPair decoded = (format == RsaKeyFormat::PKCS1)
        ? decoder.decodeRSAPrivateKeyFromPKCS1(pem)
        : decoder.decodeRSAPrivateKeyFromPKCS8(pem);
    *this = decoded.getPrivateKey();
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

std::vector<uint8_t> RSAKeyPair::toDER(RsaKeyFormat format) {
    DEREncoder encoder;
    // Encode private key, include the public key in the DER
    return encoder.encodeRSAPrivateKeyToDER(*this, format);
}

void RSAKeyPair::fromDER(const std::vector<uint8_t>& der, RsaKeyFormat format) {
    DERDecoder decoder(der);
    RSAKeyPair decoded = (format == RsaKeyFormat::PKCS1)
        ? decoder.decodeRSAPrivateKeyFromPKCS1()
        : decoder.decodeRSAPrivateKeyFromPKCS8();

    privateKey = decoded.getPrivateKey();
    publicKey = decoded.getPublicKey();

    // Update the security strength from the decoded modulus
    unsigned int nBits = publicKey.n.bitLength() + 1;
    if      (nBits >= 15360) specifiedStrength = RSASecurityStrength::RSA_15360;
    else if (nBits >=  7680) specifiedStrength = RSASecurityStrength::RSA_7680;
    else if (nBits >=  3072) specifiedStrength = RSASecurityStrength::RSA_3072;
    else if (nBits >=  2048) specifiedStrength = RSASecurityStrength::RSA_2048;
    else                     specifiedStrength = RSASecurityStrength::RSA_1024;
}

std::string RSAKeyPair::toPEM(RsaKeyFormat format) const {
    DEREncoder encoder;
    std::vector<uint8_t> der = encoder.encodeRSAPrivateKeyToDER(*this, format); // encode to DER first

    // Base64 encode DER
    std::string base64 = base64Encode(der);

    // Break Base64 into 64-character lines
    std::ostringstream oss;
    const std::string header = (format == RsaKeyFormat::PKCS1) ? 
        "-----BEGIN RSA PRIVATE KEY-----" : 
        "-----BEGIN PRIVATE KEY-----";
    const std::string footer = (format == RsaKeyFormat::PKCS1) ? 
        "-----END RSA PRIVATE KEY-----" : 
        "-----END PRIVATE KEY-----";

    oss << header << "\n";

    for (size_t i = 0; i < base64.size(); i += 64) {
        oss << base64.substr(i, 64) << "\n";
    }

    oss << footer << "\n";

    return oss.str();
}

void RSAKeyPair::fromPEM(const std::string& pem, RsaKeyFormat format) {
    // Find header and footer
    std::string header, footer;
    if (format == RsaKeyFormat::PKCS1) {
        header = "-----BEGIN RSA PRIVATE KEY-----";
        footer = "-----END RSA PRIVATE KEY-----";
    } else {
        header = "-----BEGIN PRIVATE KEY-----";
        footer = "-----END PRIVATE KEY-----";
    }

    auto start = pem.find(header);
    auto end = pem.find(footer);

    if (start == std::string::npos || end == std::string::npos || start >= end) {
        throw std::invalid_argument("Invalid PEM format: missing header or footer");
    }

    // Extract Base64 block
    start += header.size();
    std::string base64 = pem.substr(start, end - start);

    // Remove newlines and whitespace
    base64.erase(std::remove_if(base64.begin(), base64.end(), ::isspace), base64.end());

    // Decode Base64 to DER
    std::vector<uint8_t> der = base64Decode(base64);

    // Delegate to DER decoder
    fromDER(der, format);
}
