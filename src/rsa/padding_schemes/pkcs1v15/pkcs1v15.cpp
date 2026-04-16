/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * pkcs1v15.cpp
 *
 * Implements PKCS #1 v1.5 padding for RSA digital signatures and encryption.
 * This padding scheme is straightforward and deterministic, ensuring that the
 * signed message can be verified without the use of randomness. However,
 * it is less secure against certain attacks compared to more modern schemes.
 *
 * This file provides functions for encoding messages for signing and verifying
 * signatures using the PKCS #1 v1.5 padding scheme, as specified in RFC 3447
 * (https://tools.ietf.org/html/rfc3447). The implementation handles:
 *
 */

#include "pkcs1v15.h"
#include "utils.h"

std::string getAlgorithmIdentifier(const HashAlgorithm& hashAlg) {
    switch (hashAlg) {
        case HashAlgorithm::SHA1:
            return "3021300906052b0e03021a05000414";
        case HashAlgorithm::SHA256:
            return "3031300d060960864801650304020105000420";
        case HashAlgorithm::SHA384:
            return "3041300d060960864801650304020205000430";
        case HashAlgorithm::SHA512:
            return "3051300d060960864801650304020305000440";
        default:
            throw std::invalid_argument("Unsupported hash function");
    }
}

// RFC 8017 §7.2.1
std::string encodeForEncryptionPKCS1v15(const std::string& input, size_t modulusSizeBytes) {
    size_t mLen = input.length();
    if (mLen > modulusSizeBytes - 11)
        throw std::invalid_argument("Error PKCS#1v1.5 Encrypt: message too long.");

    size_t psLen = modulusSizeBytes - mLen - 3;

    // PS must consist of at least 8 non-zero random bytes
    std::string PS;
    PS.reserve(psLen);
    while (PS.size() < psLen) {
        std::string randomBytes = hexToBytes(generateRandomHexData(psLen - PS.size()));
        for (unsigned char byte : randomBytes) {
            if (byte != 0x00)
                PS += static_cast<char>(byte);
            if (PS.size() == psLen)
                break;
        }
    }

    return std::string(1, 0x00) + std::string(1, 0x02) + PS + std::string(1, 0x00) + input;
}

// RFC 8017 §7.2.2
std::string decodeForEncryptionPKCS1v15(const std::string& em, size_t modulusSizeBytes) {
    if (em.length() != modulusSizeBytes)
        throw std::invalid_argument("Error PKCS#1v1.5 Decrypt: encoded message length mismatch.");
    if (static_cast<unsigned char>(em[0]) != 0x00 || static_cast<unsigned char>(em[1]) != 0x02)
        throw std::invalid_argument("Error PKCS#1v1.5 Decrypt: invalid padding header.");

    // Scan past PS (non-zero bytes) to find the 0x00 separator
    size_t i = 2;
    while (i < em.length() && static_cast<unsigned char>(em[i]) != 0x00)
        ++i;

    size_t psLen = i - 2;
    if (psLen < 8)
        throw std::invalid_argument("Error PKCS#1v1.5 Decrypt: padding string too short.");
    if (i == em.length())
        throw std::invalid_argument("Error PKCS#1v1.5 Decrypt: zero separator not found.");

    return em.substr(i + 1);
}

// RFC 8017 §9.2
std::string encodeForSigningPKCS1v15(const std::string& input, const HashAlgorithm& hashAlg, size_t modulusSizeBytes) {
    std::string H = hexToBytes(hash(hashAlg)(input));
    std::string T = hexToBytes(getAlgorithmIdentifier(hashAlg)) + H;

    size_t tLen = T.length();
    size_t emLen = modulusSizeBytes;
    if (emLen < tLen + 11)
        throw std::invalid_argument("Error PKCS#1v1.5 Sign: key too small for hash algorithm.");

    std::string PS(emLen - tLen - 3, 0xFF);

    return std::string(1, 0x00) + std::string(1, 0x01) + PS + std::string(1, 0x00) + T;
}

// RFC 8017 §9.2 verification: re-encode and compare
bool verifyForSigningPKCS1v15(const std::string& input, const std::string& em, const HashAlgorithm& hashAlg) {
    std::string expectedEM = encodeForSigningPKCS1v15(input, hashAlg, em.length());
    return em == expectedEM;
}
