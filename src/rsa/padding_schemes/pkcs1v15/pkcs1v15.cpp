/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
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

#include <algorithm>
#include <vector>

#include "pkcs1v15.h"

SecureBytes getAlgorithmIdentifier(const HashAlgorithm& hashAlg) {
    switch (hashAlg) {
        case HashAlgorithm::SHA1:
            return SecureBytes::fromHex("3021300906052b0e03021a05000414");
        case HashAlgorithm::SHA256:
            return SecureBytes::fromHex("3031300d060960864801650304020105000420");
        case HashAlgorithm::SHA384:
            return SecureBytes::fromHex("3041300d060960864801650304020205000430");
        case HashAlgorithm::SHA512:
            return SecureBytes::fromHex("3051300d060960864801650304020305000440");
        default:
            throw std::invalid_argument("Unsupported hash function");
    }
}

// RFC 8017 §7.2.1
SecureBytes encodeForEncryptionPKCS1v15(const SecureBytes& input, size_t modulusSizeBytes) {
    size_t mLen = input.size();
    if (mLen > modulusSizeBytes - 11)
        throw std::invalid_argument("Error PKCS#1v1.5 Encrypt: message too long.");

    size_t psLen = modulusSizeBytes - mLen - 3;

    // PS must consist of at least 8 non-zero random bytes
    SecureBytes PS;
    PS = SecureBytes(0);
    while (PS.size() < psLen) {
        SecureBytes randomBytes = SecureBytes::random(psLen - PS.size());
        for (size_t i = 0; i < randomBytes.size() && PS.size() < psLen; i++) {
            if (randomBytes[i] != 0x00)
                PS.append(SecureBytes(1, randomBytes[i]));
        }
    }

    SecureBytes result(1, 0x00);
    result.append(SecureBytes(1, 0x02));
    result.append(PS);
    result.append(SecureBytes(1, 0x00));
    result.append(input);
    return result;
}

// RFC 8017 §7.2.2
SecureBytes decodeForEncryptionPKCS1v15(const SecureBytes& em, size_t modulusSizeBytes) {
    if (em.size() != modulusSizeBytes)
        throw std::invalid_argument("Error PKCS#1v1.5 Decrypt: encoded message length mismatch.");
    if (em[0] != 0x00 || em[1] != 0x02)
        throw std::invalid_argument("Error PKCS#1v1.5 Decrypt: invalid padding header.");

    // Scan past PS (non-zero bytes) to find the 0x00 separator
    auto it = std::find(em.begin() + 2, em.end(), uint8_t(0x00));

    size_t psLen = static_cast<size_t>(it - em.begin()) - 2;
    if (psLen < 8)
        throw std::invalid_argument("Error PKCS#1v1.5 Decrypt: padding string too short.");
    if (it == em.end())
        throw std::invalid_argument("Error PKCS#1v1.5 Decrypt: zero separator not found.");

    size_t msgStart = static_cast<size_t>(it - em.begin()) + 1;
    return SecureBytes::fromVector(std::vector<uint8_t>(em.begin() + msgStart, em.end()));
}

// RFC 8017 §9.2
SecureBytes encodeForSigningPKCS1v15(const SecureBytes& input, const HashAlgorithm& hashAlg, size_t modulusSizeBytes) {
    SecureBytes H = hash(hashAlg)(input);
    SecureBytes T = getAlgorithmIdentifier(hashAlg);
    T.append(H);

    size_t tLen = T.size();
    size_t emLen = modulusSizeBytes;
    if (emLen < tLen + 11)
        throw std::invalid_argument("Error PKCS#1v1.5 Sign: key too small for hash algorithm.");

    SecureBytes PS(emLen - tLen - 3, 0xFF);

    SecureBytes result(1, 0x00);
    result.append(SecureBytes(1, 0x01));
    result.append(PS);
    result.append(SecureBytes(1, 0x00));
    result.append(T);
    return result;
}

// RFC 8017 §9.2 verification: re-encode and compare
bool verifyForSigningPKCS1v15(const SecureBytes& input, const SecureBytes& em, const HashAlgorithm& hashAlg) {
    SecureBytes expectedEM = encodeForSigningPKCS1v15(input, hashAlg, em.size());
    return em == expectedEM;
}
