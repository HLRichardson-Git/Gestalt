/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * pss.cpp
 *
 * Implements Probabilistic Signature Scheme (PSS) padding for RSA digital signatures. PSS ensures
 * signature security by adding randomness (salt) to the padding, making signatures unique even
 * for identical messages and resilient to chosen-message attacks.
 *
 * This file provides functions for encoding and verifying PSS padding, based on PKCS #1 v2.1
 * (see https://tools.ietf.org/html/rfc8017). The implementation includes hashing and mask
 * generation using MGF1, supporting configurable hash functions and salt lengths.
 */

#include <algorithm>
#include <vector>

#include "pss.h"
#include "utils.h"

const size_t PADDING1_SIZE = 8;

// Source: https://datatracker.ietf.org/doc/html/rfc3447#section-9.1.1
SecureBytes encodePSS_Padding(const SecureBytes& message, const PSSParams& params, unsigned int modulusSizeBytes) {
    HashAlgorithm mgfHash = (params.mgfHashFunc == HashAlgorithm::None) ? params.hashFunc : params.mgfHashFunc;
    unsigned int emLen = ((4 * modulusSizeBytes) + 3) / 4; // Simplified equation to calculate intended EM Length
    unsigned int hLen = static_cast<unsigned int>(params.hashFunc);
    if (emLen < hLen + params.sLen + 2) throw std::invalid_argument("Error PSS Encode: emLen is too short."); // Step 3

    SecureBytes mHash = hash(params.hashFunc)(message); // Step 1 & 2

    SecureBytes salt = params.salt;
    if (salt.empty()) salt = SecureBytes::random(params.sLen); // Step 4

    SecureBytes PS1(PADDING1_SIZE, 0x00);
    SecureBytes mPrime = PS1;
    mPrime.append(mHash);
    mPrime.append(salt); // Step 5

    SecureBytes H = hash(params.hashFunc)(mPrime); // Step 6

    int ps2Len = emLen - params.sLen - hLen - 2;
    SecureBytes PS2(ps2Len, 0x00); // Step 7
    SecureBytes DB = PS2;
    DB.append(SecureBytes(1, 0x01));
    DB.append(salt); // Step 8

    SecureBytes dbMask = mgf1(H, emLen - hLen - 1, mgfHash); // Step 9
    SecureBytes maskedDB(DB.size());
    for (size_t i = 0; i < DB.size(); ++i) {
        maskedDB[i] = DB[i] ^ dbMask[i]; // Step 10
    }

    SecureBytes EM = maskedDB;
    EM.append(H);
    EM.append(SecureBytes(1, 0xbc)); // Step 12

    return EM;
}

// Source: https://datatracker.ietf.org/doc/html/rfc3447#section-9.1.2
bool verifyPSS_Padding(const SecureBytes& EM, const SecureBytes& message, const PSSParams& params, unsigned int modulusSizeBytes) {
    if (EM[EM.size() - 1] != 0xbc) {
        throw std::invalid_argument("Error: Given PSS encoded message does not end with 0xbc"); // Step 4
    }

    HashAlgorithm mgfHash = (params.mgfHashFunc == HashAlgorithm::None) ? params.hashFunc : params.mgfHashFunc;
    unsigned int emLen = static_cast<unsigned int>(EM.size());
    unsigned int hLen = static_cast<unsigned int>(params.hashFunc);
    if (emLen < hLen + params.sLen + 2) {
        throw std::invalid_argument("Error PSS Verification: emLen is too short."); // Step 3
    }

    SecureBytes mHash = hash(params.hashFunc)(message); // Step 1 & 2

    SecureBytes maskedDB = SecureBytes::fromVector(std::vector<uint8_t>(EM.begin(), EM.begin() + emLen - hLen - 1)); // Step 5
    SecureBytes H        = SecureBytes::fromVector(std::vector<uint8_t>(EM.begin() + emLen - hLen - 1, EM.begin() + emLen - 1)); // Step 5

    SecureBytes dbMask = mgf1(H, emLen - hLen - 1, mgfHash); // Step 7
    SecureBytes DB(maskedDB.size());
    for (size_t i = 0; i < maskedDB.size(); ++i) {
        DB[i] = maskedDB[i] ^ dbMask[i]; // Step 8
    }

    // Check if the leftmost (emLen - hLen - sLen - 2) octets of DB are zero
    unsigned int zeroPaddingLen = emLen - hLen - static_cast<unsigned int>(params.sLen) - 2;
    for (size_t i = 0; i < zeroPaddingLen; ++i) {
        if (DB[i] != 0x00) {
            throw std::invalid_argument("Inconsistent: Leftmost octets of DB are not zero."); // Step 10
        }
    }

    // Check if the octet at position (emLen - hLen - sLen - 1) is 0x01
    if (DB[zeroPaddingLen] != 0x01) {
        throw std::invalid_argument("Inconsistent: The specified position in DB does not contain 0x01."); // Step 10
    }

    SecureBytes salt = SecureBytes::fromVector(std::vector<uint8_t>(DB.end() - params.sLen, DB.end())); // Step 11
    SecureBytes PS1(PADDING1_SIZE, 0x00);
    SecureBytes mPrime = PS1;
    mPrime.append(mHash);
    mPrime.append(salt); // Step 12

    SecureBytes hPrime = hash(params.hashFunc)(mPrime); // Step 13

    if (H == hPrime) return true; // Step 14

    return false;
}
