/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
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

#include "pss.h"
#include "utils.h"

// Source: https://datatracker.ietf.org/doc/html/rfc3447#section-9.1.1
std::string encodePSS_Padding(const std::string& input, const PSSParams& params, unsigned int modulusSizeBytes) {
    unsigned int emLen = ((4 * modulusSizeBytes) + 3) / 4; // Simplified equation to calcualte intended EM Length
    unsigned int hLen = static_cast<unsigned int>(params.hashFunc);
    if (emLen < hLen + params.sLen + 2) throw std::invalid_argument("Error PSS Encode: emLen is too short."); // Step 3
    
    std::string mHash = hexToBytes(hash(input, params.hashFunc)); // Step 1 & 2

    std::string salt = params.salt;
    if (salt.empty()) salt = generateRandomHexData(params.sLen); // Step 4

    std::string PS1(PADDING1_SIZE, 0x00);
    std::string mPrime = PS1 + mHash + hexToBytes(salt); // Step 5
    std::string H = hexToBytes(hash(mPrime, params.hashFunc)); // Step 6

    int ps2Len = emLen - params.sLen - hLen - 2;
    std::string PS2(ps2Len, 0x00); // Step 7
    std::string DB = PS2 + "\x01" + hexToBytes(salt); // Step 8

    std::string dbMask = hexToBytes(mgf1(H, emLen - hLen - 1, params.hashFunc)); // Step 9
    std::string maskedDB;
    for (size_t i = 0; i < DB.length(); ++i) {
        maskedDB += DB[i] ^ dbMask[i]; // Step 10
    }

    std::string EM = maskedDB + H + "\xbc"; // Step 12

    return EM;
}

// Source: https://datatracker.ietf.org/doc/html/rfc3447#section-9.1.2
bool verifyPSS_Padding(const std::string& EM, const std::string& message, const PSSParams& params, unsigned int modulusSizeBytes) {
    if (static_cast<unsigned char>(EM[EM.length() - 1]) != 0xbc) {
        throw std::invalid_argument("Error: Given PSS encoded message does not end with 0xbc"); // Step 4
    }

    unsigned int emLen = EM.length();
    unsigned int hLen = static_cast<unsigned int>(params.hashFunc);
    if (emLen < hLen + params.sLen + 2) {
        throw std::invalid_argument("Error PSS Verification: emLen is too short."); // Step 3
    }

    std::string mHash = hexToBytes(hash(message, params.hashFunc)); // Step 1 & 2

    std::string maskedDB = EM.substr(0, emLen - hLen - 1); // Step 5
    std::string H = EM.substr(emLen - hLen - 1, hLen); // Step 5

    std::string dbMask = hexToBytes(mgf1(H, emLen - hLen - 1, params.hashFunc)); // Step 7
    std::string DB;
    for (size_t i = 0; i < maskedDB.length(); ++i) {
        DB += maskedDB[i] ^ dbMask[i]; // Step 8
    }

    // Check if the leftmost (emLen - hLen - sLen - 2) octets of DB are zero
    unsigned int zeroPaddingLen = emLen - hLen - params.sLen - 2;
    for (size_t i = 0; i < zeroPaddingLen; ++i) {
        if (DB[i] != 0x00) {
            throw std::invalid_argument("Inconsistent: Leftmost octets of DB are not zero."); // Step 10
        }
    }

    // Check if the octet at position (emLen - hLen - sLen - 1) is 0x01
    if (DB[zeroPaddingLen] != 0x01) {
        throw std::invalid_argument("Inconsistent: The specified position in DB does not contain 0x01."); // Step 10
    }

    std::string salt = DB.substr(DB.length() - params.sLen, params.sLen); // Step 11
    std::string PS1(PADDING1_SIZE, 0x00);
    std::string mPrime = PS1 + mHash + salt; // Step 12
    std::string hPrime = hexToBytes(hash(mPrime, params.hashFunc)); // Step 13
    
    if (H == hPrime) return true; // Step 14

    return false;
}