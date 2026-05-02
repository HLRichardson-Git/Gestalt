/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * oaep.cpp
 *
 * This file provides the implementation for the Optimal Asymmetric Encryption Padding (OAEP) scheme used in RSA
 * encryption. It includes functions for applying and removing OAEP padding with configurable hash functions and mask
 * generation functions (MGF1).
 *
 * This file provides functions for applying and removing OAEP padding, based on PKCS #1 v2.2
 * (see https://tools.ietf.org/html/rfc8017). The implementation includes hash-based mask generation using MGF1,
 * supporting configurable hash functions and label handling.
 *
 */

#include <algorithm>
#include <vector>

#include "oaep.h"

SecureBytes applyOAEP_Padding(const SecureBytes& input, const OAEPParams& params, unsigned int modulusSizeBytes) {
    HashAlgorithm mgfHash = (params.mgfHashFunc == HashAlgorithm::None) ? params.hashFunc : params.mgfHashFunc;
    unsigned int hashLength = static_cast<unsigned int>(params.hashFunc);
    unsigned int inputLength = static_cast<unsigned int>(input.size());
    int psLen = modulusSizeBytes - inputLength - (2 * hashLength) - 2;

    if (psLen < 0) {
        throw std::invalid_argument("Message too long for RSA modulus");
    }

    SecureBytes lhash = hash(params.hashFunc)(params.label);
    SecureBytes PS(psLen, 0x00);

    // DB = lhash || PS || 0x01 || input
    SecureBytes DB = lhash;
    DB.append(PS);
    DB.append(SecureBytes(1, 0x01));
    DB.append(input);

    SecureBytes seed = params.seed;
    if (seed.empty()) {
        seed = SecureBytes::random(hashLength);
    }

    SecureBytes dbMask = mgf1(seed, modulusSizeBytes - hashLength - 1, mgfHash);
    SecureBytes maskedDB(DB.size());
    for (size_t i = 0; i < DB.size(); ++i) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    SecureBytes seedMask = mgf1(maskedDB, hashLength, mgfHash);
    SecureBytes maskedSeed(seed.size());
    for (size_t i = 0; i < seed.size(); ++i) {
        maskedSeed[i] = seed[i] ^ seedMask[i];
    }

    // EM = 0x00 || maskedSeed || maskedDB
    SecureBytes result(1, 0x00);
    result.append(maskedSeed);
    result.append(maskedDB);
    return result;
}

SecureBytes removeOAEP_Padding(const SecureBytes& input, const OAEPParams& params, unsigned int modulusSizeBytes) {
    if (input[0] != 0x00) {
        throw std::invalid_argument("Given OAEP message does not begin with 0x00");
    }

    HashAlgorithm mgfHash = (params.mgfHashFunc == HashAlgorithm::None) ? params.hashFunc : params.mgfHashFunc;
    unsigned int hashLength = static_cast<unsigned int>(params.hashFunc);

    SecureBytes maskedSeed = SecureBytes::fromVector(std::vector<uint8_t>(input.begin() + 1, input.begin() + 1 + hashLength));
    SecureBytes maskedDB   = SecureBytes::fromVector(std::vector<uint8_t>(input.begin() + 1 + hashLength, input.end()));

    SecureBytes seedMask = mgf1(maskedDB, hashLength, mgfHash);
    SecureBytes seed(maskedSeed.size());
    for (size_t i = 0; i < maskedSeed.size(); ++i) {
        seed[i] = maskedSeed[i] ^ seedMask[i];
    }

    SecureBytes dbMask = mgf1(seed, modulusSizeBytes - hashLength - 1, mgfHash);
    SecureBytes DB(maskedDB.size());
    for (size_t i = 0; i < maskedDB.size(); ++i) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }

    SecureBytes lhash = hash(params.hashFunc)(params.label);
    SecureBytes dbLhash = SecureBytes::fromVector(std::vector<uint8_t>(DB.begin(), DB.begin() + hashLength));
    if (dbLhash != lhash) {
        throw std::invalid_argument("OAEP Decode Error: The encoded lhash and computed lhash are not the same.");
    }

    int psStartPos = hashLength;
    auto it = std::find(DB.begin() + psStartPos, DB.end(), uint8_t(0x01));
    if (it == DB.end()) {
        throw std::invalid_argument("OAEP Decode Error: Padding 0x01 byte not found.");
    }
    int psEndPos = static_cast<int>(it - DB.begin());
    if (psEndPos <= psStartPos) {
        throw std::invalid_argument("OAEP Decode Error: Padding 0x01 byte not found.");
    }

    // Ensure all bytes from psStartPos to psEndPos-1 are zero (the PS)
    for (int i = psStartPos; i < psEndPos; i++) {
        if (DB[i] != 0x00) {
            throw std::invalid_argument("OAEP Decode Error: Non-zero byte found in padding (PS).");
        }
    }

    return SecureBytes::fromVector(std::vector<uint8_t>(DB.begin() + psEndPos + 1, DB.end()));
}
