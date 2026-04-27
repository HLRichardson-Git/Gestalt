/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * hmac.cpp
 *
 * This file contains the implementation of Gestalts HMAC security functions.
 */

#include <algorithm>

#include "hmac.h"

std::pair<unsigned int, unsigned int> HMAC::getHashParameters(const HASH_ALGORITHM HASH) {
    switch (HASH) {
        case SHA1: return {64, 20};
        case SHA224: return {64, 28};
        case SHA256: return {64, 32};
        case SHA384: return {128, 48};
        case SHA512: return {128, 64};
        case SHA512_224: return {128, 28};
        case SHA512_256: return {128, 32};
        default: throw std::invalid_argument("Error: Invalid hash algorithm given for HMAC");
    }
}

void HMAC::hmacManager(const HASH_ALGORITHM HASH) {
    std::pair<unsigned int, unsigned int> params = getHashParameters(HASH);
    B = params.first;
    L = params.second;
}

void HMAC::processKey(const SecureBytes& key, hash_f hash) {
    if (key.size() > B) {
        SecureBytes hashedKey = hash(key);
        std::copy(hashedKey.begin(), hashedKey.end(), K.begin());
    }
    // No need to append zeros manually because K is already initialized with zeros
    else {
        std::copy(key.begin(), key.end(), K.begin());
    }
}

SecureBytes HMAC::xorVectors(const SecureBytes& a, const SecureBytes& b) {
    if (a.size() != b.size()) throw std::invalid_argument("Vectors must be of the same length");

    SecureBytes result(a.size());
    for (size_t i = 0; i < a.size(); ++i)
        result[i] = a[i] ^ b[i];
    return result;
}

SecureBytes HMAC::keyedHash(const SecureBytes& key, const SecureBytes& input, hash_f hash) {
    processKey(key, hash);
    return hash(xorVectors(K, opad) + hash(xorVectors(K, ipad) + input));
}