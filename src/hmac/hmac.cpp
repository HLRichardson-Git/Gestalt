/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * hmac.cpp
 *
 * This file contains the implementation of Gestalts HMAC security functions.
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include "hmac.h"
#include "utils.h"

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

void HMAC::processKey(const std::string& key, hash_f hash) {
    size_t keySize = key.length();

    if (keySize > B) {
        std::string hashedKey = hexToBytes(hash(key));
        std::copy(hashedKey.begin(), hashedKey.end(), K.begin());
    } 
    // No need to append zeros manually because K is already initialized with zeros
    else {
        std::copy(key.begin(), key.end(), K.begin());
    }
}

std::string HMAC::xorVectors(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
    if (a.size() != b.size()) throw std::invalid_argument("Vectors must be of the same length");

    std::string result;
    result.reserve(a.size());

    for (size_t i = 0; i < a.size(); ++i) {
        result.push_back(a[i] ^ b[i]);
    }
    return result;
}

std::string HMAC::keyedHash(const std::string& key, const std::string& input, hash_f hash) {
    processKey(key, hash);
    return hash(xorVectors(K, opad) + hexToBytes(hash(xorVectors(K, ipad) + input)));
}