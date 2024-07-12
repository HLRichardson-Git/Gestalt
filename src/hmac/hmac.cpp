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

void HMAC::hmacManager(const HASH_ALGORITHM HASH) {
    switch (HASH) {
        case SHA1:
            B = 64;
            L = 20;
            break;
        case SHA224:
            B = 64;
            L = 28;
            break;
        case SHA256:
            B = 64;
            L = 32;
            break;
        case SHA384:
            B = 128;
            L = 48;
            break;
        case SHA512:
            B = 128;
            L = 64;
            break;
        case SHA512_224:
            B = 128;
            L = 28;
            break;
        case SHA512_256:
            B = 128;
            L = 32;
            break;
        default:
            B = 0;
            L = 0;
            throw std::invalid_argument("Error: Invalid hash algorithm given for HMAC");
            break;
    }
}

void HMAC::processKey(const std::string& key, hash_f hash) {
    size_t keySize = key.length();

    if (keySize > B) {
        std::string hashedKey = hash(key);
        std::copy(hashedKey.begin(), hashedKey.end(), K.begin());
    } else {
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
    return hash(xorVectors(K, opad) + hexToASCII_Bytes(hash(xorVectors(K, ipad) + input)));
}