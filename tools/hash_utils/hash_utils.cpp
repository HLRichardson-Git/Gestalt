/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * hash_utils.cpp
 *
 * This file provides utility functions to easily select and apply various cryptographic
 * hash algorithms (SHA1, SHA224, SHA256, SHA384, SHA512) based on user input.
 * 
 * The `hash` function returns a callable function object that can be used to hash 
 * strings with the selected hash algorithm. It supports multiple hash algorithms 
 * through the `HashAlgorithm` enum and internally uses pre-defined hash functions.
 * 
 */

#include "hash_utils.h"
#include <gestalt/sha1.h>
#include <gestalt/sha2.h>

std::function<std::string(const std::string&)> hash(HashAlgorithm hashAlg) {
    switch (hashAlg) {
        case HashAlgorithm::None:
            return [](const std::string& in) { return in; };
        case HashAlgorithm::SHA1:
            return hashSHA1;
        case HashAlgorithm::SHA224:
            return hashSHA224;
        case HashAlgorithm::SHA256:
            return hashSHA256;
        case HashAlgorithm::SHA384:
            return hashSHA384;
        case HashAlgorithm::SHA512:
            return hashSHA512;
        default:
            throw std::invalid_argument("Unsupported hash function");
    }
}