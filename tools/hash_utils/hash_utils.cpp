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
            return [](const std::string& in) { return hashSHA1(SecureBytes::fromAscii(in)).toHex(); };
        case HashAlgorithm::SHA224:
            return [](const std::string& in) { return hashSHA224(SecureBytes::fromAscii(in)).toHex(); };
        case HashAlgorithm::SHA256:
            return [](const std::string& in) { return hashSHA256(SecureBytes::fromAscii(in)).toHex(); };
        case HashAlgorithm::SHA384:
            return [](const std::string& in) { return hashSHA384(SecureBytes::fromAscii(in)).toHex(); };
        case HashAlgorithm::SHA512:
            return [](const std::string& in) { return hashSHA512(SecureBytes::fromAscii(in)).toHex(); };
        default:
            throw std::invalid_argument("Unsupported hash function");
    }
}