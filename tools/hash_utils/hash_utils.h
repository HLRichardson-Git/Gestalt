/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * hash_utils.h
 *
 * This file provides utility functions to easily select and apply various cryptographic
 * hash algorithms (SHA1, SHA224, SHA256, SHA384, SHA512) based on user input.
 * 
 * The `hash` function returns a callable function object that can be used to hash 
 * strings with the selected hash algorithm. It supports multiple hash algorithms 
 * through the `HashAlgorithm` enum and internally uses pre-defined hash functions.
 * 
 */

# pragma once

#include <iostream>
#include <string>
#include <functional>

enum class HashAlgorithm : unsigned int{
    None = 0,
    SHA1 = 20, // 20-Bytes
    SHA224 = 28, // 28-Bytes
    SHA256 = 32, // 32-Bytes
    SHA384 = 48, // 48-Bytes
    SHA512 = 64 // 64-Bytes
};

std::function<std::string(const std::string&)> hash(HashAlgorithm hashAlg);