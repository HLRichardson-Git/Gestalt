/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * hash_utils.h
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