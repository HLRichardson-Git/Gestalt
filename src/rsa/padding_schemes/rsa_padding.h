/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa_padding.h
 *
 */

# pragma once

const unsigned int SHA256_LENGTH = 32; // Hard coded hash len for sha2-256 for now

enum RSA_ENCRYPTION_MGF_FUNCTIONS {
    MGF1
    //SHAKE128,
    //SHAKE256
};

enum class RSA_ENCRYPTION_HASH_FUNCTIONS : unsigned int{
   SHA1 = 20, // 20-Bytes
   //SHA224 = 28, // 28-Bytes
   SHA256 = 32, // 32-Bytes
   //SHA384 = 48, // 48-Bytes
   //SHA512 = 64 // 64-Bytes
};

std::string hash(const std::string& input, RSA_ENCRYPTION_HASH_FUNCTIONS hashFunc);

std::string mgf1(const std::string& seed, unsigned int maskLen, RSA_ENCRYPTION_HASH_FUNCTIONS hashFunc);