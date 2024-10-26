/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * pss.h
 *
 */

# pragma once

#include <iostream>

#include "../rsa_padding.h"

const size_t PADDING1_SIZE = 8;

class PSSParams {
public:
    RSA_ENCRYPTION_HASH_FUNCTIONS hashFunc;  // Enum for available hash functions
    RSA_ENCRYPTION_MGF_FUNCTIONS mgfFunc;  // Enum for MGF1 with specific hash functions
    size_t sLen;
    std::string salt; // Should only be set for testing purposes

    PSSParams(RSA_ENCRYPTION_HASH_FUNCTIONS hash = RSA_ENCRYPTION_HASH_FUNCTIONS::SHA256, 
               RSA_ENCRYPTION_MGF_FUNCTIONS mgf = RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, 
               size_t sLen = 0,
               const std::string& salt = "")
        : hashFunc(hash), mgfFunc(mgf), sLen(sLen), salt(salt) {}
};

std::size_t calculateEmLen(std::size_t emBits);

std::string applyPSS_Padding(const std::string& input, const PSSParams& params, unsigned int modulusSizeBytes);
std::string removePSS_Padding(const std::string& input, const PSSParams& params, unsigned int modulusSizeBytes);