/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * oaep.h
 *
 */

# pragma once

#include "../rsa_padding.h"

class OAEPParams {
public:
    std::string label;
    RSA_ENCRYPTION_HASH_FUNCTIONS hashFunc;  // Enum for available hash functions
    RSA_ENCRYPTION_MGF_FUNCTIONS mgfFunc;  // Enum for MGF1 with specific hash functions
    std::string seed; // Should only be set for testing purposes

    OAEPParams(RSA_ENCRYPTION_HASH_FUNCTIONS hash = RSA_ENCRYPTION_HASH_FUNCTIONS::SHA256, 
               RSA_ENCRYPTION_MGF_FUNCTIONS mgf = RSA_ENCRYPTION_MGF_FUNCTIONS::MGF1, 
               const std::string& label = "",
               const std::string& seed = "")
        : label(label), hashFunc(hash), mgfFunc(mgf), seed(seed) {}
};

std::string applyOAEP_Padding(const std::string& input, const OAEPParams& params, unsigned int modulusSizeBytes);