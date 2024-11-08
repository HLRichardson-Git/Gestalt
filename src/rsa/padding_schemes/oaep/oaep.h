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

#include <iostream>

#include "../rsa_padding.h"

class OAEPParams {
public:
    std::string label;
    HashAlgorithm hashFunc;  // Enum for available hash functions
    RSA_MGF_FUNCTIONS mgfFunc;  // Enum for MGF1 with specific hash functions
    std::string seed; // Should only be set for testing purposes

    OAEPParams(HashAlgorithm hash = HashAlgorithm::SHA256, 
               RSA_MGF_FUNCTIONS mgf = RSA_MGF_FUNCTIONS::MGF1, 
               const std::string& label = "",
               const std::string& seed = "")
        : label(label), hashFunc(hash), mgfFunc(mgf), seed(seed) {}
};

std::string applyOAEP_Padding(const std::string& input, const OAEPParams& params, unsigned int modulusSizeBytes);
std::string removeOAEP_Padding(const std::string& input, const OAEPParams& params, unsigned int modulusSizeBytes);