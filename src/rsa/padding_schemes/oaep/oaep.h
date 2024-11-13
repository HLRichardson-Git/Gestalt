/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * oaep.h
 *
 * This file provides the implementation for the Optimal Asymmetric Encryption Padding (OAEP) scheme used in RSA 
 * encryption. It includes functions for applying and removing OAEP padding with configurable hash functions and mask 
 * generation functions (MGF1).
 * 
 * This file provides functions for applying and removing OAEP padding, based on PKCS #1 v2.2 
 * (see https://tools.ietf.org/html/rfc8017). The implementation includes hash-based mask generation using MGF1, 
 * supporting configurable hash functions and label handling.
 * 
 */

# pragma once

#include <iostream>

#include "../rsa_padding.h"

class OAEPParams {
public:
    std::string label;
    HashAlgorithm hashFunc;  // Enum for available hash functions
    RSA_MGFFunctions mgfFunc;  // Enum for MGF1 with specific hash functions
    std::string seed; // Should only be set for testing purposes

    OAEPParams(HashAlgorithm hash = HashAlgorithm::SHA256, 
               RSA_MGFFunctions mgf = RSA_MGFFunctions::MGF1, 
               const std::string& label = "",
               const std::string& seed = "")
        : label(label), hashFunc(hash), mgfFunc(mgf), seed(seed) {}
};

std::string applyOAEP_Padding(const std::string& input, const OAEPParams& params, unsigned int modulusSizeBytes);
std::string removeOAEP_Padding(const std::string& input, const OAEPParams& params, unsigned int modulusSizeBytes);