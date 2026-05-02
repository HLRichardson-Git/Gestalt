/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
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
    SecureBytes label;
    HashAlgorithm hashFunc;     // Hash used for label hashing
    RSA_MGFFunctions mgfFunc;   // Mask generation function
    HashAlgorithm mgfHashFunc;  // Hash used inside MGF1 (None = use hashFunc)
    SecureBytes seed;           // Should only be set for testing purposes

    OAEPParams(HashAlgorithm hash = HashAlgorithm::SHA256,
               RSA_MGFFunctions mgf = RSA_MGFFunctions::MGF1,
               const SecureBytes& label = SecureBytes{},
               const SecureBytes& seed = SecureBytes{})
        : label(label), hashFunc(hash), mgfFunc(mgf),
          mgfHashFunc(HashAlgorithm::None), seed(seed) {}

    OAEPParams(HashAlgorithm hash,
               RSA_MGFFunctions mgf,
               HashAlgorithm mgfHash,
               const SecureBytes& label = SecureBytes{},
               const SecureBytes& seed = SecureBytes{})
        : label(label), hashFunc(hash), mgfFunc(mgf),
          mgfHashFunc(mgfHash), seed(seed) {}
};

SecureBytes applyOAEP_Padding(const SecureBytes& input, const OAEPParams& params, unsigned int modulusSizeBytes);
SecureBytes removeOAEP_Padding(const SecureBytes& input, const OAEPParams& params, unsigned int modulusSizeBytes);