/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * pss.h
 *
 * Implements Probabilistic Signature Scheme (PSS) padding for RSA digital signatures. PSS ensures 
 * signature security by adding randomness (salt) to the padding, making signatures unique even 
 * for identical messages and resilient to chosen-message attacks.
 *
 * This file provides functions for encoding and verifying PSS padding, based on PKCS #1 v2.1 
 * (see https://tools.ietf.org/html/rfc8017). The implementation includes hashing and mask 
 * generation using MGF1, supporting configurable hash functions and salt lengths.
 */

# pragma once

#include <iostream>

#include "../rsa_padding.h"

const size_t PADDING1_SIZE = 8;

class PSSParams {
public:
    HashAlgorithm hashFunc;  // Enum for available hash functions
    RSA_MGF_FUNCTIONS mgfFunc;  // Enum for MGF1 with specific hash functions
    size_t sLen;
    std::string salt; // Should only be set for testing purposes

    PSSParams(HashAlgorithm hash = HashAlgorithm::SHA256, 
              RSA_MGF_FUNCTIONS mgf = RSA_MGF_FUNCTIONS::MGF1, 
              size_t sLen = 0,
              const std::string& salt = "")
        : hashFunc(hash), mgfFunc(mgf), sLen(sLen), salt(salt) {}
};

std::string encodePSS_Padding(const std::string& input, const PSSParams& params, unsigned int modulusSizeBytes);
bool verifyPSS_Padding(const std::string& EM, const std::string& message, const PSSParams& params, unsigned int modulusSizeBytes);