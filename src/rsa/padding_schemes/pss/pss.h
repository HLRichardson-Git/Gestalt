/*
 * Copyright 2023-2026 The Gestalt Project Authors. All Rights Reserved.
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

class PSSParams {
public:
    HashAlgorithm hashFunc;     // Hash used for message hashing
    RSA_MGFFunctions mgfFunc;   // Mask generation function
    HashAlgorithm mgfHashFunc;  // Hash used inside MGF1 (None = use hashFunc)
    size_t sLen;
    SecureBytes salt;           // Should only be set for testing purposes

    PSSParams(HashAlgorithm hash = HashAlgorithm::SHA256,
              RSA_MGFFunctions mgf = RSA_MGFFunctions::MGF1,
              size_t sLen = 0,
              const SecureBytes& salt = SecureBytes{})
        : hashFunc(hash), mgfFunc(mgf), mgfHashFunc(HashAlgorithm::None),
          sLen(sLen), salt(salt) {}

    PSSParams(HashAlgorithm hash,
              RSA_MGFFunctions mgf,
              HashAlgorithm mgfHash,
              size_t sLen = 0,
              const SecureBytes& salt = SecureBytes{})
        : hashFunc(hash), mgfFunc(mgf), mgfHashFunc(mgfHash),
          sLen(sLen), salt(salt) {}
};

SecureBytes encodePSS_Padding(const SecureBytes& message, const PSSParams& params, unsigned int modulusSizeBytes);
bool verifyPSS_Padding(const SecureBytes& EM, const SecureBytes& message, const PSSParams& params, unsigned int modulusSizeBytes);