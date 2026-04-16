/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * pkcs1v15.h
 *
 * Implements PKCS #1 v1.5 padding for RSA digital signatures and encryption. 
 * This padding scheme is straightforward and deterministic, ensuring that the 
 * signed message can be verified without the use of randomness. However, 
 * it is less secure against certain attacks compared to more modern schemes.
 *
 * This file provides functions for encoding messages for signing and verifying 
 * signatures using the PKCS #1 v1.5 padding scheme, as specified in RFC 3447 
 * (https://tools.ietf.org/html/rfc3447). The implementation handles:
 * 
 */

#pragma once

#include <iostream>

#include "../rsa_padding.h"

class PKCS1v15Params {
public:
    HashAlgorithm hashAlg;
    PKCS1v15Params(HashAlgorithm hash = HashAlgorithm::SHA256) : hashAlg(hash) {}
};

std::string getAlgorithmIdentifier(const HashAlgorithm& hashAlg);

std::string encodeForEncryptionPKCS1v15(const std::string& input, size_t modulusSizeBytes);
std::string decodeForEncryptionPKCS1v15(const std::string& em, size_t modulusSizeBytes);

std::string encodeForSigningPKCS1v15(const std::string& input, const HashAlgorithm& hashAlg, size_t modulusSizeBytes);
bool verifyForSigningPKCS1v15(const std::string& input, const std::string& em, const HashAlgorithm& hashAlg);