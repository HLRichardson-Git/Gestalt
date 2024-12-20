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

/*
 * NOTICE:
 *     This is all currently not supported as there is a problem I am not sure how to fix yet which
 *     is that GMP strips the leading zeros of the encoded message of PKCS#1v1.5.
 */

std::string getAlgorithmIdentifier(const HashAlgorithm& hashAlg);

std::string encodeForEncryptionPKCS1v15(const std::string& input);
std::string decodeForEncryptionPKCS1v15(const std::string& input);

std::string encodeForSigningPKCS1v15(const std::string& input, const HashAlgorithm& hashAlg);
bool verifyForSigningPKCS1v15(const std::string& input, const std::string& EM);