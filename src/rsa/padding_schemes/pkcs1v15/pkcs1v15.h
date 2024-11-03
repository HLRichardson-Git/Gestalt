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
 * - Signing: The input message is hashed, and the resulting hash is 
 *   formatted with a specific DER-encoded structure for signing.
 * - Verification: The signature is decrypted to retrieve the encoded message 
 *   and compared against a newly computed encoded message from the original 
 *   input using the extracted hash algorithm.
 * - Encryption: The plaintext message is padded with a fixed structure, 
 *   ensuring it fits within the RSA modulus.
 * 
 * The functions provided allow for configurable hash algorithms during the 
 * signing process and ensure compliance with the PKCS#1 v1.5 specifications.
 */

std::string encodeForEncryptionPKCS1v15(const std::string& input);
std::string decodeForEncryptionPKCS1v15(const std::string& input);

std::string encodeForSigningPKCS1v15(const std::string& input, const RSA_HASH_FUNCTIONS& hashAlgoritm);
bool verifyForSigningPKCS1v15(const std::string& input, const std::string& EM);