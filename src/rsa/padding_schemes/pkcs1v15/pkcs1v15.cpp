/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * pkcs1v15.cpp
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

#include "pkcs1v15.h"
#include "utils.h"

/*
 * NOTICE:
 *     This is all currently not supported as there is a problem I am not sure how to fix yet which
 *     is that GMP strips the leading zeros of the encoded message of PKCS#1v1.5.
 */

std::string getAlgorithmIdentifier(const HashAlgorithm& hashAlg) {
    switch (hashAlg) {
        case HashAlgorithm::SHA1:
            return "3021300906052b0e03021a05000414";
            break;
        case HashAlgorithm::SHA256:
            return "3031300d060960864801650304020105000420";
            break;
        case HashAlgorithm::SHA384:
            return "3041300d060960864801650304020205000430";
            break;
        case HashAlgorithm::SHA512:
            return "3051300d060960864801650304020305000440";
        default:
            throw std::invalid_argument("Unsupported hash function");
    }
}

std::string encodeForEncryptionPKCS1v15(const std::string& input) {
    // Generate PS based on input length, return the EM
    return "";
}

std::string decodeForEncryptionPKCS1v15(const std::string& input) {
    // Do checks of encoded pkcs1v1.5 message, and seperate into sections, returning M
    return "";
}

std::string encodeForSigningPKCS1v15(const std::string& input, const HashAlgorithm& hashAlg) {
    // 1. Hash the input message
    std::string H = hexToBytes(hash(hashAlg)(input));

    // 2. Get DER-encoded AlgorithmIdentifier || Hash (H)
    std::string T = hexToBytes(getAlgorithmIdentifier(hashAlg)) + H;

    // 3
    size_t tLen = T.length();
    size_t emLen = tLen + 11;
    if (emLen < tLen + 11) throw std::invalid_argument("Error PKCS#1v1.5: intended encoded message length to short.");

    // 4. Create padding string (PS) filled with 0xFF bytes
    std::string PS(emLen - tLen - 3, 0xFF);

    // 5. Construct EM = 0x00 || 0x01 || PS || 0x00 || T
    std::string EM = std::string(1, 0x00) + std::string(1, 0x01) + PS + std::string(1, 0x00) + T;

    return EM;
}

bool verifyForSigningPKCS1v15(const std::string& input, const std::string& EM) {
    /*
     * Take EM, and do the verifications to make sure it is a valid PKCS1v1.5 encoded signature
     * Then look in the 'T' which has the hash identifier of the signature (hard coded known value) and the hash
     * Next we can call `encodeForSigningPKCS1v15` with the input and the decoded hash identifier
     * return status if outut of `encodeForSigningPKCS1v15` is the same as given EM
     */
    return true;
}