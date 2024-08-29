/*
 * Copyright 2023-2024 The Gestalt Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT License. See the file LICENSE for the full text.
 */

/*
 * rsa_padding.cpp
 *
 */

#include <iostream> // for debugging
#include <string>

#include "rsa_padding.h"
#include <gestalt/sha1.h>
#include <gestalt/sha2.h>

std::string hash(const std::string& input, RSA_ENCRYPTION_HASH_FUNCTIONS hashFunc) {
    switch (hashFunc) {
        case RSA_ENCRYPTION_HASH_FUNCTIONS::SHA1:
            return hashSHA1(input);
            break;
        case RSA_ENCRYPTION_HASH_FUNCTIONS::SHA256:
            return hashSHA256(input);
            break;
        /*case HashFunction::SHA512:
            return hashSHA512(input);
        case HashFunction::SHAKE128:
            return shake128(input);
        case HashFunction::SHAKE256:
            return shake256(input);*/
        default:
            throw std::invalid_argument("Unsupported hash function");
    }
}


std::string mgf1(const std::string& seed, unsigned int maskLen, RSA_ENCRYPTION_HASH_FUNCTIONS hashFunc) {
    unsigned int hashLength = static_cast<unsigned int>(hashFunc);
    std::string mask = "";
    unsigned char C[4];
    int iterations = (maskLen + hashLength - 1) / hashLength; // This is the same as ceil(maskLen/ SHA256_LENGTH)

    for (int i = 0; i < iterations; i++) {
        // Construct the counter C
        C[0] = (i >> 24) & 0xFF;
        C[1] = (i >> 16) & 0xFF;
        C[2] = (i >> 8) & 0xFF;
        C[3] = i & 0xFF;

        std::string computedHash = hash(seed + std::string(reinterpret_cast<char*>(C), 4), hashFunc);
        mask += computedHash;
    }

    return mask.substr(0, maskLen * 2); // mask is in hex, but we need bytes so we double the maskLen
}